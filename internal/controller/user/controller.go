/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package user

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	UserFinalizer              = "pocketid.internal/user-finalizer"
	UserGroupUserFinalizer     = "pocketid.internal/user-group-finalizer"
	defaultAPIKeyName          = "pocket-id-operator"
	DefaultLoginTokenExpiryMin = 15
)

// Reconciler reconciles a PocketIDUser object
type Reconciler struct {
	client.Client
	common.BaseReconciler
	// APIReader provides direct API reads for externally-managed secrets.
	// Used only when reading user-provided secrets (userInfoSecretRef, secretRef for API keys)
	// to avoid cache delays when secrets are created externally.
	APIReader client.Reader
	Scheme    *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	r.EnsureClient(r.Client)

	// Fetch the User CR
	user := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := r.Get(ctx, req.NamespacedName, user); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDUser", "name", user.Name)

	if !user.DeletionTimestamp.IsZero() {
		return r.ReconcileDelete(ctx, user)
	}

	// Get the PocketIDInstance to know where to connect
	instance, err := common.SelectInstance(ctx, r.Client, user.Spec.InstanceSelector)
	if err != nil {
		log.Error(err, "Failed to select PocketIDInstance")
		_ = r.SetReadyCondition(ctx, user, metav1.ConditionFalse, "InstanceSelectionError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	updatedFinalizers, err := r.ReconcileUserFinalizers(ctx, user)
	if err != nil {
		log.Error(err, "Failed to reconcile user finalizers")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if updatedFinalizers {
		return ctrl.Result{Requeue: true}, nil
	}

	// Validate instance is ready using base reconciler
	if validationResult := r.ValidateInstanceReady(ctx, user, instance); validationResult.ShouldRequeue {
		return ctrl.Result{RequeueAfter: validationResult.RequeueAfter}, validationResult.Error
	}

	// Get API client from pool
	apiClient, result, err := r.GetAPIClientOrWait(ctx, user, instance)
	if result != nil {
		return *result, err
	}

	// Reconcile the user in Pocket-ID
	if err := r.reconcileUser(ctx, user, apiClient, instance); err != nil {
		log.Error(err, "Failed to reconcile user")
		_ = r.SetReadyCondition(ctx, user, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Reconcile API keys
	if err := r.reconcileAPIKeys(ctx, user, apiClient); err != nil {
		log.Error(err, "Failed to reconcile API keys")
		_ = r.SetReadyCondition(ctx, user, metav1.ConditionFalse, "APIKeyError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.ensureOneTimeLoginStatus(ctx, user, apiClient, instance); err != nil {
		log.Error(err, "Failed to ensure one-time login status")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	_ = r.SetReadyCondition(ctx, user, metav1.ConditionTrue, "Reconciled", "User and API keys are in sync")

	cleanupResult, err := r.ReconcileOneTimeLoginStatus(ctx, user)
	if err != nil {
		log.Error(err, "Failed to reconcile one-time login status")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if cleanupResult.RequeueAfter > 0 {
		return common.ApplyResync(cleanupResult), nil
	}

	return common.ApplyResync(ctrl.Result{}), nil
}

func (r *Reconciler) ReconcileUserFinalizers(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser) (bool, error) {
	referencedByUserGroup, err := r.isUserReferencedByUserGroup(ctx, user.Name, user.Namespace)
	if err != nil {
		return false, err
	}

	updates := []helpers.FinalizerUpdate{
		{Name: UserFinalizer, ShouldAdd: true},
		{Name: UserGroupUserFinalizer, ShouldAdd: referencedByUserGroup},
	}

	return helpers.ReconcileFinalizers(ctx, r.Client, user, updates)
}

func (r *Reconciler) isUserReferencedByUserGroup(ctx context.Context, userName, userNamespace string) (bool, error) {
	userKey := fmt.Sprintf("%s/%s", userNamespace, userName)
	userGroups := &pocketidinternalv1alpha1.PocketIDUserGroupList{}
	if err := r.List(ctx, userGroups, client.MatchingFields{UserGroupUserRefIndexKey: userKey}); err == nil {
		return len(userGroups.Items) > 0, nil
	}

	if err := r.List(ctx, userGroups); err != nil {
		return false, err
	}

	for i := range userGroups.Items {
		if userGroupHasUserRef(&userGroups.Items[i], userName, userNamespace) {
			return true, nil
		}
	}

	return false, nil
}

func userGroupHasUserRef(group *pocketidinternalv1alpha1.PocketIDUserGroup, userName, userNamespace string) bool {
	for _, ref := range group.Spec.UserRefs {
		if ref.Name == "" {
			continue
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = group.Namespace
		}
		if ref.Name == userName && namespace == userNamespace {
			return true
		}
	}
	return false
}

// ReconcileDelete handles user deletion
func (r *Reconciler) ReconcileDelete(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Check if user is referenced by user groups
	referenced, err := r.isUserReferencedByUserGroup(ctx, user.Name, user.Namespace)
	if err != nil {
		log.Error(err, "Failed to check PocketIDUserGroup references")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if referenced {
		log.Info("User is referenced by PocketIDInstance, blocking deletion", "user", user.Name)
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	referencedByUserGroup, err := r.isUserReferencedByUserGroup(ctx, user.Name, user.Namespace)
	if err != nil {
		log.Error(err, "Failed to check PocketIDUserGroup references")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if referencedByUserGroup {
		log.Info("User is referenced by PocketIDUserGroup, blocking deletion", "user", user.Name)
		if _, err := helpers.EnsureFinalizer(ctx, r.Client, user, UserGroupUserFinalizer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Remove UserGroupUserFinalizer if not referenced by any user group
	if controllerutil.ContainsFinalizer(user, UserGroupUserFinalizer) {
		if err := helpers.RemoveFinalizers(ctx, r.Client, user, UserGroupUserFinalizer); err != nil {
			if errors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if user.Status.UserID != "" {
		instance, err := common.SelectInstance(ctx, r.Client, user.Spec.InstanceSelector)
		if err != nil {
			if stderrors.Is(err, common.ErrNoInstance) {
				log.Info("No PocketIDInstance found; skipping Pocket-ID deletion", "userID", user.Status.UserID)
			} else {
				log.Error(err, "Failed to select PocketIDInstance for delete")
				return ctrl.Result{}, err
			}
		} else {
			apiClient, err := common.GetAPIClient(ctx, r.Client, r.APIReader, instance)
			if err != nil {
				if stderrors.Is(err, common.ErrAPIClientNotReady) {
					log.Info("API client not ready for delete, requeuing", "userID", user.Status.UserID)
					return ctrl.Result{RequeueAfter: common.Requeue}, nil
				}
				log.Error(err, "Failed to get API client for delete")
				return ctrl.Result{}, err
			}
			log.Info("Deleting user from Pocket-ID", "userID", user.Status.UserID)
			if err := apiClient.DeleteUser(ctx, user.Status.UserID); err != nil {
				log.Error(err, "Failed to delete user from Pocket-ID")
				return ctrl.Result{}, err
			}
		}
	}

	// Delete associated secrets
	secretNames := make([]string, 0, len(user.Status.APIKeys))
	for _, keyStatus := range user.Status.APIKeys {
		if keyStatus.SecretName != "" {
			secretNames = append(secretNames, keyStatus.SecretName)
		}
	}
	if err := helpers.DeleteSecretsIfExist(ctx, r.Client, user.Namespace, secretNames); err != nil {
		log.Error(err, "Failed to delete secrets")
	}

	// Remove finalizers
	if err := helpers.RemoveFinalizers(ctx, r.Client, user, UserFinalizer, UserGroupUserFinalizer); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// resolveStringValue is a convenience wrapper around the shared helper
func (r *Reconciler) resolveStringValue(ctx context.Context, namespace string, sv pocketidinternalv1alpha1.StringValue, fallbackSecretName, fallbackKey string) (string, error) {
	return helpers.ResolveStringValue(ctx, r.Client, r.APIReader, namespace, sv, fallbackSecretName, fallbackKey)
}

// PocketIDUserAPI defines the minimal interface needed for user operations
type PocketIDUserAPI interface {
	ListUsers(ctx context.Context, search string) ([]*pocketid.User, error)
	CreateUser(ctx context.Context, input pocketid.UserInput) (*pocketid.User, error)
	GetUser(ctx context.Context, id string) (*pocketid.User, error)
	UpdateUser(ctx context.Context, id string, input pocketid.UserInput) (*pocketid.User, error)
}

// FindExistingUser checks if a user with the given username or email already exists in Pocket-ID.
// Returns the existing user if found, or nil if no matching user exists.
func (r *Reconciler) FindExistingUser(ctx context.Context, apiClient PocketIDUserAPI, username, email string) (*pocketid.User, error) {
	log := logf.FromContext(ctx)

	// Check if user with username already exists
	log.Info("Checking if user exists in Pocket-ID", "username", username)
	existingUsers, err := apiClient.ListUsers(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	// Check if username already exists
	for _, existingUser := range existingUsers {
		if existingUser.Username == username {
			log.Info("Found existing user with matching username", "username", username, "userID", existingUser.ID)
			return existingUser, nil
		}
	}

	// Check if email already exists
	if email != "" && email != fmt.Sprintf("%s@placeholder.local", username) {
		emailUsers, err := apiClient.ListUsers(ctx, email)
		if err != nil {
			return nil, fmt.Errorf("list users by email: %w", err)
		}
		for _, existingUser := range emailUsers {
			if existingUser.Email == email {
				log.Info("Found existing user with matching email", "email", email, "userID", existingUser.ID)
				return existingUser, nil
			}
		}
	}

	return nil, nil
}

// reconcileUser ensures the user exists in Pocket-ID with correct settings
func (r *Reconciler) reconcileUser(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	log := logf.FromContext(ctx)

	// Resolve all StringValue fields
	userInfoInputSecret := userInfoInputSecretName(user)
	username, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.Username, userInfoInputSecret, UserInfoSecretKeyUsername)
	if err != nil {
		return fmt.Errorf("resolve username: %w", err)
	}
	if username == "" {
		username = user.Name
	}

	firstName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.FirstName, userInfoInputSecret, UserInfoSecretKeyFirstName)
	if err != nil {
		return fmt.Errorf("resolve firstName: %w", err)
	}
	// FirstName is required by Pocket-ID, default to username if not set
	if firstName == "" {
		firstName = username
	}

	lastName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.LastName, userInfoInputSecret, UserInfoSecretKeyLastName)
	if err != nil {
		return fmt.Errorf("resolve lastName: %w", err)
	}

	email, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.Email, userInfoInputSecret, UserInfoSecretKeyEmail)
	if err != nil {
		return fmt.Errorf("resolve email: %w", err)
	}
	// Email is required by Pocket-ID, generate a placeholder if not set
	if email == "" {
		email = fmt.Sprintf("%s@placeholder.local", username)
	}

	displayName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.DisplayName, userInfoInputSecret, UserInfoSecretKeyDisplayName)
	if err != nil {
		return fmt.Errorf("resolve displayName: %w", err)
	}
	// Default displayName to "FirstName LastName" if not set
	if displayName == "" {
		displayName = firstName
		if lastName != "" {
			if displayName != "" {
				displayName += " "
			}
			displayName += lastName
		}
		// Fallback to username if still empty
		if displayName == "" {
			displayName = username
		}
	}

	input := pocketid.UserInput{
		Username:    username,
		FirstName:   firstName,
		LastName:    lastName,
		Email:       email,
		DisplayName: displayName,
		IsAdmin:     user.Spec.Admin,
		Disabled:    user.Spec.Disabled,
		Locale:      user.Spec.Locale,
	}

	// If we don't have a user ID, we need to check if user exists and create if not
	if user.Status.UserID == "" {
		// Check if user already exists
		existingUser, err := r.FindExistingUser(ctx, apiClient, username, email)
		if err != nil {
			return fmt.Errorf("find existing user: %w", err)
		}

		var pUser *pocketid.User
		if existingUser != nil {
			// User exists, adopt it and update status
			log.Info("Adopting existing user from Pocket-ID", "username", username, "userID", existingUser.ID)
			pUser = existingUser
		} else {
			// User does not exist, create it
			log.Info("Creating user in Pocket-ID", "username", username)
			pUser, err = apiClient.CreateUser(ctx, input)
			if err != nil {
				return fmt.Errorf("create user: %w", err)
			}

			// Generate one-time login token for newly created user only
			token, err := apiClient.CreateOneTimeAccessToken(ctx, pUser.ID, DefaultLoginTokenExpiryMin)
			if err != nil {
				log.Error(err, "Failed to create one-time login token - user created but token not available")
			} else {
				if err := r.SetOneTimeLoginStatus(ctx, user, instance, token.Token); err != nil {
					return fmt.Errorf("set one-time login status: %w", err)
				}
			}
		}

		// Update status with user info
		if err := r.updateUserStatus(ctx, user, pUser); err != nil {
			return err
		}

		return nil
	}

	// User exists, check if update needed
	pUser, err := apiClient.GetUser(ctx, user.Status.UserID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Check if update needed
	needsUpdate := pUser.Username != input.Username ||
		pUser.FirstName != input.FirstName ||
		pUser.LastName != input.LastName ||
		pUser.Email != input.Email ||
		pUser.DisplayName != input.DisplayName ||
		pUser.IsAdmin != input.IsAdmin ||
		pUser.Disabled != input.Disabled ||
		pUser.Locale != input.Locale

	if needsUpdate {
		log.Info("Updating user in Pocket-ID", "username", username)
		pUser, err = apiClient.UpdateUser(ctx, user.Status.UserID, input)
		if err != nil {
			return fmt.Errorf("update user: %w", err)
		}
	}

	return r.updateUserStatus(ctx, user, pUser)
}

// updateUserStatus updates the User CR status from Pocket-ID response
func (r *Reconciler) updateUserStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, pUser *pocketid.User) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &pocketidinternalv1alpha1.PocketIDUser{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(user), latest); err != nil {
			return err
		}

		oldSecretName := latest.Status.UserInfoSecretName
		secretName := userInfoOutputSecretName(latest.Name)
		if oldSecretName != "" && oldSecretName != secretName {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      oldSecretName,
					Namespace: latest.Namespace,
				},
			}
			if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("delete old user info secret %s: %w", oldSecretName, err)
			}
		}
		if err := ensureUserInfoSecret(ctx, r.Client, r.Scheme, latest, secretName, pUser); err != nil {
			return fmt.Errorf("ensure user info secret: %w", err)
		}

		latest.Status.UserID = pUser.ID
		latest.Status.UserInfoSecretName = secretName
		latest.Status.IsAdmin = pUser.IsAdmin
		latest.Status.Disabled = pUser.Disabled
		latest.Status.Locale = pUser.Locale

		return r.Status().Update(ctx, latest)
	})
}

func (r *Reconciler) SetOneTimeLoginStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, instance *pocketidinternalv1alpha1.PocketIDInstance, token string) error {
	base := user.DeepCopy()

	baseURL := instance.Spec.AppURL
	if baseURL == "" {
		baseURL = common.InternalServiceURL(instance.Name, instance.Namespace)
	}
	loginURL := fmt.Sprintf("%s/lc/%s", baseURL, token)
	expiresAt := time.Now().UTC().Add(time.Duration(DefaultLoginTokenExpiryMin) * time.Minute)

	user.Status.OneTimeLoginToken = token
	user.Status.OneTimeLoginURL = loginURL
	user.Status.OneTimeLoginExpiresAt = expiresAt.Format(time.RFC3339)

	return r.Status().Patch(ctx, user, client.MergeFrom(base))
}

func (r *Reconciler) ensureOneTimeLoginStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	if user.Status.UserID == "" {
		return nil
	}
	if user.Status.OneTimeLoginExpiresAt != "" {
		return nil
	}

	token, err := apiClient.CreateOneTimeAccessToken(ctx, user.Status.UserID, DefaultLoginTokenExpiryMin)
	if err != nil {
		return fmt.Errorf("create one-time login token: %w", err)
	}

	return r.SetOneTimeLoginStatus(ctx, user, instance, token.Token)
}

func (r *Reconciler) ReconcileOneTimeLoginStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser) (ctrl.Result, error) {
	if user.Status.OneTimeLoginExpiresAt == "" {
		return ctrl.Result{}, nil
	}

	if user.Status.OneTimeLoginToken == "" && user.Status.OneTimeLoginURL == "" {
		return ctrl.Result{}, nil
	}

	expiresAt, err := time.Parse(time.RFC3339, user.Status.OneTimeLoginExpiresAt)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Invalid one-time login expiry timestamp")
		return r.clearOneTimeLoginStatus(ctx, user)
	}

	now := time.Now().UTC()
	if !expiresAt.After(now) {
		return r.clearOneTimeLoginStatus(ctx, user)
	}

	return ctrl.Result{RequeueAfter: time.Until(expiresAt)}, nil
}

func (r *Reconciler) clearOneTimeLoginStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser) (ctrl.Result, error) {
	base := user.DeepCopy()
	user.Status.OneTimeLoginToken = ""
	user.Status.OneTimeLoginURL = ""

	if err := r.Status().Patch(ctx, user, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// reconcileAPIKeys ensures API keys exist in Pocket-ID and secrets are created
func (r *Reconciler) reconcileAPIKeys(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client) error {
	log := logf.FromContext(ctx)

	// Build map of existing keys by name
	existingKeys := make(map[string]*pocketidinternalv1alpha1.APIKeyStatus)
	for i := range user.Status.APIKeys {
		existingKeys[user.Status.APIKeys[i].Name] = &user.Status.APIKeys[i]
	}

	// Track which keys we want
	wantedKeys := make(map[string]bool)
	for _, spec := range user.Spec.APIKeys {
		wantedKeys[spec.Name] = true
	}

	// Create missing keys
	for _, spec := range user.Spec.APIKeys {
		if _, exists := existingKeys[spec.Name]; exists {
			continue
		}

		// Check if using an existing secret reference
		if spec.SecretRef != nil {
			log.Info("Using existing secret for API key", "name", spec.Name, "secret", spec.SecretRef.Name)

			// Verify the secret exists (use APIReader for fresh read of user-provided secret)
			reader := r.APIReader
			if reader == nil {
				reader = r.Client
			}
			secret := &corev1.Secret{}
			if err := reader.Get(ctx, client.ObjectKey{Namespace: user.Namespace, Name: spec.SecretRef.Name}, secret); err != nil {
				return fmt.Errorf("get secret %s for API key %s: %w", spec.SecretRef.Name, spec.Name, err)
			}

			secretKey := spec.SecretRef.Key
			if _, ok := secret.Data[secretKey]; !ok {
				return fmt.Errorf("secret %s missing key %s for API key %s", spec.SecretRef.Name, secretKey, spec.Name)
			}

			// Update status with secret reference (no Pocket-ID ID since we didn't create it)
			keyStatus := pocketidinternalv1alpha1.APIKeyStatus{
				Name:       spec.Name,
				SecretName: spec.SecretRef.Name,
				SecretKey:  secretKey,
			}

			base := user.DeepCopy()
			mergeAPIKeyStatus(user, keyStatus)
			if err := r.Status().Patch(ctx, user, client.MergeFrom(base)); err != nil {
				return fmt.Errorf("update status for API key %s: %w", spec.Name, err)
			}
			continue
		}

		log.Info("Creating API key", "name", spec.Name)

		if user.Status.UserID == "" {
			return fmt.Errorf("user ID not set for API key %s", spec.Name)
		}

		expiresAt := spec.ExpiresAt
		if expiresAt == "" {
			expiresAt = pocketid.DefaultAPIKeyExpiry().Format(time.RFC3339)
		}

		apiKey, err := apiClient.CreateAPIKeyForUser(ctx, user.Status.UserID, spec.Name, expiresAt, spec.Description, DefaultLoginTokenExpiryMin)
		if err != nil {
			return fmt.Errorf("create API key %s: %w", spec.Name, err)
		}

		// Create secret for the token: {username}-{apikeyname}-key
		secretName := fmt.Sprintf("%s-%s-key", user.Name, spec.Name)
		if err := ensureAPIKeySecret(ctx, r.Client, r.Scheme, user, secretName, apiKey.Token); err != nil {
			return fmt.Errorf("create secret for API key %s: %w", spec.Name, err)
		}

		// Update status
		keyStatus := pocketidinternalv1alpha1.APIKeyStatus{
			Name:       spec.Name,
			ID:         apiKey.ID,
			CreatedAt:  apiKey.CreatedAt,
			ExpiresAt:  apiKey.ExpiresAt,
			SecretName: secretName,
			SecretKey:  APIKeySecretKey,
		}

		base := user.DeepCopy()
		mergeAPIKeyStatus(user, keyStatus)
		if err := r.Status().Patch(ctx, user, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("update status for API key %s: %w", spec.Name, err)
		}
	}

	// Delete keys that are no longer wanted
	for name, keyStatus := range existingKeys {
		if wantedKeys[name] {
			continue
		}

		log.Info("Deleting API key", "name", name)

		// Delete from Pocket-ID
		if keyStatus.ID != "" {
			if err := apiClient.DeleteAPIKey(ctx, keyStatus.ID); err != nil {
				log.Error(err, "Failed to delete API key from Pocket-ID", "name", name)
			}
		}

		// Delete secret
		if keyStatus.SecretName != "" {
			if err := helpers.DeleteSecretIfExists(ctx, r.Client, user.Namespace, keyStatus.SecretName); err != nil {
				log.Error(err, "Failed to delete secret", "name", keyStatus.SecretName)
			}
		}

		// Remove from status
		base := user.DeepCopy()
		newKeys := make([]pocketidinternalv1alpha1.APIKeyStatus, 0)
		for _, k := range user.Status.APIKeys {
			if k.Name != name {
				newKeys = append(newKeys, k)
			}
		}
		user.Status.APIKeys = newKeys
		if err := r.Status().Patch(ctx, user, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("update status after deleting API key %s: %w", name, err)
		}
	}

	return nil
}

func (r *Reconciler) requestsForUserGroup(ctx context.Context, obj client.Object) []reconcile.Request {
	group, ok := obj.(*pocketidinternalv1alpha1.PocketIDUserGroup)
	if !ok {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(group.Spec.UserRefs))
	for _, ref := range group.Spec.UserRefs {
		if ref.Name == "" {
			continue
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = group.Namespace
		}
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: namespace, Name: ref.Name},
		})
	}

	return requests
}

// UserGroupUserRefIndexKey is the index key for user group user references
const UserGroupUserRefIndexKey = "pocketidusergroup.userRef"

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDUser{}).
		Watches(&pocketidinternalv1alpha1.PocketIDUserGroup{}, handler.EnqueueRequestsFromMapFunc(r.requestsForUserGroup)).
		Owns(&corev1.Secret{}).
		Named("pocketiduser").
		Complete(r)
}
