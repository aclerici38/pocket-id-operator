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
	"net/http"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
	"github.com/aclerici38/pocket-id-operator/internal/metrics"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	UserFinalizer          = "pocketid.internal/user-finalizer"
	UserGroupUserFinalizer = "pocketid.internal/user-group-finalizer"
	// DefaultLoginTokenExpiryMin must stay above 15 for a full-length token
	DefaultLoginTokenExpiryMin = 60
	loginTokenTTL              = DefaultLoginTokenExpiryMin * time.Minute
	apiKeysPageSize            = 100

	// DeleteFromPocketIDAnnotation when set to "true" will delete the user from Pocket-ID
	// when the PocketIDUser resource is deleted from Kubernetes. By default, users are
	// NOT deleted from Pocket-ID when the resource is deleted.
	DeleteFromPocketIDAnnotation = "pocketid.internal/delete-from-pocket-id"
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

	// apiKeysChecked holds the UIDs of users whose keys this process has compared with Pocket-ID,
	// so a restart or rollout checks every user's keys once.
	apiKeysChecked sync.Map
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

	user := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := r.Get(ctx, req.NamespacedName, user); err != nil {
		if client.IgnoreNotFound(err) == nil {
			metrics.DeleteReadinessGauge("PocketIDUser", req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("Reconciling PocketIDUser", "name", user.Name)

	if !user.DeletionTimestamp.IsZero() {
		return r.ReconcileDelete(ctx, user)
	}

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
		return ctrl.Result{RequeueAfter: common.RequeueImmediate}, nil
	}

	// Validate instance is ready using base reconciler
	if validationResult := r.ValidateInstanceReady(ctx, user, instance); validationResult.ShouldRequeue {
		return ctrl.Result{RequeueAfter: validationResult.RequeueAfter}, validationResult.Error
	}

	apiClient, result, err := r.GetAPIClientOrRequeue(ctx, user, instance)
	if result != nil {
		return *result, err
	}

	// No user ID yet, create or adopt
	if user.Status.UserID == "" {
		requeue, err := r.createOrAdoptUser(ctx, user, apiClient, instance)
		if err != nil {
			log.Error(err, "Failed to create or adopt user")
			_ = r.SetReadyCondition(ctx, user, metav1.ConditionFalse, common.ErrorReason(err, "ReconcileError"), err.Error())
			return ctrl.Result{RequeueAfter: common.RequeueAfterFor(err)}, nil
		}
		if requeue {
			return ctrl.Result{RequeueAfter: common.RequeueImmediate}, nil
		}
		return common.ApplyResync(ctrl.Result{}), nil
	}

	pUser, err := r.pushUserState(ctx, user, apiClient)
	if err != nil {
		if pocketid.IsNotFoundError(err) {
			log.Info("User was deleted externally, will recreate", "userID", user.Status.UserID)
			metrics.ExternalDeletions.WithLabelValues("PocketIDUser").Inc()
			if err := r.clearUserStatus(ctx, user); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: common.RequeueImmediate}, nil
		}
		log.Error(err, "Failed to push user state")
		_ = r.SetReadyCondition(ctx, user, metav1.ConditionFalse, common.ErrorReason(err, "ReconcileError"), err.Error())
		return ctrl.Result{RequeueAfter: common.RequeueAfterFor(err)}, nil
	}

	if err := r.updateUserStatus(ctx, user, pUser); err != nil {
		log.Error(err, "Failed to update user status")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.reconcileAPIKeys(ctx, user, apiClient, instance.Namespace, instance.Name); err != nil {
		log.Error(err, "Failed to reconcile API keys")
		_ = r.SetReadyCondition(ctx, user, metav1.ConditionFalse, common.ErrorReason(err, "APIKeyError"), err.Error())
		return ctrl.Result{RequeueAfter: common.RequeueAfterFor(err)}, nil
	}

	if err := r.createOneTimeToken(ctx, user, apiClient, instance); err != nil {
		log.Error(err, "Failed to create one-time login token")
		return ctrl.Result{RequeueAfter: common.RequeueAfterFor(err)}, nil
	}

	cleanupResult, err := r.cleanupOneTimeToken(ctx, user)
	if err != nil {
		log.Error(err, "Failed to cleanup expired one-time login token")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	_ = r.SetReadyCondition(ctx, user, metav1.ConditionTrue, "Reconciled", "User and API keys are in sync")

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
	return common.IsReferencedByList(
		ctx,
		r.Client,
		common.UserGroupUserRefIndexKey,
		userKey,
		&pocketidinternalv1alpha1.PocketIDUserGroupList{},
		func(item client.Object) bool {
			group := item.(*pocketidinternalv1alpha1.PocketIDUserGroup)
			return userGroupHasUserRef(group, userName, userNamespace)
		},
	)
}

func userGroupHasUserRef(group *pocketidinternalv1alpha1.PocketIDUserGroup, userName, userNamespace string) bool {
	if group.Spec.Users == nil {
		return false
	}
	for _, ref := range group.Spec.Users.UserRefs {
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
	r.EnsureClient(r.Client)
	r.apiKeysChecked.Delete(user.UID)

	// Check if user is referenced by user groups
	referencedByUserGroup, err := r.isUserReferencedByUserGroup(ctx, user.Name, user.Namespace)
	if err != nil {
		log.Error(err, "Failed to check PocketIDUserGroup references")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if referencedByUserGroup {
		log.Info("User is referenced by PocketIDUserGroup, blocking deletion", "user", user.Name)
		// The resource still exists in Pocket-ID, so it must stay Ready for dependents to resolve it.
		_ = r.SetReadyCondition(ctx, user, metav1.ConditionTrue, "DeletionBlocked", "Deletion is blocked while referenced by a PocketIDUserGroup")
		if _, err := helpers.EnsureFinalizer(ctx, r.Client, user, UserGroupUserFinalizer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Remove UserGroupUserFinalizer if not referenced by any user group
	if controllerutil.ContainsFinalizer(user, UserGroupUserFinalizer) {
		if err := helpers.RemoveFinalizers(ctx, r.Client, user, UserGroupUserFinalizer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: common.RequeueImmediate}, nil
	}

	// Only delete user from Pocket-ID if the annotation is set to "true"
	shouldDeleteFromPocketID := helpers.HasAnnotation(user, DeleteFromPocketIDAnnotation, "true")

	if user.Status.UserID != "" && shouldDeleteFromPocketID {
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
			// A user already gone from Pocket-ID must not hold the finalizer.
			if err := pid.Check(apiClient.DeleteUser(ctx, user.Status.UserID)); err != nil {
				if !pocketid.IsNotFoundError(err) {
					log.Error(err, "Failed to delete user from Pocket-ID")
					return ctrl.Result{}, err
				}
				log.Info("User already absent from Pocket-ID, treating delete as complete", "userID", user.Status.UserID)
			} else {
				metrics.ResourceOperations.WithLabelValues("PocketIDUser", "deleted").Inc()
			}
		}
	} else if user.Status.UserID != "" {
		log.Info("Skipping Pocket-ID user deletion (annotation not set)", "userID", user.Status.UserID, "annotation", DeleteFromPocketIDAnnotation)
	}

	// Delete associated secrets
	secretNames := make([]string, 0, len(user.Status.APIKeys))
	for _, keyStatus := range user.Status.APIKeys {
		if keyStatus.SecretName != "" {
			secretNames = append(secretNames, keyStatus.SecretName)
		}
	}
	if err := helpers.DeleteSecretsIfManaged(ctx, r.Client, user.Namespace, secretNames); err != nil {
		log.Error(err, "Failed to delete secrets")
	}

	metrics.DeleteReadinessGauge("PocketIDUser", user.Namespace, user.Name)

	// Remove finalizers
	if err := helpers.RemoveFinalizers(ctx, r.Client, user, UserFinalizer, UserGroupUserFinalizer); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// FindExistingUser checks if a user already exists in Pocket-ID.
// If id is non-empty, it looks up by ID directly. Otherwise it searches by username
// and then email. Returns the existing user if found, or nil if no match exists.
func (r *Reconciler) FindExistingUser(ctx context.Context, apiClient *pocketid.Client, id, username, email string) (*pid.UserDto, error) {
	log := logf.FromContext(ctx)

	if id != "" {
		log.Info("Looking up user by ID", "userID", id)
		existingUser, err := pid.Decode[*pid.UserDto](apiClient.GetUserByID(ctx, id))
		if err != nil {
			if pocketid.IsNotFoundError(err) {
				log.Info("User not found in Pocket-ID", "userID", id)
				return nil, nil
			}
			return nil, fmt.Errorf("get user: %w", err)
		}
		log.Info("Found existing user in Pocket-ID", "userID", id)
		return existingUser, nil
	}

	// Check if user with username already exists
	log.Info("Checking if user exists in Pocket-ID", "username", username)
	for existingUser, err := range apiClient.SearchUsers(ctx, username) {
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		if existingUser.Username == username {
			log.Info("Found existing user with matching username", "username", username, "userID", existingUser.ID)
			return &existingUser, nil
		}
	}

	// Check if email already exists
	if email != "" {
		for existingUser, err := range apiClient.SearchUsers(ctx, email) {
			if err != nil {
				return nil, fmt.Errorf("list users by email: %w", err)
			}
			if existingUser.Email == email {
				log.Info("Found existing user with matching email", "email", email, "userID", existingUser.ID)
				return &existingUser, nil
			}
		}
	}

	return nil, nil
}

// userInput is the user's profile, resolved from spec and secrets.
type userInput struct {
	username, firstName, lastName, email, displayName string
}

// buildUserInput resolves all user fields from spec and secrets into a userInput.
func (r *Reconciler) buildUserInput(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser) (userInput, error) {
	userInfoInputSecret := userInfoInputSecretName(user)
	username, err := helpers.ResolveStringValue(ctx, r.Client, r.APIReader, user.Namespace, user.Spec.Username, userInfoInputSecret, UserInfoSecretKeyUsername)
	if err != nil {
		return userInput{}, fmt.Errorf("resolve username: %w", err)
	}
	if username == "" {
		username = user.Name
	}

	firstName, err := helpers.ResolveStringValue(ctx, r.Client, r.APIReader, user.Namespace, user.Spec.FirstName, userInfoInputSecret, UserInfoSecretKeyFirstName)
	if err != nil {
		return userInput{}, fmt.Errorf("resolve firstName: %w", err)
	}
	// FirstName is required by Pocket-ID, default to username if not set
	if firstName == "" {
		firstName = username
	}

	lastName, err := helpers.ResolveStringValue(ctx, r.Client, r.APIReader, user.Namespace, user.Spec.LastName, userInfoInputSecret, UserInfoSecretKeyLastName)
	if err != nil {
		return userInput{}, fmt.Errorf("resolve lastName: %w", err)
	}

	email, err := helpers.ResolveStringValue(ctx, r.Client, r.APIReader, user.Namespace, user.Spec.Email, userInfoInputSecret, UserInfoSecretKeyEmail)
	if err != nil {
		return userInput{}, fmt.Errorf("resolve email: %w", err)
	}

	displayName, err := helpers.ResolveStringValue(ctx, r.Client, r.APIReader, user.Namespace, user.Spec.DisplayName, userInfoInputSecret, UserInfoSecretKeyDisplayName)
	if err != nil {
		return userInput{}, fmt.Errorf("resolve displayName: %w", err)
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

	return userInput{username: username, firstName: firstName, lastName: lastName, email: email, displayName: displayName}, nil
}

// userPatch is every profile field the operator manages. emailVerified is managed by Pocket-ID,
// and the ID can only be set at creation.
func userPatch(user *pocketidinternalv1alpha1.PocketIDUser, input userInput) pid.PatchUserJSONRequestBody {
	return pid.PatchUserJSONRequestBody{
		Username:    &input.username,
		FirstName:   &input.firstName,
		LastName:    &input.lastName,
		Email:       pocketid.NullIfEmpty(input.email),
		DisplayName: &input.displayName,
		IsAdmin:     &user.Spec.Admin,
		Disabled:    &user.Spec.Disabled,
		Locale:      pocketid.NullIfEmpty(user.Spec.Locale),
	}
}

// createOrAdoptUser handles creation or adoption when no status ID exists.
// Returns (requeue, error). On success, sets the status ID and signals a requeue.
func (r *Reconciler) createOrAdoptUser(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client, instance *pocketidinternalv1alpha1.PocketIDInstance) (bool, error) {
	log := logf.FromContext(ctx)

	input, err := r.buildUserInput(ctx, user)
	if err != nil {
		return false, err
	}

	// A declarative ID identifies the user directly, so adopt an existing one up front
	id := user.Spec.UserID
	if id != "" {
		existing, err := r.FindExistingUser(ctx, apiClient, id, "", "")
		if err != nil {
			return false, fmt.Errorf("search for existing user by ID: %w", err)
		}
		if existing != nil {
			log.Info("Found existing user by ID, adopting", "userID", existing.ID)
			metrics.ResourceOperations.WithLabelValues("PocketIDUser", "adopted").Inc()
			return true, r.setUserID(ctx, user, existing.ID)
		}
	}

	patch := userPatch(user, input)
	result, err := common.CreateOrAdopt(ctx, common.CreateOrAdoptConfig[*pid.UserDto]{
		ResourceKind: "user",
		ResourceID:   input.username,
		Create: func() (*pid.UserDto, error) {
			body := pid.UserCreateDto{
				Username:    input.username,
				FirstName:   patch.FirstName,
				LastName:    patch.LastName,
				Email:       patch.Email,
				DisplayName: patch.DisplayName,
				IsAdmin:     patch.IsAdmin,
				Disabled:    patch.Disabled,
				Locale:      patch.Locale,
			}
			// Pocket-ID generates an ID unless the spec declares one.
			if id != "" {
				body.ID = &id
			}
			return pid.Decode[*pid.UserDto](apiClient.CreateUser(ctx, body))
		},
		FindExisting: func() (*pid.UserDto, error) {
			return r.FindExistingUser(ctx, apiClient, id, input.username, input.email)
		},
		IsNil: func(u *pid.UserDto) bool {
			return u == nil
		},
	})
	if err != nil {
		return false, err
	}

	if result.Resource == nil {
		return true, nil
	}

	operation := "adopted"
	if result.IsNewlyCreated {
		operation = "created"
	}
	metrics.ResourceOperations.WithLabelValues("PocketIDUser", operation).Inc()

	if err := r.setUserID(ctx, user, result.Resource.ID); err != nil {
		return false, err
	}

	// Generate one-time login token for newly created user only
	if result.IsNewlyCreated {
		token, err := createLoginToken(ctx, apiClient, result.Resource.ID)
		if err != nil {
			log.Error(err, "Failed to create one-time login token - user created but token not available")
		} else {
			if err := r.SetOneTimeLoginStatus(ctx, user, instance, token); err != nil {
				return false, fmt.Errorf("set one-time login status: %w", err)
			}
		}
	}

	return true, nil
}

// pushUserState writes the spec's profile and custom claims, and returns the user as it stands
// afterwards.
func (r *Reconciler) pushUserState(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client) (pid.UserDto, error) {
	input, err := r.buildUserInput(ctx, user)
	if err != nil {
		return pid.UserDto{}, err
	}

	pUser, err := pid.Decode[pid.UserDto](apiClient.PatchUser(ctx, user.Status.UserID, userPatch(user, input)))
	if err != nil {
		return pUser, fmt.Errorf("update user: %w", err)
	}

	if pUser.CustomClaims, err = pid.Decode[[]pid.CustomClaimDto](apiClient.UpdateCustomClaimsForUser(ctx, user.Status.UserID,
		helpers.CustomClaimsToPocketID(user.Spec.CustomClaims))); err != nil {
		return pUser, fmt.Errorf("update user custom claims: %w", err)
	}
	return pUser, nil
}

// setUserID persists only the user ID to status.
func (r *Reconciler) setUserID(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, id string) error {
	base := user.DeepCopy()
	user.Status.UserID = id
	return common.PatchStatus(ctx, r.Client, user, base)
}

// clearUserStatus clears the UserID from status, triggering recreation on next reconcile.
func (r *Reconciler) clearUserStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser) error {
	return r.ClearStatusField(ctx, user, func() {
		user.Status.UserID = ""
		user.Status.APIKeys = nil
	})
}

// updateUserStatus updates the User CR status from Pocket-ID response
func (r *Reconciler) updateUserStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, pUser pid.UserDto) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &pocketidinternalv1alpha1.PocketIDUser{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(user), latest); err != nil {
			return err
		}
		base := latest.DeepCopy()

		oldSecretName := latest.Status.UserInfoSecretName
		secretName := userInfoOutputSecretName(latest.Name)
		if oldSecretName != "" && oldSecretName != secretName {
			if err := helpers.DeleteSecretIfManaged(ctx, r.Client, latest.Namespace, oldSecretName); err != nil {
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
		latest.Status.EmailVerified = pUser.EmailVerified
		latest.Status.CustomClaims = helpers.CustomClaimsFromPocketID(pUser.CustomClaims)

		return common.PatchStatus(ctx, r.Client, latest, base)
	})
}

func (r *Reconciler) SetOneTimeLoginStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, instance *pocketidinternalv1alpha1.PocketIDInstance, token string) error {
	base := user.DeepCopy()

	baseURL := instance.EffectiveAppURL()
	if baseURL == "" {
		baseURL = common.InternalServiceURL(instance)
	}
	loginURL := fmt.Sprintf("%s/lc/%s", baseURL, token)
	expiresAt := time.Now().UTC().Add(loginTokenTTL)

	user.Status.OneTimeLoginToken = token
	user.Status.OneTimeLoginURL = loginURL
	user.Status.OneTimeLoginExpiresAt = expiresAt.Format(time.RFC3339)

	return common.PatchStatus(ctx, r.Client, user, base)
}

// createOneTimeToken generates a one-time login token for the user
// if one doesn't already exist, and writes it to the CR status.
func (r *Reconciler) createOneTimeToken(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	if user.Status.UserID == "" {
		return nil
	}
	if user.Status.OneTimeLoginExpiresAt != "" {
		return nil
	}

	token, err := createLoginToken(ctx, apiClient, user.Status.UserID)
	if err != nil {
		return fmt.Errorf("create one-time login token: %w", err)
	}

	return r.SetOneTimeLoginStatus(ctx, user, instance, token)
}

// createLoginToken creates a one-time token the user can sign in with at /lc/{token}.
func createLoginToken(ctx context.Context, apiClient *pocketid.Client, userID string) (string, error) {
	token, err := pid.Decode[pid.TokenCreatedDto](apiClient.CreateOneTimeAccessTokenForUserAdmin(ctx, userID,
		pid.TokenCreateDto{TTL: new(int64(loginTokenTTL.Seconds()))}))
	return token.Token, err
}

// cleanupOneTimeToken clears the one-time login token from status if it
// has expired, or returns a requeue result to clean it up when it does expire.
func (r *Reconciler) cleanupOneTimeToken(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser) (ctrl.Result, error) {
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

	if err := common.PatchStatus(ctx, r.Client, user, base); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// reconcileAPIKeys converges the user's API keys in Pocket-ID, and the Secrets holding their tokens, onto the spec.
// Keys are only managed in a session as their owner, and Pocket-ID rate-limits starting sessions per client IP,
// so it is skipped once this process has checked them and a reconcile of the current spec has converged them.
func (r *Reconciler) reconcileAPIKeys(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client, instanceNamespace, instanceName string) error {
	if len(user.Spec.APIKeys) == 0 && len(user.Status.APIKeys) == 0 {
		return nil
	}
	if _, checked := r.apiKeysChecked.Load(user.UID); checked && apiKeysConverged(user) {
		return nil
	}
	err := apiClient.WithUserSession(ctx, user.Status.UserID, loginTokenTTL, func(session *pid.Client) error {
		current := make(map[string]pid.APIKeyDto)
		for key, err := range pid.All[pid.APIKeyDto](func(page int) (*http.Response, error) {
			return session.ListAPIKeys(ctx, &pid.ListAPIKeysParams{PaginationPage: &page, PaginationLimit: new(apiKeysPageSize)})
		}) {
			if err != nil {
				return fmt.Errorf("list API keys: %w", err)
			}
			current[key.ID] = key
		}

		recordOp := func(operation string) {
			metrics.APIKeyOperations.WithLabelValues(instanceNamespace, instanceName, operation).Inc()
		}
		for _, spec := range user.Spec.APIKeys {
			if err := r.reconcileAPIKey(ctx, user, session, spec, current, recordOp); err != nil {
				return fmt.Errorf("API key %s: %w", spec.Name, err)
			}
		}
		return r.pruneAPIKeys(ctx, user, session, recordOp)
	})
	if err == nil {
		r.apiKeysChecked.Store(user.UID, struct{}{})
	}
	return err
}

// reconcileAPIKey creates the key if Pocket-ID doesn't have it, then pushes any drift from the spec.
func (r *Reconciler) reconcileAPIKey(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, session *pid.Client, spec pocketidinternalv1alpha1.APIKeySpec, current map[string]pid.APIKeyDto, recordOp func(string)) error {
	log := logf.FromContext(ctx)

	status := apiKeyStatus(user, spec.Name)
	secretName := fmt.Sprintf("%s-%s-key", user.Name, spec.Name)
	key, exists := current[status.ID]

	var issued pid.APIKeyResponseDto
	switch {
	case !exists:
		if status.ID != "" {
			log.Info("API key was deleted externally, will recreate", "name", spec.Name, "id", status.ID)
			metrics.ExternalDeletions.WithLabelValues("APIKey").Inc()
		}
		log.Info("Creating API key", "name", spec.Name)
		expiresAt, err := apiKeyExpiry(spec.ExpiresAt)
		if err != nil {
			return err
		}
		if issued, err = pid.Decode[pid.APIKeyResponseDto](session.CreateAPIKey(ctx, pid.APIKeyCreateDto{
			Name:        spec.Name,
			ExpiresAt:   expiresAt,
			Description: pocketid.NullIfEmpty(spec.Description),
			Scopes:      spec.Scopes,
		})); err != nil {
			return fmt.Errorf("create API key: %w", err)
		}
		recordOp("created")
	// Status records the expiry whose token was saved, so a renewal whose token never reached the Secret is retried.
	case expiryDrifted(spec.ExpiresAt, key.ExpiresAt.Format(time.RFC3339)) || expiryDrifted(spec.ExpiresAt, status.ExpiresAt):
		log.Info("Renewing API key", "name", spec.Name, "expiresAt", spec.ExpiresAt)
		expiresAt, err := apiKeyExpiry(spec.ExpiresAt)
		if err != nil {
			return err
		}
		if issued, err = pid.Decode[pid.APIKeyResponseDto](session.RenewAPIKey(ctx, key.ID, pid.APIKeyRenewDto{
			ExpiresAt:        expiresAt,
			GracePeriodHours: new(0),
		})); err != nil {
			return fmt.Errorf("renew API key: %w", err)
		}
		recordOp("renewed")
	}
	if issued.Token != "" {
		key = issued.APIKey
		if err := ensureAPIKeySecret(ctx, r.Client, r.Scheme, user, secretName, issued.Token); err != nil {
			// The retry creates another key, so revoke this one rather than leave a key nobody holds the token for.
			if !exists {
				if revokeErr := revokeAPIKey(ctx, session, key.ID); revokeErr != nil {
					log.Error(revokeErr, "Failed to revoke API key whose token wasn't saved", "name", spec.Name)
				}
			}
			return fmt.Errorf("write token secret: %w", err)
		}
	}

	if key.Name != spec.Name || key.Description != spec.Description || !scopesEqual(key.Scopes, spec.Scopes) {
		log.Info("Updating API key", "name", spec.Name)
		updated, err := pid.Decode[pid.APIKeyDto](session.UpdateAPIKey(ctx, key.ID, pid.APIKeyUpdateDto{
			Name:        spec.Name,
			Description: pocketid.NullIfEmpty(spec.Description),
			Scopes:      spec.Scopes,
		}))
		if err != nil {
			return fmt.Errorf("update API key: %w", err)
		}
		key = updated
		recordOp("updated")
	}

	lastUsedAt := ""
	if key.LastUsedAt != nil {
		lastUsedAt = key.LastUsedAt.Format(time.RFC3339)
	}
	base := user.DeepCopy()
	mergeAPIKeyStatus(user, pocketidinternalv1alpha1.APIKeyStatus{
		Name:       spec.Name,
		ID:         key.ID,
		CreatedAt:  key.CreatedAt.Format(time.RFC3339),
		ExpiresAt:  key.ExpiresAt.Format(time.RFC3339),
		LastUsedAt: lastUsedAt,
		SecretName: secretName,
	})
	return common.PatchStatus(ctx, r.Client, user, base)
}

// apiKeyExpiry returns the spec's expiry, or the default when it sets none.
func apiKeyExpiry(spec string) (time.Time, error) {
	if spec == "" {
		return pocketid.DefaultAPIKeyExpiry(), nil
	}
	expiresAt, err := time.Parse(time.RFC3339, spec)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse expiresAt: %w", err)
	}
	return expiresAt, nil
}

// revokeAPIKey revokes an API key, treating one that's already gone as revoked.
func revokeAPIKey(ctx context.Context, session *pid.Client, id string) error {
	if err := pid.Check(session.RevokeAPIKey(ctx, id)); err != nil && !pocketid.IsNotFoundError(err) {
		return fmt.Errorf("revoke API key: %w", err)
	}
	return nil
}

// pruneAPIKeys revokes the keys recorded in status that are no longer in the spec.
func (r *Reconciler) pruneAPIKeys(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, session *pid.Client, recordOp func(string)) error {
	log := logf.FromContext(ctx)

	wantedKeys := make(map[string]bool, len(user.Spec.APIKeys))
	for _, spec := range user.Spec.APIKeys {
		wantedKeys[spec.Name] = true
	}

	for _, keyStatus := range slices.Clone(user.Status.APIKeys) {
		name := keyStatus.Name
		if wantedKeys[name] {
			continue
		}

		log.Info("Deleting API key", "name", name)
		if keyStatus.ID != "" {
			if err := revokeAPIKey(ctx, session, keyStatus.ID); err != nil {
				return fmt.Errorf("delete API key %s: %w", name, err)
			}
			recordOp("deleted")
		}

		// Delete secret
		if keyStatus.SecretName != "" {
			if err := helpers.DeleteSecretIfManaged(ctx, r.Client, user.Namespace, keyStatus.SecretName); err != nil {
				log.Error(err, "Failed to delete secret", "name", keyStatus.SecretName)
			}
		}

		base := user.DeepCopy()
		user.Status.APIKeys = slices.DeleteFunc(user.Status.APIKeys, func(k pocketidinternalv1alpha1.APIKeyStatus) bool {
			return k.Name == name
		})
		if err := common.PatchStatus(ctx, r.Client, user, base); err != nil {
			return fmt.Errorf("update status after deleting API key %s: %w", name, err)
		}
	}

	return nil
}

// apiKeysConverged reports whether every key in the spec has been created, and Ready says the current spec was reconciled.
func apiKeysConverged(user *pocketidinternalv1alpha1.PocketIDUser) bool {
	if len(user.Spec.APIKeys) != len(user.Status.APIKeys) {
		return false
	}
	for _, spec := range user.Spec.APIKeys {
		if apiKeyStatus(user, spec.Name).ID == "" {
			return false
		}
	}
	ready := meta.FindStatusCondition(user.Status.Conditions, "Ready")
	return ready != nil && ready.Status == metav1.ConditionTrue && ready.ObservedGeneration == user.Generation
}

func apiKeyStatus(user *pocketidinternalv1alpha1.PocketIDUser, name string) pocketidinternalv1alpha1.APIKeyStatus {
	for _, status := range user.Status.APIKeys {
		if status.Name == name {
			return status
		}
	}
	return pocketidinternalv1alpha1.APIKeyStatus{}
}

// expiryDrifted reports whether an explicit expiry in the spec differs from the key's.
// An unparsable one counts as drift so Pocket-ID's rejection of it surfaces. Sqlite stores whole seconds.
func expiryDrifted(desired, actual string) bool {
	if desired == "" {
		return false
	}
	want, wantErr := time.Parse(time.RFC3339, desired)
	got, gotErr := time.Parse(time.RFC3339, actual)
	return wantErr != nil || gotErr != nil || !want.Truncate(time.Second).Equal(got.Truncate(time.Second))
}

// scopesEqual compares scopes as sets, since Pocket-ID sorts and dedupes the scopes it stores.
func scopesEqual(a, b []string) bool {
	return slices.Equal(slices.Compact(slices.Sorted(slices.Values(a))), slices.Compact(slices.Sorted(slices.Values(b))))
}

func (r *Reconciler) requestsForUserGroup(ctx context.Context, obj client.Object) []reconcile.Request {
	group, ok := obj.(*pocketidinternalv1alpha1.PocketIDUserGroup)
	if !ok {
		return nil
	}

	if group.Spec.Users == nil || len(group.Spec.Users.UserRefs) == 0 {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(group.Spec.Users.UserRefs))
	for _, ref := range group.Spec.Users.UserRefs {
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

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDUser{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&pocketidinternalv1alpha1.PocketIDUserGroup{}, handler.EnqueueRequestsFromMapFunc(r.requestsForUserGroup)).
		Owns(&corev1.Secret{}).
		Named("pocketiduser").
		Complete(r)
}
