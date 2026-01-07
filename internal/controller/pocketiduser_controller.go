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

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	userFinalizer     = "pocketid.internal/user-finalizer"
	apiKeySecretKey   = "token"
	defaultAPIKeyName = "pocket-id-operator"
)

// PocketIDUserReconciler reconciles a PocketIDUser object
type PocketIDUserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *PocketIDUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the User CR
	user := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := r.Get(ctx, req.NamespacedName, user); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDUser", "name", user.Name)

	// Get the PocketIDInstance to know where to connect
	instance, err := r.getInstance(ctx, user.Namespace)
	if err != nil {
		log.Error(err, "Failed to get PocketIDInstance")
		r.setReadyCondition(ctx, user, metav1.ConditionFalse, "InstanceNotFound", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Check if instance is available
	if !r.isInstanceReady(instance) {
		log.Info("PocketIDInstance not ready, requeuing")
		r.setReadyCondition(ctx, user, metav1.ConditionFalse, "InstanceNotReady", "Waiting for PocketIDInstance to be ready")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Get API client
	apiClient, err := r.getAPIClient(ctx, instance, user.Namespace)
	if err != nil {
		log.Error(err, "Failed to get API client")
		r.setReadyCondition(ctx, user, metav1.ConditionFalse, "APIClientError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Handle deletion
	if !user.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, user, apiClient)
	}

	// Add finalizer if missing
	if !controllerutil.ContainsFinalizer(user, userFinalizer) {
		controllerutil.AddFinalizer(user, userFinalizer)
		if err := r.Update(ctx, user); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Reconcile the user in Pocket-ID
	if err := r.reconcileUser(ctx, user, apiClient); err != nil {
		log.Error(err, "Failed to reconcile user")
		r.setReadyCondition(ctx, user, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Reconcile API keys
	if err := r.reconcileAPIKeys(ctx, user, apiClient); err != nil {
		log.Error(err, "Failed to reconcile API keys")
		r.setReadyCondition(ctx, user, metav1.ConditionFalse, "APIKeyError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	r.setReadyCondition(ctx, user, metav1.ConditionTrue, "Reconciled", "User and API keys are in sync")
	return ctrl.Result{}, nil
}

// getInstance finds the PocketIDInstance in the namespace (assumes single instance per namespace)
func (r *PocketIDUserReconciler) getInstance(ctx context.Context, namespace string) (*pocketidinternalv1alpha1.PocketIDInstance, error) {
	instances := &pocketidinternalv1alpha1.PocketIDInstanceList{}
	if err := r.List(ctx, instances, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	if len(instances.Items) == 0 {
		return nil, fmt.Errorf("no PocketIDInstance found in namespace %s", namespace)
	}

	return &instances.Items[0], nil
}

// isInstanceReady checks if the instance has Available=True condition
func (r *PocketIDUserReconciler) isInstanceReady(instance *pocketidinternalv1alpha1.PocketIDInstance) bool {
	for _, cond := range instance.Status.Conditions {
		if cond.Type == "Available" && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// getAPIClient creates an authenticated Pocket-ID client
func (r *PocketIDUserReconciler) getAPIClient(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, namespace string) (*pocketid.Client, error) {
	// Use internal service URL for operator-to-instance communication
	serviceURL := internalServiceURL(instance.Name, instance.Namespace)
	baseClient := pocketid.NewClient(serviceURL)

	// If auth is configured in spec, use that
	if instance.Spec.Auth != nil {
		token, err := r.getAPIKeyToken(ctx, namespace, instance.Spec.Auth.UserRef, instance.Spec.Auth.APIKeyName)
		if err != nil {
			return nil, fmt.Errorf("get API key token: %w", err)
		}
		return baseClient.WithAPIKey(token), nil
	}

	// Check if auth is configured in status (from bootstrap)
	if instance.Status.AuthUserRef != "" && instance.Status.AuthAPIKeyName != "" {
		token, err := r.getAPIKeyTokenDirect(ctx, namespace, instance.Status.AuthUserRef, instance.Status.AuthAPIKeyName)
		if err != nil {
			return nil, fmt.Errorf("get bootstrapped API key token: %w", err)
		}
		return baseClient.WithAPIKey(token), nil
	}

	// No auth configured - this will only work for unauthenticated endpoints
	return baseClient, nil
}

// getAPIKeyTokenDirect retrieves the API key token directly from the secret
// This is used for bootstrapped auth where the status.APIKeys may not be populated yet
func (r *PocketIDUserReconciler) getAPIKeyTokenDirect(ctx context.Context, namespace, userRef, apiKeyName string) (string, error) {
	// The secret name follows the pattern: {userRef}-{apiKeyName}-key
	secretName := fmt.Sprintf("%s-%s-key", userRef, apiKeyName)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, secret); err != nil {
		return "", fmt.Errorf("get secret %s: %w", secretName, err)
	}

	token, ok := secret.Data["token"]
	if !ok {
		return "", fmt.Errorf("secret %s missing key 'token'", secretName)
	}

	return string(token), nil
}

// getAPIKeyToken retrieves the API key token from the user's secret
func (r *PocketIDUserReconciler) getAPIKeyToken(ctx context.Context, namespace, userRef, apiKeyName string) (string, error) {
	// Get the referenced User CR
	user := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: userRef}, user); err != nil {
		return "", fmt.Errorf("get user %s: %w", userRef, err)
	}

	// Find the API key in status
	var keyStatus *pocketidinternalv1alpha1.APIKeyStatus
	for i := range user.Status.APIKeys {
		if user.Status.APIKeys[i].Name == apiKeyName {
			keyStatus = &user.Status.APIKeys[i]
			break
		}
	}

	if keyStatus == nil {
		return "", fmt.Errorf("API key %s not found in user %s status", apiKeyName, userRef)
	}

	if keyStatus.SecretName == "" {
		return "", fmt.Errorf("API key %s has no secret reference", apiKeyName)
	}

	// Get the secret
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: keyStatus.SecretName}, secret); err != nil {
		return "", fmt.Errorf("get secret %s: %w", keyStatus.SecretName, err)
	}

	key := keyStatus.SecretKey
	if key == "" {
		key = apiKeySecretKey
	}

	token, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s missing key %s", keyStatus.SecretName, key)
	}

	return string(token), nil
}

// reconcileDelete handles user deletion
func (r *PocketIDUserReconciler) reconcileDelete(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Delete user from Pocket-ID if we have their ID
	if user.Status.UserID != "" {
		log.Info("Deleting user from Pocket-ID", "userID", user.Status.UserID)
		if err := apiClient.DeleteUser(ctx, user.Status.UserID); err != nil {
			log.Error(err, "Failed to delete user from Pocket-ID, continuing with finalizer removal")
		}
	}

	// Delete associated secrets
	for _, keyStatus := range user.Status.APIKeys {
		if keyStatus.SecretName != "" {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      keyStatus.SecretName,
					Namespace: user.Namespace,
				},
			}
			if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete secret", "secret", keyStatus.SecretName)
			}
		}
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(user, userFinalizer)
	if err := r.Update(ctx, user); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// resolveStringValue resolves a StringValue to its actual string value
func (r *PocketIDUserReconciler) resolveStringValue(ctx context.Context, namespace string, sv pocketidinternalv1alpha1.StringValue) (string, error) {
	if sv.Value != "" {
		return sv.Value, nil
	}
	if sv.ValueFrom != nil {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: sv.ValueFrom.Name}, secret); err != nil {
			return "", fmt.Errorf("get secret %s: %w", sv.ValueFrom.Name, err)
		}
		key := sv.ValueFrom.Key
		val, ok := secret.Data[key]
		if !ok {
			return "", fmt.Errorf("secret %s missing key %s", sv.ValueFrom.Name, key)
		}
		return string(val), nil
	}
	return "", nil
}

// reconcileUser ensures the user exists in Pocket-ID with correct settings
func (r *PocketIDUserReconciler) reconcileUser(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client) error {
	log := logf.FromContext(ctx)

	// Resolve all StringValue fields
	username, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.Username)
	if err != nil {
		return fmt.Errorf("resolve username: %w", err)
	}
	if username == "" {
		username = user.Name
	}

	firstName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.FirstName)
	if err != nil {
		return fmt.Errorf("resolve firstName: %w", err)
	}
	// FirstName is required by Pocket-ID, default to username if not set
	if firstName == "" {
		firstName = username
	}

	lastName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.LastName)
	if err != nil {
		return fmt.Errorf("resolve lastName: %w", err)
	}

	email, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.Email)
	if err != nil {
		return fmt.Errorf("resolve email: %w", err)
	}
	// Email is required by Pocket-ID, generate a placeholder if not set
	if email == "" {
		email = fmt.Sprintf("%s@placeholder.local", username)
	}

	displayName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.DisplayName)
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

	// If we don't have a user ID, we need to create the user
	if user.Status.UserID == "" {
		log.Info("Creating user in Pocket-ID", "username", username)
		pUser, err := apiClient.CreateUser(ctx, input)
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		return r.updateUserStatus(ctx, user, pUser)
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
func (r *PocketIDUserReconciler) updateUserStatus(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, pUser *pocketid.User) error {
	base := user.DeepCopy()

	user.Status.UserID = pUser.ID
	user.Status.Username = pUser.Username
	user.Status.DisplayName = pUser.DisplayName
	user.Status.Email = pUser.Email
	user.Status.IsAdmin = pUser.IsAdmin
	user.Status.Disabled = pUser.Disabled
	user.Status.Locale = pUser.Locale

	return r.Status().Patch(ctx, user, client.MergeFrom(base))
}

// reconcileAPIKeys ensures API keys exist in Pocket-ID and secrets are created
func (r *PocketIDUserReconciler) reconcileAPIKeys(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, apiClient *pocketid.Client) error {
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

			// Verify the secret exists
			secret := &corev1.Secret{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: user.Namespace, Name: spec.SecretRef.Name}, secret); err != nil {
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
			user.Status.APIKeys = append(user.Status.APIKeys, keyStatus)
			if err := r.Status().Patch(ctx, user, client.MergeFrom(base)); err != nil {
				return fmt.Errorf("update status for API key %s: %w", spec.Name, err)
			}
			continue
		}

		log.Info("Creating API key", "name", spec.Name)

		expiresAt := spec.ExpiresAt
		if expiresAt == "" {
			expiresAt = pocketid.DefaultAPIKeyExpiry().Format(time.RFC3339)
		}

		apiKey, err := apiClient.CreateAPIKey(ctx, spec.Name, expiresAt, spec.Description)
		if err != nil {
			return fmt.Errorf("create API key %s: %w", spec.Name, err)
		}

		// Create secret for the token: {username}-{apikeyname}-key
		secretName := fmt.Sprintf("%s-%s-key", user.Name, spec.Name)
		if err := r.createAPIKeySecret(ctx, user, secretName, apiKey.Token); err != nil {
			return fmt.Errorf("create secret for API key %s: %w", spec.Name, err)
		}

		// Update status
		keyStatus := pocketidinternalv1alpha1.APIKeyStatus{
			Name:       spec.Name,
			ID:         apiKey.ID,
			CreatedAt:  apiKey.CreatedAt,
			ExpiresAt:  apiKey.ExpiresAt,
			SecretName: secretName,
			SecretKey:  apiKeySecretKey,
		}

		base := user.DeepCopy()
		user.Status.APIKeys = append(user.Status.APIKeys, keyStatus)
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
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      keyStatus.SecretName,
					Namespace: user.Namespace,
				},
			}
			if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
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

// createAPIKeySecret creates a secret containing the API key token
func (r *PocketIDUserReconciler) createAPIKeySecret(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, secretName, token string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: user.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := controllerutil.SetControllerReference(user, secret, r.Scheme); err != nil {
			return err
		}

		secret.Type = corev1.SecretTypeOpaque
		secret.Data = map[string][]byte{
			apiKeySecretKey: []byte(token),
		}

		return nil
	})

	return err
}

// setReadyCondition updates the Ready condition on the User CR
func (r *PocketIDUserReconciler) setReadyCondition(ctx context.Context, user *pocketidinternalv1alpha1.PocketIDUser, status metav1.ConditionStatus, reason, message string) {
	base := user.DeepCopy()

	meta.SetStatusCondition(&user.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: user.Generation,
	})

	if err := r.Status().Patch(ctx, user, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update condition")
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *PocketIDUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDUser{}).
		Owns(&corev1.Secret{}).
		Named("pocketiduser").
		Complete(r)
}
