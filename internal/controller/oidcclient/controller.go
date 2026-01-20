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

package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	oidcClientFinalizer = "pocketid.internal/oidc-client-finalizer"
)

// OIDCClientAllowedGroupIndexKey is the index key for OIDC client allowed groups
const OIDCClientAllowedGroupIndexKey = "pocketidoidcclient.allowedGroup"

// Reconciler reconciles a PocketIDOIDCClient object
type Reconciler struct {
	client.Client
	common.BaseReconciler
	APIReader client.Reader
	Scheme    *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	r.EnsureClient(r.Client)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := r.Get(ctx, req.NamespacedName, oidcClient); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDOIDCClient", "name", oidcClient.Name)

	if !oidcClient.DeletionTimestamp.IsZero() {
		return r.ReconcileDelete(ctx, oidcClient)
	}

	if updated, err := helpers.EnsureFinalizer(ctx, r.Client, oidcClient, oidcClientFinalizer); err != nil {
		return ctrl.Result{}, err
	} else if updated {
		return ctrl.Result{Requeue: true}, nil
	}

	instance, err := common.SelectInstance(ctx, r.Client, oidcClient.Spec.InstanceSelector)
	if err != nil {
		log.Error(err, "Failed to select PocketIDInstance")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "InstanceSelectionError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if validationResult := r.ValidateInstanceReady(ctx, oidcClient, instance); validationResult.ShouldRequeue {
		return ctrl.Result{RequeueAfter: validationResult.RequeueAfter}, validationResult.Error
	}

	// Get API client from pool
	apiClient, result, err := r.GetAPIClientOrWait(ctx, oidcClient, instance)
	if result != nil {
		return *result, err
	}

	current, err := r.reconcileOIDCClient(ctx, oidcClient, apiClient)
	if err != nil {
		log.Error(err, "Failed to reconcile OIDC client")
		if updateErr := r.UpdateOIDCClientStatus(ctx, oidcClient, current); updateErr != nil {
			log.Error(updateErr, "Failed to update OIDC client status")
		}
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.UpdateOIDCClientStatus(ctx, oidcClient, current); err != nil {
		log.Error(err, "Failed to update OIDC client status")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient); err != nil {
		log.Error(err, "Failed to reconcile OIDC client secret")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "SecretReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if removed, err := helpers.CheckAndRemoveAnnotation(ctx, r.Client, oidcClient, "pocketid.internal/regenerate-client-secret", "true"); err != nil {
		log.Error(err, "Failed to remove regenerate-client-secret annotation")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	} else if removed {
		log.Info("Removed regenerate-client-secret annotation after secret regeneration")
	}

	_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionTrue, "Reconciled", "OIDC client is in sync")

	return common.ApplyResync(ctrl.Result{}), nil
}

// pocketIDOIDCClientAPI defines the minimal interface needed for OIDC client operations
type pocketIDOIDCClientAPI interface {
	ListOIDCClients(ctx context.Context, search string) ([]*pocketid.OIDCClient, error)
	CreateOIDCClient(ctx context.Context, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error)
	GetOIDCClient(ctx context.Context, id string) (*pocketid.OIDCClient, error)
	UpdateOIDCClient(ctx context.Context, id string, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error)
	UpdateOIDCClientAllowedGroups(ctx context.Context, id string, groupIDs []string) error
}

// findExistingOIDCClient checks if an OIDC client with the given ID already exists in Pocket-ID.
// Returns the existing client if found, or nil if no matching client exists.
func (r *Reconciler) FindExistingOIDCClient(ctx context.Context, apiClient pocketIDOIDCClientAPI, clientID string) (*pocketid.OIDCClient, error) {
	log := logf.FromContext(ctx)

	log.Info("Checking if OIDC client exists in Pocket-ID", "clientID", clientID)
	existingClients, err := apiClient.ListOIDCClients(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("list OIDC clients: %w", err)
	}

	// Check if ID already exists
	for _, existingClient := range existingClients {
		if existingClient.ID == clientID {
			log.Info("Found existing OIDC client with matching ID", "clientID", clientID)
			return existingClient, nil
		}
	}

	return nil, nil
}

func (r *Reconciler) reconcileOIDCClient(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient *pocketid.Client) (*pocketid.OIDCClient, error) {
	log := logf.FromContext(ctx)

	input := r.OidcClientInput(oidcClient)

	clientID := oidcClient.Status.ClientID
	if clientID == "" {
		clientID = oidcClient.Spec.ClientID
	}
	if clientID == "" {
		clientID = oidcClient.Name
	}

	var current *pocketid.OIDCClient
	var err error
	if oidcClient.Status.ClientID == "" {
		// Try to create first, then fallback to adopting if it already exists
		log.Info("Creating OIDC client in Pocket-ID", "clientID", clientID)
		current, err = apiClient.CreateOIDCClient(ctx, input)
		if err != nil {
			// Check if creation failed because client already exists
			if pocketid.IsAlreadyExistsError(err) {
				log.Info("OIDC client already exists in Pocket-ID, attempting to adopt", "clientID", clientID)
				existingClient, findErr := r.FindExistingOIDCClient(ctx, apiClient, clientID)
				if findErr != nil {
					return nil, fmt.Errorf("find existing OIDC client after create conflict: %w", findErr)
				}
				if existingClient == nil {
					return nil, fmt.Errorf("create OIDC client failed with conflict but could not find existing client: %w", err)
				}
				log.Info("Adopting existing OIDC client from Pocket-ID", "clientID", clientID)
				current = existingClient
			} else {
				return nil, fmt.Errorf("create OIDC client: %w", err)
			}
		}
	} else {
		log.Info("Updating OIDC client in Pocket-ID", "clientID", clientID)
		current, err = apiClient.UpdateOIDCClient(ctx, oidcClient.Status.ClientID, input)
		if err != nil {
			if pocketid.IsNotFoundError(err) {
				log.Info("OIDC client was deleted externally, will recreate", "clientID", oidcClient.Status.ClientID)
				if clearErr := r.clearClientStatus(ctx, oidcClient); clearErr != nil {
					return nil, fmt.Errorf("clear client status after external deletion: %w", clearErr)
				}
				return nil, nil // Requeue will recreate
			}
			return nil, fmt.Errorf("update OIDC client: %w", err)
		}
	}

	if oidcClient.Spec.AllowedUserGroups != nil {
		groupIDs, err := r.ResolveAllowedUserGroups(ctx, oidcClient)
		if err != nil {
			return current, err
		}
		if err := apiClient.UpdateOIDCClientAllowedGroups(ctx, current.ID, groupIDs); err != nil {
			return current, err
		}
		current.AllowedUserGroupIDs = groupIDs
	}

	return current, nil
}

func (r *Reconciler) OidcClientInput(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) pocketid.OIDCClientInput {
	name := oidcClient.Name

	// Determine the client ID: prefer spec.clientID, fallback to resource name
	clientID := oidcClient.Spec.ClientID
	if clientID == "" {
		clientID = oidcClient.Name
	}

	var credentials *pocketid.OIDCClientCredentials
	if len(oidcClient.Spec.FederatedIdentities) > 0 {
		identities := make([]pocketid.OIDCClientFederatedIdentity, 0, len(oidcClient.Spec.FederatedIdentities))
		for _, identity := range oidcClient.Spec.FederatedIdentities {
			identities = append(identities, pocketid.OIDCClientFederatedIdentity{
				Issuer:   identity.Issuer,
				Subject:  identity.Subject,
				Audience: identity.Audience,
				JWKS:     identity.JWKS,
			})
		}
		credentials = &pocketid.OIDCClientCredentials{FederatedIdentities: identities}
	}

	hasLogo := oidcClient.Spec.LogoURL != ""
	hasDarkLogo := oidcClient.Spec.DarkLogoURL != ""
	isGroupRestricted := len(oidcClient.Spec.AllowedUserGroups) > 0

	return pocketid.OIDCClientInput{
		ID:                       clientID,
		Name:                     name,
		CallbackURLs:             oidcClient.Spec.CallbackURLs,
		LogoutCallbackURLs:       oidcClient.Spec.LogoutCallbackURLs,
		LaunchURL:                oidcClient.Spec.LaunchURL,
		LogoURL:                  oidcClient.Spec.LogoURL,
		DarkLogoURL:              oidcClient.Spec.DarkLogoURL,
		HasLogo:                  hasLogo,
		HasDarkLogo:              hasDarkLogo,
		IsPublic:                 oidcClient.Spec.IsPublic,
		IsGroupRestricted:        isGroupRestricted,
		PKCEEnabled:              oidcClient.Spec.PKCEEnabled,
		RequiresReauthentication: oidcClient.Spec.RequiresReauthentication,
		Credentials:              credentials,
	}
}

func (r *Reconciler) ResolveAllowedUserGroups(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) ([]string, error) {
	return helpers.ResolveUserGroupReferences(ctx, r.Client, oidcClient.Spec.AllowedUserGroups, oidcClient.Namespace)
}

// clearClientStatus clears the ClientID from status, triggering recreation on next reconcile.
func (r *Reconciler) clearClientStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) error {
	base := oidcClient.DeepCopy()
	oidcClient.Status.ClientID = ""
	return r.Status().Patch(ctx, oidcClient, client.MergeFrom(base))
}

// UpdateOIDCClientStatus updates the OIDCClient status with values returned from pocket-id
func (r *Reconciler) UpdateOIDCClientStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, current *pocketid.OIDCClient) error {
	if current == nil {
		return nil
	}
	base := oidcClient.DeepCopy()
	oidcClient.Status.ClientID = current.ID
	oidcClient.Status.Name = current.Name
	oidcClient.Status.AllowedUserGroupIDs = current.AllowedUserGroupIDs
	return r.Status().Patch(ctx, oidcClient, client.MergeFrom(base))
}

func (r *Reconciler) ReconcileDelete(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (ctrl.Result, error) {
	r.EnsureClient(r.Client)
	return r.ReconcileDeleteWithPocketID(
		ctx,
		oidcClient,
		oidcClient.Status.ClientID,
		oidcClient.Spec.InstanceSelector,
		oidcClientFinalizer,
		func(ctx context.Context, client *pocketid.Client, id string) error {
			return client.DeleteOIDCClient(ctx, id)
		},
	)
}

func (r *Reconciler) ReconcileSecret(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, instance *pocketidinternalv1alpha1.PocketIDInstance, apiClient *pocketid.Client) error {
	enabled := true
	if oidcClient.Spec.Secret != nil && oidcClient.Spec.Secret.Enabled != nil {
		enabled = *oidcClient.Spec.Secret.Enabled
	}

	secretName := r.GetSecretName(oidcClient)

	if !enabled {
		// Delete the secret if it exists but is now disabled
		secret := &corev1.Secret{}
		err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: oidcClient.Namespace}, secret)
		if err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				return fmt.Errorf("failed to delete disabled secret: %w", err)
			}
		}
		return nil
	}

	keys := r.GetSecretKeys(oidcClient)

	secretData := make(map[string][]byte)

	if oidcClient.Status.ClientID != "" {
		secretData[keys.ClientID] = []byte(oidcClient.Status.ClientID)
	}

	// Include client_secret for non-public clients
	// Only regenerate if the secret doesn't exist yet or if explicitly requested via annotation
	if !oidcClient.Spec.IsPublic && oidcClient.Status.ClientID != "" {
		existingSecret := &corev1.Secret{}
		err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: oidcClient.Namespace}, existingSecret)

		shouldRegenerateSecret := false
		if err != nil {
			// Secret doesn't exist, we need to generate it
			shouldRegenerateSecret = true
		} else if _, exists := existingSecret.Data[keys.ClientSecret]; !exists {
			// Secret exists but doesn't have the client_secret key
			shouldRegenerateSecret = true
		} else if helpers.HasAnnotation(oidcClient, "pocketid.internal/regenerate-client-secret", "true") {
			// User explicitly requested regeneration via annotation
			shouldRegenerateSecret = true
		}

		if shouldRegenerateSecret {
			if apiClient == nil {
				return fmt.Errorf("apiClient is required to regenerate client secret")
			}

			clientSecret, err := apiClient.RegenerateOIDCClientSecret(ctx, oidcClient.Status.ClientID)
			if err != nil {
				return fmt.Errorf("failed to get client secret: %w", err)
			}
			secretData[keys.ClientSecret] = []byte(clientSecret)
		} else {
			// update existing secret
			secretData[keys.ClientSecret] = existingSecret.Data[keys.ClientSecret]
		}
	}

	if instance.Spec.AppURL != "" {
		secretData[keys.IssuerURL] = []byte(instance.Spec.AppURL)
	}

	if len(oidcClient.Spec.CallbackURLs) > 0 {
		callbackURLsJSON, err := json.Marshal(oidcClient.Spec.CallbackURLs)
		if err != nil {
			return fmt.Errorf("failed to marshal callback URLs: %w", err)
		}
		secretData[keys.CallbackURLs] = callbackURLsJSON
	}

	if len(oidcClient.Spec.LogoutCallbackURLs) > 0 {
		logoutCallbackURLsJSON, err := json.Marshal(oidcClient.Spec.LogoutCallbackURLs)
		if err != nil {
			return fmt.Errorf("failed to marshal logout callback URLs: %w", err)
		}
		secretData[keys.LogoutCallbackURLs] = logoutCallbackURLsJSON
	}

	if instance.Spec.AppURL != "" {
		baseURL := instance.Spec.AppURL
		secretData[keys.DiscoveryURL] = []byte(baseURL + "/.well-known/openid-configuration")
		secretData[keys.AuthorizationURL] = []byte(baseURL + "/authorize")
		secretData[keys.TokenURL] = []byte(baseURL + "/api/oidc/token")
		secretData[keys.UserinfoURL] = []byte(baseURL + "/api/oidc/userinfo")
		secretData[keys.JwksURL] = []byte(baseURL + "/.well-known/jwks.json")
		secretData[keys.EndSessionURL] = []byte(baseURL + "/api/oidc/end-session")
	}

	// Create or update the secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: oidcClient.Namespace,
			Labels:    common.ManagedByLabels(nil),
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		secret.Data = secretData
		secret.Type = corev1.SecretTypeOpaque

		if err := controllerutil.SetControllerReference(oidcClient, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create or update secret: %w", err)
	}

	return nil
}

func (r *Reconciler) GetSecretName(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) string {
	if oidcClient.Spec.Secret != nil && oidcClient.Spec.Secret.Name != "" {
		return oidcClient.Spec.Secret.Name
	}
	return oidcClient.Name + "-oidc-credentials"
}

func (r *Reconciler) GetSecretKeys(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) pocketidinternalv1alpha1.OIDCClientSecretKeys {
	defaults := pocketidinternalv1alpha1.OIDCClientSecretKeys{
		ClientID:           "client_id",
		ClientSecret:       "client_secret",
		IssuerURL:          "issuer_url",
		CallbackURLs:       "callback_urls",
		LogoutCallbackURLs: "logout_callback_urls",
		DiscoveryURL:       "discovery_url",
		AuthorizationURL:   "authorization_url",
		TokenURL:           "token_url",
		UserinfoURL:        "userinfo_url",
		JwksURL:            "jwks_url",
		EndSessionURL:      "end_session_url",
	}

	if oidcClient.Spec.Secret == nil || oidcClient.Spec.Secret.Keys == nil {
		return defaults
	}

	keys := *oidcClient.Spec.Secret.Keys

	if keys.ClientID == "" {
		keys.ClientID = defaults.ClientID
	}
	if keys.ClientSecret == "" {
		keys.ClientSecret = defaults.ClientSecret
	}
	if keys.IssuerURL == "" {
		keys.IssuerURL = defaults.IssuerURL
	}
	if keys.CallbackURLs == "" {
		keys.CallbackURLs = defaults.CallbackURLs
	}
	if keys.LogoutCallbackURLs == "" {
		keys.LogoutCallbackURLs = defaults.LogoutCallbackURLs
	}
	if keys.DiscoveryURL == "" {
		keys.DiscoveryURL = defaults.DiscoveryURL
	}
	if keys.AuthorizationURL == "" {
		keys.AuthorizationURL = defaults.AuthorizationURL
	}
	if keys.TokenURL == "" {
		keys.TokenURL = defaults.TokenURL
	}
	if keys.UserinfoURL == "" {
		keys.UserinfoURL = defaults.UserinfoURL
	}
	if keys.JwksURL == "" {
		keys.JwksURL = defaults.JwksURL
	}
	if keys.EndSessionURL == "" {
		keys.EndSessionURL = defaults.EndSessionURL
	}

	return keys
}

func (r *Reconciler) requestsForUserGroup(ctx context.Context, obj client.Object) []reconcile.Request {
	group, ok := obj.(*pocketidinternalv1alpha1.PocketIDUserGroup)
	if !ok {
		return nil
	}

	clients := &pocketidinternalv1alpha1.PocketIDOIDCClientList{}
	if err := r.List(ctx, clients, client.MatchingFields{
		OIDCClientAllowedGroupIndexKey: client.ObjectKeyFromObject(group).String(),
	}); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list OIDC clients for user group", "userGroup", client.ObjectKeyFromObject(group))
		return nil
	}

	requests := make([]reconcile.Request, 0, len(clients.Items))
	for i := range clients.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&clients.Items[i]),
		})
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDOIDCClient{}, OIDCClientAllowedGroupIndexKey, func(raw client.Object) []string {
		oidcClient, ok := raw.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
		if !ok {
			return nil
		}

		if len(oidcClient.Spec.AllowedUserGroups) == 0 {
			return nil
		}

		keys := make([]string, 0, len(oidcClient.Spec.AllowedUserGroups))
		for _, ref := range oidcClient.Spec.AllowedUserGroups {
			if ref.Name == "" {
				continue
			}
			namespace := ref.Namespace
			if namespace == "" {
				namespace = oidcClient.Namespace
			}
			keys = append(keys, fmt.Sprintf("%s/%s", namespace, ref.Name))
		}
		return keys
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDOIDCClient{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&pocketidinternalv1alpha1.PocketIDUserGroup{}, handler.EnqueueRequestsFromMapFunc(r.requestsForUserGroup)).
		Named("pocketidoidcclient").
		Complete(r)
}
