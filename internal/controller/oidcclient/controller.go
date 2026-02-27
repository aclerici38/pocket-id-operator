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
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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
	"github.com/aclerici38/pocket-id-operator/internal/metrics"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	oidcClientFinalizer          = "pocketid.internal/oidc-client-finalizer"
	UserGroupOIDCClientFinalizer = "pocketid.internal/user-group-oidc-client-finalizer"
)

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
		if client.IgnoreNotFound(err) == nil {
			metrics.DeleteReadinessGauge("PocketIDOIDCClient", req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDOIDCClient", "name", oidcClient.Name)

	if !oidcClient.DeletionTimestamp.IsZero() {
		return r.ReconcileDelete(ctx, oidcClient)
	}

	updatedFinalizers, err := r.ReconcileOIDCClientFinalizers(ctx, oidcClient)
	if err != nil {
		log.Error(err, "Failed to reconcile OIDC client finalizers")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if updatedFinalizers {
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

	apiClient, result, err := r.GetAPIClientOrRequeue(ctx, oidcClient, instance)
	if result != nil {
		return *result, err
	}

	// No client ID yet, create or adopt
	if oidcClient.Status.ClientID == "" {
		requeue, err := r.createOrAdoptOIDCClient(ctx, oidcClient, apiClient)
		if err != nil {
			log.Error(err, "Failed to create or adopt OIDC client")
			_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "ReconcileError", err.Error())
			return ctrl.Result{RequeueAfter: common.Requeue}, nil
		}
		if requeue {
			return ctrl.Result{Requeue: true}, nil
		}
		return common.ApplyResync(ctrl.Result{}), nil
	}

	// Fetch current state from Pocket ID
	current, err := apiClient.GetOIDCClient(ctx, oidcClient.Status.ClientID)
	if err != nil {
		if pocketid.IsNotFoundError(err) {
			log.Info("OIDC client was deleted externally, will recreate", "clientID", oidcClient.Status.ClientID)
			metrics.ExternalDeletions.WithLabelValues("PocketIDOIDCClient").Inc()
			if err := r.clearClientStatus(ctx, oidcClient); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "GetError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.UpdateOIDCClientStatus(ctx, oidcClient, current); err != nil {
		log.Error(err, "Failed to update OIDC client status")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.pushOIDCClientState(ctx, oidcClient, apiClient, current); err != nil {
		log.Error(err, "Failed to push OIDC client state")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.ReconcileSCIM(ctx, oidcClient, apiClient); err != nil {
		log.Error(err, "Failed to reconcile SCIM service provider")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "SCIMReconcileError", err.Error())
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

// PocketIDOIDCClientAPI defines the minimal interface needed for OIDC client operations
type PocketIDOIDCClientAPI interface {
	ListOIDCClients(ctx context.Context, search string) ([]*pocketid.OIDCClient, error)
	CreateOIDCClient(ctx context.Context, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error)
	GetOIDCClient(ctx context.Context, id string) (*pocketid.OIDCClient, error)
	UpdateOIDCClient(ctx context.Context, id string, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error)
	UpdateOIDCClientAllowedGroups(ctx context.Context, id string, groupIDs []string) error
	GetOIDCClientSCIMServiceProvider(ctx context.Context, oidcClientID string) (*pocketid.SCIMServiceProvider, error)
	CreateSCIMServiceProvider(ctx context.Context, input pocketid.SCIMServiceProviderInput) (*pocketid.SCIMServiceProvider, error)
	UpdateSCIMServiceProvider(ctx context.Context, id string, input pocketid.SCIMServiceProviderInput) (*pocketid.SCIMServiceProvider, error)
	DeleteSCIMServiceProvider(ctx context.Context, id string) error
}

// FindExistingOIDCClient checks if an OIDC client already exists in Pocket-ID.
// If specClientID is non-empty, it looks up by client ID directly.
// Otherwise, it searches by name and returns an exact match.
// Returns the existing client if found, or nil if no matching client exists.
func (r *Reconciler) FindExistingOIDCClient(ctx context.Context, apiClient PocketIDOIDCClientAPI, specClientID, name string) (*pocketid.OIDCClient, error) {
	log := logf.FromContext(ctx)

	if specClientID != "" {
		log.Info("Looking up OIDC client by ID", "clientID", specClientID)
		existingClient, err := apiClient.GetOIDCClient(ctx, specClientID)
		if err != nil {
			if pocketid.IsNotFoundError(err) {
				log.Info("OIDC client not found in Pocket-ID", "clientID", specClientID)
				return nil, nil
			}
			return nil, fmt.Errorf("get OIDC client: %w", err)
		}
		log.Info("Found existing OIDC client in Pocket-ID", "clientID", specClientID)
		return existingClient, nil
	}

	log.Info("Searching for OIDC client by name", "name", name)
	clients, err := apiClient.ListOIDCClients(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("list OIDC clients: %w", err)
	}

	for _, c := range clients {
		if c.Name == name {
			log.Info("Found existing OIDC client with matching name", "name", name, "clientID", c.ID)
			return c, nil
		}
	}

	log.Info("No OIDC client found with matching name", "name", name)
	return nil, nil
}

// createOrAdoptOIDCClient handles creation or adoption when no ID exists in the status.
// Returns (requeue, error). On success, sets the status ID and signals a requeue
// so the next reconcile loop can GET the canonical state.
func (r *Reconciler) createOrAdoptOIDCClient(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient *pocketid.Client) (bool, error) {
	log := logf.FromContext(ctx)
	input := r.OidcClientInput(oidcClient, nil)

	// Aggregate all allowed groups
	groupIDs, err := r.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		return false, fmt.Errorf("aggregate allowed user groups: %w", err)
	}
	input.IsGroupRestricted = len(groupIDs) > 0

	resourceID := oidcClient.Spec.ClientID
	if resourceID == "" {
		resourceID = "(auto-generated)"
	}

	// When spec.clientID is not set, search by name first to adopt
	if oidcClient.Spec.ClientID == "" {
		log.Info("No clientID specified, searching for existing OIDC client by name", "name", oidcClient.Name)
		existing, err := r.FindExistingOIDCClient(ctx, apiClient, "", oidcClient.Name)
		if err != nil {
			return false, fmt.Errorf("search for existing OIDC client by name: %w", err)
		}
		if existing != nil {
			log.Info("Found existing OIDC client by name, adopting", "name", oidcClient.Name, "clientID", existing.ID)
			metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", "adopted").Inc()
			if err := r.setClientID(ctx, oidcClient, existing.ID); err != nil {
				return false, err
			}
			return true, nil
		}
		log.Info("No existing OIDC client found by name, creating new", "name", oidcClient.Name)
	}

	result, err := common.CreateOrAdopt(ctx, common.CreateOrAdoptConfig[*pocketid.OIDCClient]{
		ResourceKind: "OIDC client",
		ResourceID:   resourceID,
		Create: func() (*pocketid.OIDCClient, error) {
			return apiClient.CreateOIDCClient(ctx, input)
		},
		FindExisting: func() (*pocketid.OIDCClient, error) {
			return r.FindExistingOIDCClient(ctx, apiClient, oidcClient.Spec.ClientID, oidcClient.Name)
		},
		IsNil: func(c *pocketid.OIDCClient) bool {
			return c == nil
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
	metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", operation).Inc()

	if err := r.setClientID(ctx, oidcClient, result.Resource.ID); err != nil {
		return false, err
	}
	return true, nil
}

// pushOIDCClientState compares the desired state from the CR spec against the current
// state fetched from Pocket ID and only pushes updates if they differ.
func (r *Reconciler) pushOIDCClientState(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient *pocketid.Client, current *pocketid.OIDCClient) error {
	log := logf.FromContext(ctx)

	// Aggregate allowed groups before building input so IsGroupRestricted is correct
	groupIDs, err := r.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		return fmt.Errorf("aggregate allowed user groups: %w", err)
	}

	desired := r.OidcClientInput(oidcClient, current)
	desired.IsGroupRestricted = len(groupIDs) > 0

	currentInput := current.ToInput()
	clientChanged := !desired.Equal(currentInput)
	hasCredentials := desired.Credentials != nil
	groupsChanged := !pocketid.SortedEqual(groupIDs, current.AllowedUserGroupIDs)

	// Clear any existing credentials if the CR doesn't specify any when adopting
	firstReconcile := !helpers.IsResourceReady(oidcClient.Status.Conditions)
	if firstReconcile && !hasCredentials {
		desired.Credentials = &pocketid.OIDCClientCredentials{FederatedIdentities: []pocketid.OIDCClientFederatedIdentity{}}
	}
	shouldPushCredentials := hasCredentials || firstReconcile

	if !clientChanged && !shouldPushCredentials && !groupsChanged {
		log.V(2).Info("OIDC client state is in sync, skipping update")
		return nil
	}

	// Always push when credentials are present since they
	// are write-only and cannot be compared against the fetched state.
	if clientChanged || shouldPushCredentials {
		if _, err := apiClient.UpdateOIDCClient(ctx, oidcClient.Status.ClientID, desired); err != nil {
			return fmt.Errorf("update OIDC client: %w", err)
		}
	}

	if groupsChanged {
		if groupIDs == nil {
			groupIDs = []string{}
		}
		if err := apiClient.UpdateOIDCClientAllowedGroups(ctx, oidcClient.Status.ClientID, groupIDs); err != nil {
			return err
		}
	}

	metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", "updated").Inc()
	return nil
}

// aggregateAllowedUserGroupIDs returns the union of:
// 1. Direct refs from spec.allowedUserGroups
// 2. UserGroups whose spec.allowedOIDCClients references this client
// Returns nil if neither source contributes.
func (r *Reconciler) aggregateAllowedUserGroupIDs(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) ([]string, error) {
	// Find UserGroups whose spec.allowedOIDCClients references this client
	clientKey := fmt.Sprintf("%s/%s", oidcClient.Namespace, oidcClient.Name)
	userGroups := &pocketidinternalv1alpha1.PocketIDUserGroupList{}
	if err := r.List(ctx, userGroups, client.MatchingFields{
		common.UserGroupAllowedOIDCClientIndexKey: clientKey,
	}); err != nil {
		return nil, fmt.Errorf("list user groups referencing OIDC client: %w", err)
	}

	hasDirectRefs := len(oidcClient.Spec.AllowedUserGroups) > 0
	hasReverseRefs := len(userGroups.Items) > 0

	if !hasDirectRefs && !hasReverseRefs {
		return nil, nil
	}

	groupIDSet := make(map[string]struct{})

	if hasDirectRefs {
		directIDs, err := helpers.ResolveUserGroupReferences(ctx, r.Client, oidcClient.Spec.AllowedUserGroups, oidcClient.Namespace)
		if err != nil {
			return nil, fmt.Errorf("resolve allowed user groups: %w", err)
		}
		for _, id := range directIDs {
			groupIDSet[id] = struct{}{}
		}
	}

	// Extract status.GroupID from ready UserGroups that reference this client
	for _, group := range userGroups.Items {
		if helpers.IsResourceReady(group.Status.Conditions) && group.Status.GroupID != "" {
			groupIDSet[group.Status.GroupID] = struct{}{}
		}
	}

	groupIDs := make([]string, 0, len(groupIDSet))
	for id := range groupIDSet {
		groupIDs = append(groupIDs, id)
	}
	sort.Strings(groupIDs)
	return groupIDs, nil
}

// setClientID persists only the client ID to status.
func (r *Reconciler) setClientID(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, id string) error {
	base := oidcClient.DeepCopy()
	oidcClient.Status.ClientID = id
	return r.Status().Patch(ctx, oidcClient, client.MergeFrom(base))
}

// OidcClientInput builds an OIDCClientInput from the CR spec.
// When current is provided, it is used as the fallback for callback URLs not set in the spec
func (r *Reconciler) OidcClientInput(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, current *pocketid.OIDCClient) pocketid.OIDCClientInput {
	name := oidcClient.Name

	// Only set client ID if in spec
	var clientID *string
	if oidcClient.Spec.ClientID != "" {
		clientID = &oidcClient.Spec.ClientID
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

	// When callback URLs are not in the spec, preserve the server-side values.
	// This prevents overwriting pocket-id's TOFU auto-detected URLs.
	callbackURLs := oidcClient.Spec.CallbackURLs
	if len(callbackURLs) == 0 && current != nil {
		callbackURLs = current.CallbackURLs
	}
	logoutCallbackURLs := oidcClient.Spec.LogoutCallbackURLs
	if len(logoutCallbackURLs) == 0 && current != nil {
		logoutCallbackURLs = current.LogoutCallbackURLs
	}

	return pocketid.OIDCClientInput{
		ID:                       clientID,
		Name:                     name,
		CallbackURLs:             callbackURLs,
		LogoutCallbackURLs:       logoutCallbackURLs,
		LaunchURL:                oidcClient.Spec.LaunchURL,
		LogoURL:                  oidcClient.Spec.LogoURL,
		DarkLogoURL:              oidcClient.Spec.DarkLogoURL,
		HasLogo:                  hasLogo,
		HasDarkLogo:              hasDarkLogo,
		IsPublic:                 oidcClient.Spec.IsPublic,
		IsGroupRestricted:        len(oidcClient.Spec.AllowedUserGroups) > 0,
		PKCEEnabled:              oidcClient.Spec.PKCEEnabled,
		RequiresReauthentication: oidcClient.Spec.RequiresReauthentication,
		Credentials:              credentials,
	}
}

// clearClientStatus clears the ClientID from status, triggering recreation on next reconcile.
func (r *Reconciler) clearClientStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) error {
	return r.ClearStatusField(ctx, oidcClient, func() {
		oidcClient.Status.ClientID = ""
	})
}

// ReconcileSCIM ensures the SCIM service provider in pocket-id matches the desired spec.
func (r *Reconciler) ReconcileSCIM(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient PocketIDOIDCClientAPI) error {
	log := logf.FromContext(ctx)

	// If SCIM is not desired, delete any existing provider
	if oidcClient.Spec.SCIM == nil {
		if oidcClient.Status.SCIMProviderID != "" {
			log.Info("SCIM removed from spec, deleting service provider", "scimProviderID", oidcClient.Status.SCIMProviderID)
			if err := apiClient.DeleteSCIMServiceProvider(ctx, oidcClient.Status.SCIMProviderID); err != nil {
				if !pocketid.IsNotFoundError(err) {
					return fmt.Errorf("delete SCIM service provider: %w", err)
				}
			}
			return r.clearSCIMProviderID(ctx, oidcClient)
		}
		// Clean up stale providers only on first reconcile.
		if !helpers.IsResourceReady(oidcClient.Status.Conditions) {
			existing, err := apiClient.GetOIDCClientSCIMServiceProvider(ctx, oidcClient.Status.ClientID)
			if err != nil && !pocketid.IsNotFoundError(err) {
				return fmt.Errorf("get SCIM service provider: %w", err)
			}
			if existing != nil {
				log.Info("Deleting untracked SCIM service provider found on adopted OIDC client", "scimProviderID", existing.ID)
				if err := apiClient.DeleteSCIMServiceProvider(ctx, existing.ID); err != nil && !pocketid.IsNotFoundError(err) {
					return fmt.Errorf("delete untracked SCIM service provider: %w", err)
				}
			}
		}
		return nil
	}

	token, err := helpers.ResolveSecretKeySelector(ctx, r.Client, r.APIReader, oidcClient.Namespace, oidcClient.Spec.SCIM.TokenSecretRef)
	if err != nil {
		return fmt.Errorf("resolve SCIM token secret: %w", err)
	}

	input := pocketid.SCIMServiceProviderInput{
		Endpoint:     oidcClient.Spec.SCIM.Endpoint,
		OIDCClientID: oidcClient.Status.ClientID,
		Token:        token,
	}

	if oidcClient.Status.SCIMProviderID == "" {
		existing, err := apiClient.GetOIDCClientSCIMServiceProvider(ctx, oidcClient.Status.ClientID)
		if err != nil {
			return fmt.Errorf("get SCIM service provider: %w", err)
		}
		if existing != nil {
			log.Info("Adopting existing SCIM service provider", "scimProviderID", existing.ID)
			if _, err := apiClient.UpdateSCIMServiceProvider(ctx, existing.ID, input); err != nil {
				return fmt.Errorf("update adopted SCIM service provider: %w", err)
			}
			return r.setSCIMProviderID(ctx, oidcClient, existing.ID)
		}
		log.Info("Creating SCIM service provider", "endpoint", input.Endpoint)
		created, err := apiClient.CreateSCIMServiceProvider(ctx, input)
		if err != nil {
			return fmt.Errorf("create SCIM service provider: %w", err)
		}
		return r.setSCIMProviderID(ctx, oidcClient, created.ID)
	}

	// Fetch current state to detect changes and handle external deletion.
	// GetOIDCClientSCIMServiceProvider returns nil, nil on 404.
	current, err := apiClient.GetOIDCClientSCIMServiceProvider(ctx, oidcClient.Status.ClientID)
	if err != nil {
		return fmt.Errorf("get SCIM service provider: %w", err)
	}
	if current == nil {
		staleID := oidcClient.Status.SCIMProviderID
		log.Info("SCIM service provider not found externally, clearing status for recreation", "scimProviderID", staleID)
		if err := r.clearSCIMProviderID(ctx, oidcClient); err != nil {
			return err
		}
		return fmt.Errorf("SCIM service provider %s not found, will recreate on next reconcile", staleID)
	}

	// Token is write-only and cannot be read back from the API, so always push
	// when one is configured. Otherwise only update if the endpoint changed.
	hasToken := token != ""
	if !hasToken && current.Endpoint == input.Endpoint {
		log.V(2).Info("SCIM service provider is in sync, skipping update")
		return nil
	}

	if _, err := apiClient.UpdateSCIMServiceProvider(ctx, current.ID, input); err != nil {
		return fmt.Errorf("update SCIM service provider: %w", err)
	}
	if current.ID != oidcClient.Status.SCIMProviderID {
		return r.setSCIMProviderID(ctx, oidcClient, current.ID)
	}
	return nil
}

func (r *Reconciler) setSCIMProviderID(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, id string) error {
	base := oidcClient.DeepCopy()
	oidcClient.Status.SCIMProviderID = id
	return r.Status().Patch(ctx, oidcClient, client.MergeFrom(base))
}

func (r *Reconciler) clearSCIMProviderID(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) error {
	return r.ClearStatusField(ctx, oidcClient, func() {
		oidcClient.Status.SCIMProviderID = ""
	})
}

// UpdateOIDCClientStatus updates the OIDCClient status with values returned from pocket-id
func (r *Reconciler) UpdateOIDCClientStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, current *pocketid.OIDCClient) error {
	if current == nil {
		return nil
	}
	base := oidcClient.DeepCopy()
	oidcClient.Status.ClientID = current.ID
	oidcClient.Status.Name = current.Name
	oidcClient.Status.CallbackURLs = current.CallbackURLs
	oidcClient.Status.LogoutCallbackURLs = current.LogoutCallbackURLs
	oidcClient.Status.AllowedUserGroupIDs = current.AllowedUserGroupIDs
	return r.Status().Patch(ctx, oidcClient, client.MergeFrom(base))
}

func (r *Reconciler) ReconcileOIDCClientFinalizers(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (bool, error) {
	referencedByUserGroup, err := r.isOIDCClientReferencedByUserGroup(ctx, oidcClient)
	if err != nil {
		return false, err
	}

	updates := []helpers.FinalizerUpdate{
		{Name: oidcClientFinalizer, ShouldAdd: true},
		{Name: UserGroupOIDCClientFinalizer, ShouldAdd: referencedByUserGroup},
	}

	return helpers.ReconcileFinalizers(ctx, r.Client, oidcClient, updates)
}

func (r *Reconciler) isOIDCClientReferencedByUserGroup(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (bool, error) {
	clientKey := fmt.Sprintf("%s/%s", oidcClient.Namespace, oidcClient.Name)
	return common.IsReferencedByList(
		ctx,
		r.Client,
		common.UserGroupAllowedOIDCClientIndexKey,
		clientKey,
		&pocketidinternalv1alpha1.PocketIDUserGroupList{},
		func(item client.Object) bool {
			group := item.(*pocketidinternalv1alpha1.PocketIDUserGroup)
			return userGroupAllowsOIDCClient(group, oidcClient.Namespace, oidcClient.Name)
		},
	)
}

func userGroupAllowsOIDCClient(group *pocketidinternalv1alpha1.PocketIDUserGroup, clientNamespace, clientName string) bool {
	for _, ref := range group.Spec.AllowedOIDCClients {
		if ref.Name == "" {
			continue
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = group.Namespace
		}
		if ref.Name == clientName && namespace == clientNamespace {
			return true
		}
	}
	return false
}

func (r *Reconciler) ReconcileDelete(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (ctrl.Result, error) {
	r.EnsureClient(r.Client)
	referencedByUserGroup, err := r.isOIDCClientReferencedByUserGroup(ctx, oidcClient)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to check PocketIDUserGroup references")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if referencedByUserGroup {
		logf.FromContext(ctx).Info("OIDC client is referenced by PocketIDUserGroup, blocking deletion", "oidcClient", oidcClient.Name)
		if _, err := helpers.EnsureFinalizer(ctx, r.Client, oidcClient, UserGroupOIDCClientFinalizer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Remove UserGroupOIDCClientFinalizer if not referenced
	if controllerutil.ContainsFinalizer(oidcClient, UserGroupOIDCClientFinalizer) {
		if err := helpers.RemoveFinalizers(ctx, r.Client, oidcClient, UserGroupOIDCClientFinalizer); err != nil {
			if errors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// SCIM service providers are cascade-deleted by pocket-id when the
	// OIDC client is removed, so no explicit SCIM cleanup is needed here.
	result, err := r.ReconcileDeleteWithPocketID(
		ctx,
		oidcClient,
		oidcClient.Status.ClientID,
		oidcClient.Spec.InstanceSelector,
		oidcClientFinalizer,
		func(ctx context.Context, apiClient *pocketid.Client, id string) error {
			if err := apiClient.DeleteOIDCClient(ctx, id); err != nil {
				return err
			}
			metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", "deleted").Inc()
			return nil
		},
	)
	if err == nil && result == (ctrl.Result{}) {
		metrics.DeleteReadinessGauge("PocketIDOIDCClient", oidcClient.Namespace, oidcClient.Name)
	}
	return result, err
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

	seen := make(map[client.ObjectKey]struct{})
	var requests []reconcile.Request

	// Forward: OIDCClients whose spec.allowedUserGroups references this group
	clients := &pocketidinternalv1alpha1.PocketIDOIDCClientList{}
	if err := r.List(ctx, clients, client.MatchingFields{
		common.OIDCClientAllowedGroupIndexKey: client.ObjectKeyFromObject(group).String(),
	}); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list OIDC clients for user group", "userGroup", client.ObjectKeyFromObject(group))
		return nil
	}
	for i := range clients.Items {
		key := client.ObjectKeyFromObject(&clients.Items[i])
		seen[key] = struct{}{}
		requests = append(requests, reconcile.Request{NamespacedName: key})
	}

	// Reverse: OIDCClients referenced in this UserGroup's spec.allowedOIDCClients
	for _, ref := range group.Spec.AllowedOIDCClients {
		if ref.Name == "" {
			continue
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = group.Namespace
		}
		key := client.ObjectKey{Namespace: namespace, Name: ref.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			requests = append(requests, reconcile.Request{NamespacedName: key})
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDOIDCClient{}, common.OIDCClientAllowedGroupIndexKey, func(raw client.Object) []string {
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
		Watches(
			&pocketidinternalv1alpha1.PocketIDUserGroup{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForUserGroup),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("pocketidoidcclient").
		Complete(r)
}
