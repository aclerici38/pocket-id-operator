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
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
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
	lastRotatedAtAnnotation      = "pocketid.internal/last-rotated-at"
	// lastScheduledRotationAtAnnotation records only scheduled rotations and is the sole driver
	// of the instance-wide min-spacing aggregate. Manual rotations update lastRotatedAtAnnotation
	// (which gates the per-client interval) but deliberately leave this one untouched, so an
	// out-of-band rotation never perturbs the instance's scheduled-rotation spacing.
	lastScheduledRotationAtAnnotation = "pocketid.internal/last-scheduled-rotation-at"
	// regenerateClientSecretAnnotation is set by a user to force an immediate secret
	// rotation, bypassing the scheduled-rotation gates.
	regenerateClientSecretAnnotation = "pocketid.internal/regenerate-client-secret"

	defaultLogoTemplate     = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/{{name}}.png"
	defaultDarkLogoTemplate = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/{{name}}-dark.png"
)

// Reconciler reconciles a PocketIDOIDCClient object
type Reconciler struct {
	client.Client
	common.BaseReconciler
	APIReader client.Reader
	Scheme    *runtime.Scheme

	// DefaultAutoGenerateLogos is the default for logo.autoGenerate when not set per-client (from AUTOGENERATE_LOGOS env var).
	DefaultAutoGenerateLogos bool
	// IsLogoReachable checks if a logo URL is reachable. Defaults to isURLReachable.
	IsLogoReachable func(string) bool
	// DefaultLogoTemplate is the default URL template for light logos (from DEFAULT_LOGO_URL env var).
	DefaultLogoTemplate string
	// DefaultDarkLogoTemplate is the default URL template for dark logos (from DEFAULT_DARK_LOGO_URL env var).
	DefaultDarkLogoTemplate string

	// skipUpdate gates the update phase of reconciliation
	// and just fetches the state
	skipUpdate map[types.NamespacedName]bool

	// pendingInitialMint marks clients created (not adopted) by the operator whose client
	// secret has not yet been stored. It lets storeClientSecret=false permit the one-time
	// initial mint for brand-new clients while never regenerating pre-existing credentials.
	pendingInitialMint map[types.NamespacedName]bool
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidapis,verbs=get;list;watch
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
			metrics.DeleteOIDCClientAllowedGroupCount(req.Namespace, req.Name)
			metrics.DeleteOIDCClientPKCESupported(req.Namespace, req.Name)
			metrics.DeleteOIDCClientRotationMetrics(req.Namespace, req.Name)
			delete(r.pendingInitialMint, req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("Reconciling PocketIDOIDCClient", "name", oidcClient.Name)

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

	// Skip the push if this reconcile was triggered for post-update status refresh
	key := client.ObjectKeyFromObject(oidcClient)
	if r.skipUpdate[key] {
		delete(r.skipUpdate, key)
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionTrue, "Reconciled", "OIDC client is in sync")
		return common.ApplyResync(ctrl.Result{}), nil
	}

	updated, err := r.pushOIDCClientState(ctx, oidcClient, apiClient, current)
	if err != nil {
		log.Error(err, "Failed to push OIDC client state")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.ReconcileSCIM(ctx, oidcClient, apiClient); err != nil {
		log.Error(err, "Failed to reconcile SCIM service provider")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "SCIMReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.ReconcileAPIAccess(ctx, oidcClient, apiClient); err != nil {
		log.Error(err, "Failed to reconcile API access")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "APIAccessReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient); err != nil {
		log.Error(err, "Failed to reconcile OIDC client secret")
		_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "SecretReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if removed, err := helpers.CheckAndRemoveAnnotation(ctx, r.Client, oidcClient, regenerateClientSecretAnnotation, "true"); err != nil {
		log.Error(err, "Failed to remove regenerate-client-secret annotation")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	} else if removed {
		// The annotation is removed even when it was ignored (storeClientSecret false),
		// so it cannot fire unexpectedly if the flag is later flipped back to true.
		if storeClientSecret(oidcClient) {
			log.Info("Removed regenerate-client-secret annotation after secret regeneration")
		} else {
			log.Info("Removed regenerate-client-secret annotation without regenerating: secret.storeClientSecret is false")
		}
	}

	_ = r.SetReadyCondition(ctx, oidcClient, metav1.ConditionTrue, "Reconciled", "OIDC client is in sync")

	if updated {
		return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
	}

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

	logoURL, darkLogoURL, err := r.resolveAndUpdateLogoStatus(ctx, oidcClient)
	if err != nil {
		return false, fmt.Errorf("resolve logos: %w", err)
	}

	input := r.OidcClientInput(oidcClient, nil, logoURL, darkLogoURL)

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

	name := oidcClientName(oidcClient)

	// When spec.clientID is not set, search by name first to adopt
	if oidcClient.Spec.ClientID == "" {
		log.Info("No clientID specified, searching for existing OIDC client by name", "name", name)
		existing, err := r.FindExistingOIDCClient(ctx, apiClient, "", name)
		if err != nil {
			return false, fmt.Errorf("search for existing OIDC client by name: %w", err)
		}
		if existing != nil {
			log.Info("Found existing OIDC client by name, adopting", "name", name, "clientID", existing.ID)
			metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", "adopted").Inc()
			if err := r.setClientID(ctx, oidcClient, existing.ID); err != nil {
				return false, err
			}
			return true, nil
		}
		log.Info("No existing OIDC client found by name, creating new", "name", name)
	}

	result, err := common.CreateOrAdopt(ctx, common.CreateOrAdoptConfig[*pocketid.OIDCClient]{
		ResourceKind: "OIDC client",
		ResourceID:   resourceID,
		Create: func() (*pocketid.OIDCClient, error) {
			return apiClient.CreateOIDCClient(ctx, input)
		},
		FindExisting: func() (*pocketid.OIDCClient, error) {
			return r.FindExistingOIDCClient(ctx, apiClient, oidcClient.Spec.ClientID, name)
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
		// A brand-new client has no externally-managed secret to protect, so the initial
		// mint is allowed even when storeClientSecret is false.
		if r.pendingInitialMint == nil {
			r.pendingInitialMint = make(map[types.NamespacedName]bool)
		}
		r.pendingInitialMint[client.ObjectKeyFromObject(oidcClient)] = true
	}
	metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", operation).Inc()

	if err := r.setClientID(ctx, oidcClient, result.Resource.ID); err != nil {
		return false, err
	}
	return true, nil
}

// pushOIDCClientState compares the desired state from the CR spec against the current
// state fetched from Pocket ID and only pushes updates if they differ.
func (r *Reconciler) pushOIDCClientState(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient *pocketid.Client, current *pocketid.OIDCClient) (bool, error) {
	log := logf.FromContext(ctx)

	// Aggregate allowed groups before building input so IsGroupRestricted is correct
	groupIDs, err := r.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		return false, fmt.Errorf("aggregate allowed user groups: %w", err)
	}
	metrics.OIDCClientAllowedGroupCount.WithLabelValues(oidcClient.Namespace, oidcClient.Name).Set(float64(len(groupIDs)))

	// Resolve logos, update CR status, and get reachable URLs for the API payload
	logoURL, darkLogoURL, err := r.resolveAndUpdateLogoStatus(ctx, oidcClient)
	if err != nil {
		return false, fmt.Errorf("resolve logos: %w", err)
	}

	desired := r.OidcClientInput(oidcClient, current, logoURL, darkLogoURL)
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
		log.V(1).Info("OIDC client state is in sync, skipping update")
		return false, nil
	}

	log.Info("Updating OIDC client", "name", oidcClient.Name)

	// Always push when credentials are present since they
	// are write-only and cannot be compared against the fetched state.
	if clientChanged || shouldPushCredentials {
		if _, err := apiClient.UpdateOIDCClient(ctx, oidcClient.Status.ClientID, desired); err != nil {
			return false, fmt.Errorf("update OIDC client: %w", err)
		}
	}

	if groupsChanged {
		if groupIDs == nil {
			groupIDs = []string{}
		}
		if err := apiClient.UpdateOIDCClientAllowedGroups(ctx, oidcClient.Status.ClientID, groupIDs); err != nil {
			return false, err
		}
	}

	metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", "updated").Inc()

	if r.skipUpdate == nil {
		r.skipUpdate = make(map[types.NamespacedName]bool)
	}
	r.skipUpdate[client.ObjectKeyFromObject(oidcClient)] = true

	return true, nil
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

// oidcClientName returns the Pocket-ID name for the given OIDC client:
// spec.name if set, otherwise metadata.name.
func oidcClientName(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) string {
	if oidcClient.Spec.Name != "" {
		return oidcClient.Spec.Name
	}
	return oidcClient.Name
}

// OidcClientInput builds an OIDCClientInput from the CR spec.
// logoURL/darkLogoURL should only contain reachable URLs to send to Pocket-ID.
// When current is provided, it is used as the fallback for callback URLs not set in the spec.
func (r *Reconciler) OidcClientInput(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, current *pocketid.OIDCClient, logoURL, darkLogoURL string) pocketid.OIDCClientInput {
	name := oidcClientName(oidcClient)

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

	// When callback URLs are not in the spec, preserve the server-side values
	// so out-of-band changes made in pocket-id are not overwritten.
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
		Description:              oidcClient.Spec.Description,
		CallbackURLs:             callbackURLs,
		LogoutCallbackURLs:       logoutCallbackURLs,
		LaunchURL:                oidcClient.Spec.LaunchURL,
		LogoURL:                  logoURL,
		DarkLogoURL:              darkLogoURL,
		HasLogo:                  logoURL != "",
		HasDarkLogo:              darkLogoURL != "",
		IsPublic:                 oidcClient.Spec.IsPublic,
		IsGroupRestricted:        len(oidcClient.Spec.AllowedUserGroups) > 0,
		PKCEEnabled:              oidcClient.Spec.PKCEEnabled,
		RequiresReauthentication: oidcClient.Spec.RequiresReauthentication,
		SkipConsent:              oidcClient.Spec.SkipConsent,
		Credentials:              credentials,
	}
}

// resolveAndUpdateLogoStatus resolves logo URLs, checks reachability, updates the CR status,
// and returns the reachable URLs to include in the Pocket-ID API payload.
func (r *Reconciler) resolveAndUpdateLogoStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (logoURL, darkLogoURL string, err error) {
	resolvedLogo, logoReachable, resolvedDark, darkReachable := r.resolveLogoURLs(ctx, oidcClient, oidcClient.Name)

	if err := r.updateLogoStatus(ctx, oidcClient, resolvedLogo, logoReachable, resolvedDark, darkReachable); err != nil {
		return "", "", err
	}

	if logoReachable {
		logoURL = resolvedLogo
	}
	if darkReachable {
		darkLogoURL = resolvedDark
	}
	return logoURL, darkLogoURL, nil
}

// resolveLogoURLs determines the final logo URLs for the OIDC client.
// The name used for {{name}} substitution is metadata.name, overridable via logo.nameOverride.
// Precedence: deprecated spec.logoUrl/darkLogoUrl > logo struct template resolution > empty.
// Always returns the resolved URL. Reachability is checked only when the URL changed or was
// previously unreachable; otherwise the cached reachability from status is reused.
func (r *Reconciler) resolveLogoURLs(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, name string) (logoURL string, logoReachable bool, darkLogoURL string, darkLogoReachable bool) {
	// Deprecated fields take precedence for backwards compatibility
	if oidcClient.Spec.LogoURL != "" || oidcClient.Spec.DarkLogoURL != "" {
		return oidcClient.Spec.LogoURL, oidcClient.Spec.LogoURL != "", oidcClient.Spec.DarkLogoURL, oidcClient.Spec.DarkLogoURL != ""
	}

	logo := oidcClient.Spec.Logo

	autoGenerate := r.DefaultAutoGenerateLogos
	if logo != nil && logo.AutoGenerate != nil {
		autoGenerate = *logo.AutoGenerate
	}

	logoName := name
	if logo != nil && logo.NameOverride != "" {
		logoName = logo.NameOverride
	}

	// Explicit per-client templates are always used regardless of autoGenerate.
	// autoGenerate only controls whether default templates fill in when no
	// explicit URL is set, independently for light and dark logos.
	var logoTemplate, darkLogoTemplate string
	if logo != nil {
		logoTemplate = logo.LogoURL
		darkLogoTemplate = logo.DarkLogoURL
	}
	if logoTemplate == "" && autoGenerate {
		if r.DefaultLogoTemplate != "" {
			logoTemplate = r.DefaultLogoTemplate
		} else {
			logoTemplate = defaultLogoTemplate
		}
	}
	if darkLogoTemplate == "" && autoGenerate {
		if r.DefaultDarkLogoTemplate != "" {
			darkLogoTemplate = r.DefaultDarkLogoTemplate
		} else {
			darkLogoTemplate = defaultDarkLogoTemplate
		}
	}

	log := logf.FromContext(ctx)
	checkReachable := r.IsLogoReachable
	if checkReachable == nil {
		checkReachable = isURLReachable
	}

	status := oidcClient.Status

	if logoTemplate != "" {
		logoURL = strings.ReplaceAll(logoTemplate, "{{name}}", logoName)
		if status.LogoReachable != nil && *status.LogoReachable && logoURL == status.LogoURL {
			logoReachable = true
		} else if checkReachable(logoURL) {
			logoReachable = true
		} else {
			log.V(1).Info("Logo URL is not reachable", "url", logoURL)
		}
	}
	if darkLogoTemplate != "" {
		darkLogoURL = strings.ReplaceAll(darkLogoTemplate, "{{name}}", logoName)
		if status.DarkLogoReachable != nil && *status.DarkLogoReachable && darkLogoURL == status.DarkLogoURL {
			darkLogoReachable = true
		} else if checkReachable(darkLogoURL) {
			darkLogoReachable = true
		} else {
			log.V(1).Info("Dark logo URL is not reachable", "url", darkLogoURL)
		}
	}

	return logoURL, logoReachable, darkLogoURL, darkLogoReachable
}

// isURLReachable performs a HEAD request to check if a URL is reachable (2xx status).
func isURLReachable(url string) bool {
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Head(url)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
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
		log.V(1).Info("SCIM service provider is in sync, skipping update")
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

// updateLogoStatus persists the resolved logo URLs and their reachability state to the CR status.
func (r *Reconciler) updateLogoStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, logoURL string, logoReachable bool, darkLogoURL string, darkLogoReachable bool) error {
	base := oidcClient.DeepCopy()
	oidcClient.Status.LogoURL = logoURL
	oidcClient.Status.LogoReachable = &logoReachable
	oidcClient.Status.DarkLogoURL = darkLogoURL
	oidcClient.Status.DarkLogoReachable = &darkLogoReachable
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
	oidcClient.Status.CallbackURLs = current.CallbackURLs
	oidcClient.Status.LogoutCallbackURLs = current.LogoutCallbackURLs
	oidcClient.Status.AllowedUserGroupIDs = current.AllowedUserGroupIDs
	// Pocket-ID keeps PKCESupported set even after PKCE is enabled, so gate on
	// PKCEEnabled to mean "PKCE can be enabled". Only surface the status field when
	// the recommendation is active.
	pkceRecommended := current.PKCESupported && !current.PKCEEnabled
	if pkceRecommended {
		oidcClient.Status.PKCESupported = &pkceRecommended
	} else {
		oidcClient.Status.PKCESupported = nil
	}
	metrics.SetOIDCClientPKCESupported(oidcClient.Namespace, oidcClient.Name, pkceRecommended)
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
		metrics.DeleteOIDCClientAllowedGroupCount(oidcClient.Namespace, oidcClient.Name)
		metrics.DeleteOIDCClientPKCESupported(oidcClient.Namespace, oidcClient.Name)
		metrics.DeleteOIDCClientRotationMetrics(oidcClient.Namespace, oidcClient.Name)
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
		// Delete the secret if it exists but is now disabled. Only delete a
		// secret the operator manages: a user may point spec.secret.name at a
		// secret they own, and we must never delete a resource we don't manage.
		secret := &corev1.Secret{}
		err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: oidcClient.Namespace}, secret)
		if err == nil {
			if !common.IsManagedByOperator(secret) {
				return nil
			}
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

	// Include client_secret for non-public clients that store it.
	// Only regenerate if the secret doesn't exist yet or if explicitly requested via annotation.
	var rotatedAt *metav1.Time
	var scheduledRotation bool
	if !oidcClient.Spec.IsPublic && oidcClient.Status.ClientID != "" {
		var err error
		rotatedAt, scheduledRotation, err = r.reconcileClientSecretData(ctx, oidcClient, instance, apiClient, secretName, keys, secretData)
		if err != nil {
			return err
		}
	}

	appURL := instance.EffectiveAppURL()
	if appURL != "" {
		secretData[keys.IssuerURL] = []byte(appURL)
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

	if appURL != "" {
		baseURL := appURL
		secretData[keys.DiscoveryURL] = []byte(baseURL + "/.well-known/openid-configuration")
		secretData[keys.AuthorizationURL] = []byte(baseURL + "/authorize")
		secretData[keys.TokenURL] = []byte(baseURL + "/api/oidc/token")
		secretData[keys.UserinfoURL] = []byte(baseURL + "/api/oidc/userinfo")
		secretData[keys.JwksURL] = []byte(baseURL + "/.well-known/jwks.json")
		secretData[keys.EndSessionURL] = []byte(baseURL + "/api/oidc/end-session")
	}

	secretLabels := r.GetSecretLabels(oidcClient)
	secretAnnotations := r.GetSecretAnnotations(oidcClient)

	// Create or update the secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: oidcClient.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Labels == nil {
			secret.Labels = make(map[string]string, len(secretLabels))
		}
		for k, v := range secretLabels {
			secret.Labels[k] = v
		}

		// Add user annotations
		reconcileSecretAnnotations(secret, secretAnnotations)

		secret.Data = secretData
		secret.Type = corev1.SecretTypeOpaque

		if rotatedAt != nil {
			if secret.Annotations == nil {
				secret.Annotations = make(map[string]string)
			}
			secret.Annotations[lastRotatedAtAnnotation] = rotatedAt.UTC().Format(time.RFC3339)
			// Only scheduled rotations advance the instance-wide aggregate.
			if scheduledRotation {
				secret.Annotations[lastScheduledRotationAtAnnotation] = rotatedAt.UTC().Format(time.RFC3339)
			}
		}

		if err := controllerutil.SetControllerReference(oidcClient, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create or update secret: %w", err)
	}

	delete(r.pendingInitialMint, client.ObjectKeyFromObject(oidcClient))

	r.applyRotationStatus(ctx, oidcClient, rotatedAt)

	// Set instance rotation status each reconcile to self-correct
	// when secret write succeeds but instance.status write fails.
	// rotatedThisReconcile distinguishes the expected advance that follows a rotation we just
	// performed from a genuine lost-write recovered on a later reconcile.
	rotatedThisReconcile := rotatedAt != nil && scheduledRotation
	if err := r.advanceInstanceRotationStatus(ctx, instance, secret, rotatedThisReconcile); err != nil {
		return fmt.Errorf("failed to advance instance rotation status: %w", err)
	}

	return nil
}

// recordRotationSchedule updates the rotation schedule gauges for a client from a rotation
// evaluation. When rotation is disabled it records enabled=0 and clears the interval/last/next
// gauges so stale series do not linger.
func (r *Reconciler) recordRotationSchedule(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, eval rotationEval) {
	ns, name := oidcClient.Namespace, oidcClient.Name
	metrics.SetOIDCClientRotationEnabled(ns, name, eval.enabled)
	if !eval.enabled {
		metrics.DeleteOIDCClientRotationSchedule(ns, name)
		return
	}
	var lastUnix float64
	if !eval.lastRotated.IsZero() {
		lastUnix = float64(eval.lastRotated.Unix())
	}
	var nextUnix float64
	if next := eval.nextEligible(); !next.IsZero() {
		nextUnix = float64(next.Unix())
	}
	metrics.SetOIDCClientRotationSchedule(ns, name, eval.interval.Seconds(), lastUnix, nextUnix)

	// Maintenance window gauges, when a window is configured.
	win := oidcClient.Spec.ClientSecretRotation.Window
	if win == nil {
		metrics.DeleteOIDCClientRotationWindow(ns, name)
		return
	}
	open, nextOpen, nextClose, err := windowState(time.Now(), win.Opens, win.ClosesAfter.Duration)
	if err != nil {
		// Invalid window config; the rotationDue path records window_error when due.
		metrics.DeleteOIDCClientRotationWindow(ns, name)
		return
	}
	var nextOpenUnix float64
	if !nextOpen.IsZero() {
		nextOpenUnix = float64(nextOpen.Unix())
	}
	var nextCloseUnix float64
	if !nextClose.IsZero() {
		nextCloseUnix = float64(nextClose.Unix())
	}
	metrics.SetOIDCClientRotationWindow(ns, name, open, nextOpenUnix, nextCloseUnix)
}

// applyRotationStatus mirrors the rotation timestamp onto the oidcclient status after a
// secret rotation.
func (r *Reconciler) applyRotationStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, rotatedAt *metav1.Time) {
	if rotatedAt == nil {
		return
	}
	base := oidcClient.DeepCopy()
	oidcClient.Status.LastRotatedAt = rotatedAt
	if err := r.Status().Patch(ctx, oidcClient, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to mirror LastRotatedAt to status")
	}
}

// advanceInstanceRotationStatus moves instance.Status.LastRotatedClientSecret forward to the
// secret's lastScheduledRotationAtAnnotation when that annotation is newer. Running this on every
// reconcile decouples recording the aggregate from the rotation event, so a lost status write
// self-heals on a subsequent reconcile instead of leaving min-spacing permanently blind. Manual
// rotations never set that annotation, so they cannot move the aggregate.
//
// Check cached first, then verify via apiReader. The advance is monotonic.
//
// rotatedThisReconcile reports whether the caller performed the scheduled rotation in this same
// reconcile. When true, the aggregate trailing the rotation is expected (this call is its first
// writer) and the advance is logged at V(1). When false, a trailing aggregate means a prior
// reconcile rotated but failed to persist it.
func (r *Reconciler) advanceInstanceRotationStatus(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, secret *corev1.Secret, rotatedThisReconcile bool) error {
	ts, ok := secret.Annotations[lastScheduledRotationAtAnnotation]
	if !ok {
		return nil
	}
	rotatedAt, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil
	}

	// Cheap cached gate: in steady state the aggregate already reflects this rotation, so we
	// skip the API read and write entirely.
	if cur := instance.Status.LastRotatedClientSecret; cur != nil && !rotatedAt.After(cur.Time) {
		return nil
	}

	// Cached aggregate is behind. Confirm against a strongly-consistent read before advancing
	// so we never regress a value another client already moved past us.
	fresh := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(instance), fresh); err != nil {
		return fmt.Errorf("failed to read fresh instance status for rotation aggregate: %w", err)
	}
	if cur := fresh.Status.LastRotatedClientSecret; cur != nil && !rotatedAt.After(cur.Time) {
		return nil
	}

	// The strongly-consistent read still trails the recorded rotation. If we rotated in this
	// reconcile, that's the expected first write of the aggregate (debug). Otherwise a prior
	// reconcile rotated but failed to persist the aggregate, leaving min-spacing blind until now.
	if rotatedThisReconcile {
		logf.FromContext(ctx).V(1).Info("Advancing instance rotation aggregate after rotation",
			"instance", client.ObjectKeyFromObject(fresh),
			"advancingTo", rotatedAt.UTC().Format(time.RFC3339))
	} else {
		logf.FromContext(ctx).Info("WARNING: instance rotation aggregate fell behind a recorded rotation, advancing to self-heal",
			"instance", client.ObjectKeyFromObject(fresh),
			"cachedLastRotatedClientSecret", fresh.Status.LastRotatedClientSecret,
			"advancingTo", rotatedAt.UTC().Format(time.RFC3339))
	}

	base := fresh.DeepCopy()
	fresh.Status.LastRotatedClientSecret = &metav1.Time{Time: rotatedAt}
	if err := r.Status().Patch(ctx, fresh, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("failed to advance instance LastRotatedClientSecret: %w", err)
	}
	return nil
}

// reconcileClientSecretData owns the client_secret key of the credentials Secret: it decides
// whether the secret must be regenerated, fills secretData accordingly, and maintains the
// rotation metrics. When storeClientSecret is false the operator never regenerates an existing
// credential: a previously stored value is carried forward untouched, an adopted client's
// externally-managed secret is left alone (no client_secret key), and only a client the
// operator just created may mint and store its initial secret. Returns the rotation timestamp
// (nil when nothing was rotated) and whether the rotation was scheduled.
// Extracted to keep ReconcileSecret under the cyclomatic complexity limit.
func (r *Reconciler) reconcileClientSecretData(
	ctx context.Context,
	oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient,
	instance *pocketidinternalv1alpha1.PocketIDInstance,
	apiClient *pocketid.Client,
	secretName string,
	keys pocketidinternalv1alpha1.OIDCClientSecretKeys,
	secretData map[string][]byte,
) (rotatedAt *metav1.Time, scheduledRotation bool, err error) {
	if !storeClientSecret(oidcClient) && !r.pendingInitialMint[client.ObjectKeyFromObject(oidcClient)] {
		// Record the rotation schedule as disabled so gauges from a previously enabled
		// schedule cannot linger when rotation and storeClientSecret are turned off in
		// the same update.
		r.recordRotationSchedule(oidcClient, rotationEval{})

		// A stored client_secret can only have been minted by the operator (created
		// client); keep it. Adopted clients never have one.
		existing := &corev1.Secret{}
		if err := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: oidcClient.Namespace}, existing); err == nil {
			if v, ok := existing.Data[keys.ClientSecret]; ok {
				secretData[keys.ClientSecret] = v
			}
		}

		if helpers.HasAnnotation(oidcClient, regenerateClientSecretAnnotation, "true") {
			logf.FromContext(ctx).Info("Ignoring regenerate-client-secret annotation: secret.storeClientSecret is false",
				"name", oidcClient.Name)
		}
		return nil, false, nil
	}

	// Seed the rotation counters at 0 so this client's first rotation of each kind registers
	// as a visible 0→1 step for increase()/rate() rather than a dropped first sample.
	metrics.InitOIDCClientRotationCounters(oidcClient.Namespace, oidcClient.Name)

	decision, err := r.secretRegenDecision(ctx, oidcClient, instance, secretName)
	if err != nil {
		return nil, false, err
	}
	scheduledRotation = decision.scheduled

	// Refresh the schedule gauges from the evaluation so the dashboard reflects the
	// current state even on reconciles that do not rotate.
	if decision.evaluated {
		r.recordRotationSchedule(oidcClient, decision.eval)
	}

	if !decision.regenerate {
		// update existing secret
		secretData[keys.ClientSecret] = decision.existing.Data[keys.ClientSecret]
		return nil, scheduledRotation, nil
	}

	if apiClient == nil {
		return nil, false, fmt.Errorf("apiClient is required to regenerate client secret")
	}

	logf.FromContext(ctx).Info("Rotating client secret",
		"name", oidcClient.Name, "clientID", oidcClient.Status.ClientID, "trigger", decision.trigger)

	clientSecret, err := apiClient.RegenerateOIDCClientSecret(ctx, oidcClient.Status.ClientID)
	if err != nil {
		metrics.OIDCClientSecretRotations.WithLabelValues(oidcClient.Namespace, oidcClient.Name, "error", decision.trigger).Inc()
		return nil, false, fmt.Errorf("failed to get client secret: %w", err)
	}
	metrics.OIDCClientSecretRotations.WithLabelValues(oidcClient.Namespace, oidcClient.Name, "success", decision.trigger).Inc()
	secretData[keys.ClientSecret] = []byte(clientSecret)
	now := metav1.NewTime(time.Now())
	return &now, scheduledRotation, nil
}

// regenDecision is the outcome of secretRegenDecision: whether to regenerate the client
// secret, what triggered it, whether it was a scheduled rotation (which drives the instance
// aggregate), the existing secret, and the rotation evaluation when one was performed.
type regenDecision struct {
	regenerate bool
	// trigger is "initial", "manual", or "scheduled"; only meaningful when regenerate is true.
	trigger string
	// scheduled is true for any automatic scheduled rotation (interval- or window-driven);
	// false for "initial" and "manual" triggers. Only scheduled rotations advance the
	// instance-wide aggregate.
	scheduled bool
	existing  *corev1.Secret
	// eval holds the rotation evaluation. evaluated reports whether it was populated (i.e.
	// rotationDue ran), so the schedule gauges are only recorded from a real evaluation.
	eval      rotationEval
	evaluated bool
}

// secretRegenDecision fetches the existing client secret (if any) and decides whether it
// needs to be regenerated and what triggered the regeneration. When a scheduled rotation was
// due but deferred by a downstream gate, it records the deferral metric.
// Extracted to keep ReconcileSecret under the cyclomatic complexity limit.
func (r *Reconciler) secretRegenDecision(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, instance *pocketidinternalv1alpha1.PocketIDInstance, secretName string) (regenDecision, error) {
	d := regenDecision{existing: &corev1.Secret{}}
	getErr := r.Get(ctx, client.ObjectKey{Name: secretName, Namespace: oidcClient.Namespace}, d.existing)
	if getErr != nil {
		d.regenerate, d.trigger = true, "initial"
		return d, nil
	}
	keys := r.GetSecretKeys(oidcClient)
	if _, exists := d.existing.Data[keys.ClientSecret]; !exists {
		d.regenerate, d.trigger = true, "initial"
		return d, nil
	}
	if helpers.HasAnnotation(oidcClient, regenerateClientSecretAnnotation, "true") {
		d.regenerate, d.trigger = true, "manual"
		return d, nil
	}
	eval, err := r.rotationDue(ctx, oidcClient, instance, d.existing)
	d.eval, d.evaluated = eval, true
	if err != nil {
		// A due rotation hit a window/config error; record it before propagating.
		if eval.deferReason != "" {
			metrics.OIDCClientRotationDeferred.WithLabelValues(oidcClient.Namespace, oidcClient.Name, eval.deferReason).Inc()
		}
		return d, err
	}
	if eval.due {
		d.regenerate, d.trigger, d.scheduled = true, "scheduled", true
	} else if eval.deferReason != "" {
		metrics.OIDCClientRotationDeferred.WithLabelValues(oidcClient.Namespace, oidcClient.Name, eval.deferReason).Inc()
	}
	return d, nil
}

// rotationTrigger reports whether a rotation is owed — its time-based trigger has fired since the
// anchor (last rotation, or creation when never rotated) — and the current state of any configured
// maintenance window. The two trigger modes are selected by whether interval is set:
//   - interval set:   owed once the interval has elapsed. The window, if configured, is evaluated
//     only when owed (its open state confines the rotation but never triggers it).
//   - interval unset: window-driven. The window opening is the trigger, so owed and the window's
//     open state are derived together from the same schedule: owed means a window
//     has opened since the anchor that has not been acted on.
//
// hasWindow reports whether a window is configured. An invalid window returns an error.
func rotationTrigger(rot *pocketidinternalv1alpha1.ClientSecretRotation, lastRotated, creation, now time.Time) (owed, windowOpen, hasWindow bool, err error) {
	hasWindow = rot.Window != nil
	if rot.Interval != nil {
		owed = intervalElapsed(now, lastRotated, creation, rot.Interval.Duration)
		if owed && hasWindow {
			windowOpen, err = withinWindow(now, rot.Window.Opens, rot.Window.ClosesAfter.Duration)
		}
		return owed, windowOpen, hasWindow, err
	}
	// Interval unset: the window is the sole trigger, so it must be configured. Admission (CEL)
	// guarantees this for enabled rotations, but guard the dereference so a malformed object
	// surfaces a clear error instead of panicking the reconcile loop.
	if !hasWindow {
		return false, false, false, fmt.Errorf("rotation has neither interval nor window configured")
	}
	windowOpen, owed, err = windowRotationDue(now, rotationAnchor(lastRotated, creation), rot.Window.Opens, rot.Window.ClosesAfter.Duration)
	return owed, windowOpen, hasWindow, err
}

// rotationDue checks whether all rotation gates pass: the time-based trigger (interval-driven or
// window-driven), the optional maintenance window, and instance-wide min-spacing. It returns a
// rotationEval describing the decision (and, when an owed rotation was blocked, which gate
// deferred it) so callers can drive logging, metrics, and the schedule gauges.
// The min-spacing check fetches a fresh instance status directly from the API server
// (bypassing the cache) so a rotation written by a previous reconcile is visible immediately.
func (r *Reconciler) rotationDue(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, instance *pocketidinternalv1alpha1.PocketIDInstance, existingSecret *corev1.Secret) (rotationEval, error) {
	log := logf.FromContext(ctx)
	eval := rotationEval{}

	rot := oidcClient.Spec.ClientSecretRotation
	if rot == nil || !rot.Enabled {
		return eval, nil
	}
	eval.enabled = true
	now := time.Now()
	creation := oidcClient.CreationTimestamp.Time

	// Read the last rotation timestamp; the zero value means the secret has never been rotated.
	if ts, ok := existingSecret.Annotations[lastRotatedAtAnnotation]; ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			eval.lastRotated = t
		}
	}
	eval.anchor = rotationAnchor(eval.lastRotated, creation)
	if rot.Interval != nil {
		eval.interval = rot.Interval.Duration
	}

	// Gate 1: trigger. A rotation is "owed" when its time-based trigger has fired since the anchor
	// — an elapsed interval (interval-driven) or a maintenance-window opening (window-driven).
	owed, windowOpen, hasWindow, err := rotationTrigger(rot, eval.lastRotated, creation, now)
	if err != nil {
		eval.deferReason = "window_error"
		return eval, err
	}
	if !owed {
		if rot.Interval != nil {
			log.V(1).Info("Secret rotation not due: interval not yet elapsed", "nextEligible", eval.nextEligible())
		} else {
			log.V(1).Info("Secret rotation not due: no maintenance window has opened since the last rotation",
				"lastRotated", eval.lastRotated)
		}
		return eval, nil
	}

	// Gate 2: maintenance window. When configured, an owed rotation may only fire while the window
	// is open; otherwise it is deferred. The two modes record distinct reasons because they mean
	// opposite things: interval-driven "window_closed" is healthy waiting (the interval elapsed
	// ahead of the window and will rotate at the next opening), whereas window-driven
	// "window_missed" means an opening passed unserved (operator down, min-spacing starvation, or
	// a freshly adopted secret) and the rotation has fallen a full cycle behind.
	if hasWindow && !windowOpen {
		eval.deferReason = "window_closed"
		if rot.Interval == nil {
			eval.deferReason = "window_missed"
		}
		log.V(1).Info("Secret rotation deferred: maintenance window closed",
			"reason", eval.deferReason, "windowOpens", rot.Window.Opens, "closesAfter", rot.Window.ClosesAfter.Duration)
		return eval, nil
	}

	// Gate 3: instance-wide min-spacing. Bypass the cache for a fresh status read
	// so a rotation written by a previous reconcile is visible immediately.
	fresh := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(instance), fresh); err != nil {
		return eval, fmt.Errorf("failed to get fresh instance status for min-spacing check: %w", err)
	}
	var minSpacing time.Duration
	if fresh.Spec.OIDCClientRotation != nil {
		minSpacing = fresh.Spec.OIDCClientRotation.MinSpacing.Duration
	}
	if !minSpacingOK(now, fresh.Status.LastRotatedClientSecret, minSpacing) {
		eval.deferReason = "min_spacing"
		log.Info("Secret rotation deferred: instance min-spacing not satisfied",
			"minSpacing", minSpacing, "lastGlobalRotation", fresh.Status.LastRotatedClientSecret)
		return eval, nil
	}

	eval.due = true
	return eval, nil
}

// storeClientSecret reports whether the client secret should be stored in the
// Secret (and therefore regenerated when needed). Defaults to true.
func storeClientSecret(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) bool {
	if oidcClient.Spec.Secret != nil && oidcClient.Spec.Secret.StoreClientSecret != nil {
		return *oidcClient.Spec.Secret.StoreClientSecret
	}
	return true
}

func (r *Reconciler) GetSecretName(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) string {
	if oidcClient.Spec.Secret != nil && oidcClient.Spec.Secret.Name != "" {
		return oidcClient.Spec.Secret.Name
	}
	return oidcClient.Name + "-oidc-credentials"
}

func (r *Reconciler) GetSecretLabels(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) map[string]string {
	secretLabels := common.ManagedByLabels(nil)

	if oidcClient.Spec.Secret != nil {
		if oidcClient.Spec.Secret.AdditionalLabels != nil {
			for k, v := range oidcClient.Spec.Secret.AdditionalLabels {
				_, exists := secretLabels[k]
				if !exists {
					secretLabels[k] = v
				}
			}
		}
	}
	return secretLabels
}

// GetSecretAnnotations returns the user-defined annotations to apply to the managed
// secret. Operator-managed annotations are applied separately and take precedence.
func (r *Reconciler) GetSecretAnnotations(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) map[string]string {
	if oidcClient.Spec.Secret == nil || oidcClient.Spec.Secret.AdditionalAnnotations == nil {
		return nil
	}

	annotations := make(map[string]string, len(oidcClient.Spec.Secret.AdditionalAnnotations))
	for k, v := range oidcClient.Spec.Secret.AdditionalAnnotations {
		annotations[k] = v
	}
	return annotations
}

// operatorManagedSecretAnnotations are annotations the operator writes on the
// managed secret. They cannot be overridden by AdditionalAnnotations.
var operatorManagedSecretAnnotations = map[string]struct{}{
	lastRotatedAtAnnotation:           {},
	lastScheduledRotationAtAnnotation: {},
}

// reconcileSecretAnnotations sets the secret's annotations to the desired
// user-defined set while retaining any operator-managed annotations already
// present. This drops annotations removed from the spec without disturbing
// operator-owned ones.
func reconcileSecretAnnotations(secret *corev1.Secret, desired map[string]string) {
	preserved := make(map[string]string)
	for key := range operatorManagedSecretAnnotations {
		if v, ok := secret.Annotations[key]; ok {
			preserved[key] = v
		}
	}

	if len(desired) == 0 && len(preserved) == 0 {
		secret.Annotations = nil
		return
	}

	annotations := make(map[string]string, len(desired)+len(preserved))
	for k, v := range desired {
		if _, managed := operatorManagedSecretAnnotations[k]; managed {
			continue
		}
		annotations[k] = v
	}
	for k, v := range preserved {
		annotations[k] = v
	}
	secret.Annotations = annotations
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

// oidcClientPredicate gates which events enqueue a reconcile. GenerationChangedPredicate
// alone drops annotation-only edits (annotations don't bump metadata.generation), which
// would delay a manual regenerate-client-secret request until the next periodic resync.
// Or-ing in AnnotationChangedPredicate lets the annotation force an immediate rotation
// while still filtering out status-only updates.
func oidcClientPredicate() predicate.Predicate {
	return predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{})
}

// requestsForAPI enqueues OIDC clients whose spec.apiAccess references the given API,
// so they re-resolve permission IDs when the API's spec changes.
func (r *Reconciler) requestsForAPI(ctx context.Context, obj client.Object) []reconcile.Request {
	api, ok := obj.(*pocketidinternalv1alpha1.PocketIDAPI)
	if !ok {
		return nil
	}

	clients := &pocketidinternalv1alpha1.PocketIDOIDCClientList{}
	if err := r.List(ctx, clients, client.MatchingFields{
		common.OIDCClientAPIAccessIndexKey: client.ObjectKeyFromObject(api).String(),
	}); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list OIDC clients for API", "api", client.ObjectKeyFromObject(api))
		return nil
	}

	requests := make([]reconcile.Request, 0, len(clients.Items))
	for i := range clients.Items {
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&clients.Items[i])})
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

	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDOIDCClient{}, common.OIDCClientAPIAccessIndexKey, func(raw client.Object) []string {
		oidcClient, ok := raw.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
		if !ok {
			return nil
		}

		if len(oidcClient.Spec.APIAccess) == 0 {
			return nil
		}

		keys := make([]string, 0, len(oidcClient.Spec.APIAccess))
		for _, grant := range oidcClient.Spec.APIAccess {
			if grant.APIRef.Name == "" {
				continue
			}
			namespace := grant.APIRef.Namespace
			if namespace == "" {
				namespace = oidcClient.Namespace
			}
			keys = append(keys, fmt.Sprintf("%s/%s", namespace, grant.APIRef.Name))
		}
		return keys
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDOIDCClient{}, builder.WithPredicates(oidcClientPredicate())).
		Watches(
			&pocketidinternalv1alpha1.PocketIDUserGroup{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForUserGroup),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// No GenerationChangedPredicate here: clients resolve permission keys to IDs from
		// the API's status.permissions, which changes without a spec/generation bump (e.g.
		// after the API is externally recreated with new permission IDs). Watching all
		// changes gives clients an instant re-resolve instead of waiting for a resync.
		Watches(
			&pocketidinternalv1alpha1.PocketIDAPI{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForAPI),
		).
		Named("pocketidoidcclient").
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}
