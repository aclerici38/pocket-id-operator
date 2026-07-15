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

package api

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	// APIFinalizer ensures the API is deleted from Pocket-ID before the CR is removed.
	APIFinalizer = "pocketid.internal/api-finalizer"
	// OIDCClientAPIFinalizer blocks deletion while an OIDC client still grants access to this API.
	OIDCClientAPIFinalizer = "pocketid.internal/oidc-client-api-finalizer"
)

// Reconciler reconciles a PocketIDAPI object
type Reconciler struct {
	client.Client
	common.BaseReconciler
	APIReader client.Reader
	Scheme    *runtime.Scheme

	// skipUpdate gates the update phase of reconciliation and just fetches the state.
	skipUpdate map[types.NamespacedName]bool
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidapis,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidapis/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidapis/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients,verbs=get;list;watch

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	r.EnsureClient(r.Client)

	api := &pocketidinternalv1alpha1.PocketIDAPI{}
	if err := r.Get(ctx, req.NamespacedName, api); err != nil {
		if client.IgnoreNotFound(err) == nil {
			metrics.DeleteReadinessGauge("PocketIDAPI", req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("Reconciling PocketIDAPI", "name", api.Name)

	if !api.DeletionTimestamp.IsZero() {
		return r.ReconcileDelete(ctx, api)
	}

	updatedFinalizers, err := r.reconcileFinalizers(ctx, api)
	if err != nil {
		log.Error(err, "Failed to reconcile API finalizers")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if updatedFinalizers {
		return ctrl.Result{Requeue: true}, nil
	}

	instance, err := common.SelectInstance(ctx, r.Client, api.Spec.InstanceSelector)
	if err != nil {
		log.Error(err, "Failed to select PocketIDInstance")
		_ = r.SetReadyCondition(ctx, api, metav1.ConditionFalse, "InstanceSelectionError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if validationResult := r.ValidateInstanceReady(ctx, api, instance); validationResult.ShouldRequeue {
		return ctrl.Result{RequeueAfter: validationResult.RequeueAfter}, validationResult.Error
	}

	apiClient, result, err := r.GetAPIClientOrRequeue(ctx, api, instance)
	if result != nil {
		return *result, err
	}

	// No API ID yet, create or adopt.
	if api.Status.APIID == "" {
		requeue, err := r.createOrAdoptAPI(ctx, api, apiClient)
		if err != nil {
			log.Error(err, "Failed to create or adopt API")
			_ = r.SetReadyCondition(ctx, api, metav1.ConditionFalse, "ReconcileError", err.Error())
			return ctrl.Result{RequeueAfter: common.Requeue}, nil
		}
		if requeue {
			return ctrl.Result{Requeue: true}, nil
		}
		return common.ApplyResync(ctrl.Result{}), nil
	}

	// Fetch current state from Pocket ID.
	current, err := apiClient.GetAPI(ctx, api.Status.APIID)
	if err != nil {
		if pocketid.IsNotFoundError(err) {
			log.Info("API was deleted externally, will recreate", "apiID", api.Status.APIID)
			metrics.ExternalDeletions.WithLabelValues("PocketIDAPI").Inc()
			if err := r.clearAPIStatus(ctx, api); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}
		_ = r.SetReadyCondition(ctx, api, metav1.ConditionFalse, "GetError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.updateAPIStatus(ctx, api, current); err != nil {
		log.Error(err, "Failed to update API status")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Skip the push if this reconcile was triggered for post-update status refresh.
	key := client.ObjectKeyFromObject(api)
	if r.skipUpdate[key] {
		delete(r.skipUpdate, key)
		_ = r.SetReadyCondition(ctx, api, metav1.ConditionTrue, "Reconciled", "API is in sync")
		return common.ApplyResync(ctrl.Result{}), nil
	}

	updated, err := r.pushAPIState(ctx, api, apiClient, current)
	if err != nil {
		log.Error(err, "Failed to push API state")
		_ = r.SetReadyCondition(ctx, api, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	_ = r.SetReadyCondition(ctx, api, metav1.ConditionTrue, "Reconciled", "API is in sync")

	if updated {
		return ctrl.Result{RequeueAfter: 100 * time.Millisecond}, nil
	}

	return common.ApplyResync(ctrl.Result{}), nil
}

// PocketIDAPIClient defines the minimal interface needed to look up existing APIs.
type PocketIDAPIClient interface {
	ListAPIs(ctx context.Context, search string) ([]*pocketid.API, error)
}

// FindExistingAPI returns an existing API in Pocket-ID matching the resource, or nil.
func (r *Reconciler) FindExistingAPI(ctx context.Context, apiClient PocketIDAPIClient, resource string) (*pocketid.API, error) {
	log := logf.FromContext(ctx)

	log.Info("Checking if API exists in Pocket-ID", "resource", resource)
	existing, err := apiClient.ListAPIs(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("list APIs: %w", err)
	}

	for _, candidate := range existing {
		if candidate.Resource == resource {
			log.Info("Found existing API with matching resource", "resource", resource, "apiID", candidate.ID)
			return candidate, nil
		}
	}

	return nil, nil
}

// createOrAdoptAPI creates or adopts the API when no status ID exists.
// Adoption matches on the immutable resource identifier. Returns (requeue, error).
func (r *Reconciler) createOrAdoptAPI(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI, apiClient *pocketid.Client) (bool, error) {
	log := logf.FromContext(ctx)
	name := apiName(api)
	resource := api.Spec.Resource

	// Search by resource first: Pocket-ID does not necessarily reject a duplicate
	// resource, so adopt an existing match rather than risk creating a second API.
	existing, err := r.FindExistingAPI(ctx, apiClient, resource)
	if err != nil {
		return false, fmt.Errorf("search for existing API by resource: %w", err)
	}
	if existing != nil {
		log.Info("Adopting existing API", "resource", resource, "apiID", existing.ID)
		metrics.ResourceOperations.WithLabelValues("PocketIDAPI", "adopted").Inc()
		return true, r.setAPIID(ctx, api, existing.ID)
	}

	result, err := common.CreateOrAdopt(ctx, common.CreateOrAdoptConfig[*pocketid.API]{
		ResourceKind: "API",
		ResourceID:   resource,
		Create: func() (*pocketid.API, error) {
			return apiClient.CreateAPI(ctx, pocketid.APIInput{Name: name, Resource: resource})
		},
		FindExisting: func() (*pocketid.API, error) {
			return r.FindExistingAPI(ctx, apiClient, resource)
		},
		IsNil: func(a *pocketid.API) bool { return a == nil },
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
	metrics.ResourceOperations.WithLabelValues("PocketIDAPI", operation).Inc()

	return true, r.setAPIID(ctx, api, result.Resource.ID)
}

// pushAPIState reconciles the API name and permissions to match the spec. The
// operator is the sole owner: the permission set is replaced with exactly the
// spec's permissions, so permissions added out-of-band are removed.
func (r *Reconciler) pushAPIState(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI, apiClient *pocketid.Client, current *pocketid.API) (bool, error) {
	log := logf.FromContext(ctx)

	desiredName := apiName(api)
	desiredPerms := buildPermissionInputs(api.Spec.Permissions)

	nameChanged := desiredName != current.Name
	permsChanged := !permissionsEqual(desiredPerms, current.Permissions)
	if !nameChanged && !permsChanged {
		log.V(1).Info("API state is in sync, skipping update")
		return false, nil
	}

	log.Info("Updating API", "name", api.Name)
	if nameChanged {
		if _, err := apiClient.UpdateAPI(ctx, api.Status.APIID, desiredName); err != nil {
			return false, fmt.Errorf("update API: %w", err)
		}
	}
	if permsChanged {
		if _, err := apiClient.UpdateAPIPermissions(ctx, api.Status.APIID, desiredPerms); err != nil {
			return false, fmt.Errorf("update API permissions: %w", err)
		}
	}

	metrics.ResourceOperations.WithLabelValues("PocketIDAPI", "updated").Inc()

	if r.skipUpdate == nil {
		r.skipUpdate = make(map[types.NamespacedName]bool)
	}
	r.skipUpdate[client.ObjectKeyFromObject(api)] = true

	return true, nil
}

// apiName returns the Pocket-ID name for the API: spec.name if set, else metadata.name.
func apiName(api *pocketidinternalv1alpha1.PocketIDAPI) string {
	if api.Spec.Name != "" {
		return api.Spec.Name
	}
	return api.Name
}

func (r *Reconciler) setAPIID(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI, id string) error {
	base := api.DeepCopy()
	api.Status.APIID = id
	return r.Status().Patch(ctx, api, client.MergeFrom(base))
}

func (r *Reconciler) clearAPIStatus(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI) error {
	return r.ClearStatusField(ctx, api, func() {
		api.Status.APIID = ""
	})
}

func (r *Reconciler) updateAPIStatus(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI, current *pocketid.API) error {
	if current == nil {
		return nil
	}
	base := api.DeepCopy()
	api.Status.APIID = current.ID
	api.Status.Name = current.Name
	api.Status.Resource = current.Resource
	api.Status.CreatedAt = current.CreatedAt
	api.Status.Permissions = observedPermissions(current.Permissions)
	return r.Status().Patch(ctx, api, client.MergeFrom(base))
}

func (r *Reconciler) reconcileFinalizers(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI) (bool, error) {
	referencedByOIDCClient, err := r.isAPIReferencedByOIDCClient(ctx, api)
	if err != nil {
		return false, err
	}

	updates := []helpers.FinalizerUpdate{
		{Name: APIFinalizer, ShouldAdd: true},
		{Name: OIDCClientAPIFinalizer, ShouldAdd: referencedByOIDCClient},
	}

	return helpers.ReconcileFinalizers(ctx, r.Client, api, updates)
}

func (r *Reconciler) isAPIReferencedByOIDCClient(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI) (bool, error) {
	apiKey := fmt.Sprintf("%s/%s", api.Namespace, api.Name)
	return common.IsReferencedByList(
		ctx,
		r.Client,
		common.OIDCClientAPIAccessIndexKey,
		apiKey,
		&pocketidinternalv1alpha1.PocketIDOIDCClientList{},
		func(item client.Object) bool {
			oidcClient := item.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
			return oidcClientReferencesAPI(oidcClient, api.Namespace, api.Name)
		},
	)
}

// oidcClientReferencesAPI reports whether the OIDC client grants access to the given API.
func oidcClientReferencesAPI(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiNamespace, apiName string) bool {
	for _, grant := range oidcClient.Spec.APIAccess {
		if grant.APIRef.Name == "" {
			continue
		}
		namespace := grant.APIRef.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}
		if grant.APIRef.Name == apiName && namespace == apiNamespace {
			return true
		}
	}
	return false
}

func (r *Reconciler) ReconcileDelete(ctx context.Context, api *pocketidinternalv1alpha1.PocketIDAPI) (ctrl.Result, error) {
	r.EnsureClient(r.Client)
	referencedByOIDCClient, err := r.isAPIReferencedByOIDCClient(ctx, api)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to check PocketIDOIDCClient references")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if referencedByOIDCClient {
		logf.FromContext(ctx).Info("API is referenced by PocketIDOIDCClient, blocking deletion", "api", api.Name)
		if _, err := helpers.EnsureFinalizer(ctx, r.Client, api, OIDCClientAPIFinalizer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Remove OIDCClientAPIFinalizer if no longer referenced.
	if controllerutil.ContainsFinalizer(api, OIDCClientAPIFinalizer) {
		if err := helpers.RemoveFinalizers(ctx, r.Client, api, OIDCClientAPIFinalizer); err != nil {
			if errors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	result, err := r.ReconcileDeleteWithPocketID(
		ctx,
		api,
		api.Status.APIID,
		api.Spec.InstanceSelector,
		APIFinalizer,
		func(ctx context.Context, apiClient *pocketid.Client, id string) error {
			if err := apiClient.DeleteAPI(ctx, id); err != nil {
				return err
			}
			metrics.ResourceOperations.WithLabelValues("PocketIDAPI", "deleted").Inc()
			return nil
		},
	)
	if err == nil && result == (ctrl.Result{}) {
		metrics.DeleteReadinessGauge("PocketIDAPI", api.Namespace, api.Name)
	}
	return result, err
}

// requestsForOIDCClient enqueues the APIs referenced by an OIDC client's apiAccess so
// their reference finalizer is re-evaluated when the client's grants change.
func (r *Reconciler) requestsForOIDCClient(_ context.Context, obj client.Object) []reconcile.Request {
	oidcClient, ok := obj.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
	if !ok {
		return nil
	}

	seen := make(map[client.ObjectKey]struct{})
	var requests []reconcile.Request
	for _, grant := range oidcClient.Spec.APIAccess {
		if grant.APIRef.Name == "" {
			continue
		}
		namespace := grant.APIRef.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}
		key := client.ObjectKey{Namespace: namespace, Name: grant.APIRef.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		requests = append(requests, reconcile.Request{NamespacedName: key})
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDAPI{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&pocketidinternalv1alpha1.PocketIDOIDCClient{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForOIDCClient),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("pocketidapi").
		Complete(r)
}
