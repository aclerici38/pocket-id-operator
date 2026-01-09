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
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
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
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	oidcClientFinalizer            = "pocketid.internal/oidc-client-finalizer"
	oidcClientAllowedGroupIndexKey = "pocketidoidcclient.allowedGroup"
)

// PocketIDOIDCClientReconciler reconciles a PocketIDOIDCClient object
type PocketIDOIDCClientReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the PocketIDOIDCClient object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
func (r *PocketIDOIDCClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := r.Get(ctx, req.NamespacedName, oidcClient); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDOIDCClient", "name", oidcClient.Name)

	if !oidcClient.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, oidcClient)
	}

	if !controllerutil.ContainsFinalizer(oidcClient, oidcClientFinalizer) {
		controllerutil.AddFinalizer(oidcClient, oidcClientFinalizer)
		if err := r.Update(ctx, oidcClient); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	instance, err := selectInstance(ctx, r.Client, oidcClient.Spec.InstanceSelector)
	if err != nil {
		log.Error(err, "Failed to select PocketIDInstance")
		r.setReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "InstanceSelectionError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if !instanceReady(instance) {
		log.Info("PocketIDInstance not ready, requeuing")
		r.setReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "InstanceNotReady", "Waiting for PocketIDInstance to be ready")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if !instance.Status.Bootstrapped {
		log.Info("PocketIDInstance not bootstrapped, requeuing")
		r.setReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "InstanceNotBootstrapped", "Waiting for PocketIDInstance bootstrap")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	apiClient, err := apiClientForInstance(ctx, r.Client, instance)
	if err != nil {
		if errors.Is(err, ErrAPIClientNotReady) {
			log.Info("API client not ready, requeuing")
			r.setReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "APIClientNotReady", "Waiting for PocketID API client")
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		log.Error(err, "Failed to get API client")
		r.setReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "APIClientError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	current, err := r.reconcileOIDCClient(ctx, oidcClient, apiClient)
	if err != nil {
		log.Error(err, "Failed to reconcile OIDC client")
		if updateErr := r.updateOIDCClientStatus(ctx, oidcClient, current); updateErr != nil {
			log.Error(updateErr, "Failed to update OIDC client status")
		}
		r.setReadyCondition(ctx, oidcClient, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if err := r.updateOIDCClientStatus(ctx, oidcClient, current); err != nil {
		log.Error(err, "Failed to update OIDC client status")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	r.setReadyCondition(ctx, oidcClient, metav1.ConditionTrue, "Reconciled", "OIDC client is in sync")

	return applyResync(ctrl.Result{}), nil
}

func (r *PocketIDOIDCClientReconciler) reconcileOIDCClient(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient *pocketid.Client) (*pocketid.OIDCClient, error) {
	input := r.oidcClientInput(oidcClient)

	clientID := oidcClient.Status.ClientID
	if clientID == "" {
		clientID = oidcClient.Spec.ID
	}

	var current *pocketid.OIDCClient
	var err error
	if clientID == "" {
		current, err = apiClient.CreateOIDCClient(ctx, input)
	} else {
		current, err = apiClient.UpdateOIDCClient(ctx, clientID, input)
	}
	if err != nil {
		return nil, err
	}

	if oidcClient.Spec.AllowedUserGroups != nil {
		groupIDs, err := r.resolveAllowedUserGroups(ctx, oidcClient)
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

func (r *PocketIDOIDCClientReconciler) oidcClientInput(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) pocketid.OIDCClientInput {
	name := oidcClient.Spec.Name
	if name == "" {
		name = oidcClient.Name
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
		ID:                       oidcClient.Spec.ID,
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

func (r *PocketIDOIDCClientReconciler) resolveAllowedUserGroups(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) ([]string, error) {
	groupIDs := make([]string, 0, len(oidcClient.Spec.AllowedUserGroups))
	for _, ref := range oidcClient.Spec.AllowedUserGroups {
		if ref.Name == "" {
			return nil, fmt.Errorf("allowedUserGroups contains an empty name")
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}
		group := &pocketidinternalv1alpha1.PocketIDUserGroup{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, group); err != nil {
			return nil, fmt.Errorf("get user group %s: %w", ref.Name, err)
		}
		if group.Status.GroupID == "" {
			return nil, fmt.Errorf("user group %s is not ready", ref.Name)
		}
		groupIDs = append(groupIDs, group.Status.GroupID)
	}
	return groupIDs, nil
}

// Updates the OIDCClient status with values returned from pocket-id
func (r *PocketIDOIDCClientReconciler) updateOIDCClientStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, current *pocketid.OIDCClient) error {
	if current == nil {
		return nil
	}
	base := oidcClient.DeepCopy()
	oidcClient.Status.ClientID = current.ID
	oidcClient.Status.Name = current.Name
	oidcClient.Status.AllowedUserGroupIDs = current.AllowedUserGroupIDs
	return r.Status().Patch(ctx, oidcClient, client.MergeFrom(base))
}

func (r *PocketIDOIDCClientReconciler) setReadyCondition(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, status metav1.ConditionStatus, reason, message string) {
	base := oidcClient.DeepCopy()
	meta.SetStatusCondition(&oidcClient.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: oidcClient.Generation,
	})
	if err := r.Status().Patch(ctx, oidcClient, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update condition")
	}
}

func (r *PocketIDOIDCClientReconciler) reconcileDelete(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if oidcClient.Status.ClientID != "" {
		instance, err := selectInstance(ctx, r.Client, oidcClient.Spec.InstanceSelector)
		if err != nil {
			if errors.Is(err, errNoInstance) {
				log.Info("No PocketIDInstance found; skipping Pocket-ID deletion", "clientID", oidcClient.Status.ClientID)
			} else {
				log.Error(err, "Failed to select PocketIDInstance for delete")
				return ctrl.Result{}, err
			}
		} else {
			apiClient, err := apiClientForInstance(ctx, r.Client, instance)
			if err != nil {
				if errors.Is(err, ErrAPIClientNotReady) {
					log.Info("API client not ready for delete, requeuing", "clientID", oidcClient.Status.ClientID)
					return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
				}
				log.Error(err, "Failed to get API client for delete")
				return ctrl.Result{}, err
			}
			log.Info("Deleting OIDC client from Pocket-ID", "clientID", oidcClient.Status.ClientID)
			if err := apiClient.DeleteOIDCClient(ctx, oidcClient.Status.ClientID); err != nil {
				log.Error(err, "Failed to delete OIDC client from Pocket-ID")
				return ctrl.Result{}, err
			}
		}
	}

	controllerutil.RemoveFinalizer(oidcClient, oidcClientFinalizer)
	if err := r.Update(ctx, oidcClient); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *PocketIDOIDCClientReconciler) requestsForUserGroup(ctx context.Context, obj client.Object) []reconcile.Request {
	group, ok := obj.(*pocketidinternalv1alpha1.PocketIDUserGroup)
	if !ok {
		return nil
	}

	clients := &pocketidinternalv1alpha1.PocketIDOIDCClientList{}
	if err := r.List(ctx, clients, client.MatchingFields{
		oidcClientAllowedGroupIndexKey: client.ObjectKeyFromObject(group).String(),
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
func (r *PocketIDOIDCClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDOIDCClient{}, oidcClientAllowedGroupIndexKey, func(raw client.Object) []string {
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
