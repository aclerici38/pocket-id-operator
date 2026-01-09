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
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	userGroupFinalizer           = "pocketid.internal/user-group-finalizer"
	oidcClientUserGroupFinalizer = "pocketid.internal/oidc-client-finalizer"
	userGroupUserRefIndexKey     = "pocketidusergroup.userRef"
)

// PocketIDUserGroupReconciler reconciles a PocketIDUserGroup object
type PocketIDUserGroupReconciler struct {
	client.Client
	BaseReconciler
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidoidcclients,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the PocketIDUserGroup object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
func (r *PocketIDUserGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	r.EnsureClient(r.Client)

	userGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := r.Get(ctx, req.NamespacedName, userGroup); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDUserGroup", "name", userGroup.Name)

	if !userGroup.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, userGroup)
	}

	updatedFinalizers, err := r.reconcileUserGroupFinalizers(ctx, userGroup)
	if err != nil {
		log.Error(err, "Failed to reconcile user group finalizers")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	if updatedFinalizers {
		return ctrl.Result{Requeue: true}, nil
	}

	instance, err := selectInstance(ctx, r.Client, userGroup.Spec.InstanceSelector)
	if err != nil {
		log.Error(err, "Failed to select PocketIDInstance")
		_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionFalse, "InstanceSelectionError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Validate instance is ready using base reconciler
	if validationResult := r.ValidateInstanceReady(ctx, userGroup, instance); validationResult.ShouldRequeue {
		return ctrl.Result{RequeueAfter: validationResult.RequeueAfter}, validationResult.Error
	}

	// Get API client using base reconciler
	apiClient, result, err := r.GetAPIClientOrWait(ctx, userGroup, instance)
	if result != nil {
		return *result, err
	}

	current, err := r.reconcileUserGroup(ctx, userGroup, apiClient)
	if err != nil {
		log.Error(err, "Failed to reconcile user group")
		if updateErr := r.updateUserGroupStatus(ctx, userGroup, current); updateErr != nil {
			log.Error(updateErr, "Failed to update user group status")
		}
		_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if err := r.updateUserGroupStatus(ctx, userGroup, current); err != nil {
		log.Error(err, "Failed to update user group status")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionTrue, "Reconciled", "User group is in sync")

	return applyResync(ctrl.Result{}), nil
}

func (r *PocketIDUserGroupReconciler) reconcileUserGroup(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, apiClient *pocketid.Client) (*pocketid.UserGroup, error) {
	name := userGroup.Spec.Name
	if name == "" {
		name = userGroup.Name
	}
	friendlyName := userGroup.Spec.FriendlyName
	if friendlyName == "" {
		friendlyName = name
	}

	var current *pocketid.UserGroup
	var err error
	if userGroup.Status.GroupID == "" {
		current, err = apiClient.CreateUserGroup(ctx, name, friendlyName)
	} else {
		current, err = apiClient.UpdateUserGroup(ctx, userGroup.Status.GroupID, name, friendlyName)
	}
	if err != nil {
		return nil, err
	}

	if userGroup.Spec.CustomClaims != nil {
		claims := make([]pocketid.CustomClaim, 0, len(userGroup.Spec.CustomClaims))
		for _, claim := range userGroup.Spec.CustomClaims {
			claims = append(claims, pocketid.CustomClaim{Key: claim.Key, Value: claim.Value})
		}
		updated, err := apiClient.UpdateUserGroupCustomClaims(ctx, current.ID, claims)
		if err != nil {
			return nil, err
		}
		current.CustomClaims = updated
	}

	if userGroup.Spec.UserRefs != nil {
		userIDs, err := r.resolveUserRefs(ctx, userGroup)
		if err != nil {
			return current, err
		}
		if err := apiClient.UpdateUserGroupUsers(ctx, current.ID, userIDs); err != nil {
			return current, err
		}
	}

	latest, err := apiClient.GetUserGroup(ctx, current.ID)
	if err != nil {
		return nil, err
	}

	return latest, nil
}

func (r *PocketIDUserGroupReconciler) resolveUserRefs(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) ([]string, error) {
	return ResolveUserReferences(ctx, r.Client, userGroup.Spec.UserRefs, userGroup.Namespace)
}

func (r *PocketIDUserGroupReconciler) updateUserGroupStatus(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, current *pocketid.UserGroup) error {
	if current == nil {
		return nil
	}
	base := userGroup.DeepCopy()
	userGroup.Status.GroupID = current.ID
	userGroup.Status.Name = current.Name
	userGroup.Status.FriendlyName = current.FriendlyName
	userGroup.Status.CreatedAt = current.CreatedAt
	userGroup.Status.LdapID = current.LdapID
	userGroup.Status.UserCount = current.UserCount
	userGroup.Status.CustomClaims = toCustomClaims(current.CustomClaims)
	return r.Status().Patch(ctx, userGroup, client.MergeFrom(base))
}

func (r *PocketIDUserGroupReconciler) reconcileUserGroupFinalizers(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) (bool, error) {
	needsUpdate := false

	if !controllerutil.ContainsFinalizer(userGroup, userGroupFinalizer) {
		controllerutil.AddFinalizer(userGroup, userGroupFinalizer)
		needsUpdate = true
	}

	referencedByOIDCClient, err := r.isUserGroupReferencedByOIDCClient(ctx, userGroup)
	if err != nil {
		return false, err
	}
	if referencedByOIDCClient {
		if !controllerutil.ContainsFinalizer(userGroup, oidcClientUserGroupFinalizer) {
			controllerutil.AddFinalizer(userGroup, oidcClientUserGroupFinalizer)
			needsUpdate = true
		}
	} else if controllerutil.ContainsFinalizer(userGroup, oidcClientUserGroupFinalizer) {
		controllerutil.RemoveFinalizer(userGroup, oidcClientUserGroupFinalizer)
		needsUpdate = true
	}

	if !needsUpdate {
		return false, nil
	}

	if err := r.Update(ctx, userGroup); err != nil {
		if errors.IsConflict(err) {
			return true, nil
		}
		return false, err
	}

	return true, nil
}

func (r *PocketIDUserGroupReconciler) isUserGroupReferencedByOIDCClient(ctx context.Context, group *pocketidinternalv1alpha1.PocketIDUserGroup) (bool, error) {
	groupKey := fmt.Sprintf("%s/%s", group.Namespace, group.Name)
	clients := &pocketidinternalv1alpha1.PocketIDOIDCClientList{}
	if err := r.List(ctx, clients, client.MatchingFields{oidcClientAllowedGroupIndexKey: groupKey}); err == nil {
		return len(clients.Items) > 0, nil
	}

	if err := r.List(ctx, clients); err != nil {
		return false, err
	}

	for i := range clients.Items {
		if oidcClientAllowsGroup(&clients.Items[i], group.Namespace, group.Name) {
			return true, nil
		}
	}

	return false, nil
}

func oidcClientAllowsGroup(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, groupNamespace, groupName string) bool {
	for _, ref := range oidcClient.Spec.AllowedUserGroups {
		if ref.Name == "" {
			continue
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}
		if ref.Name == groupName && namespace == groupNamespace {
			return true
		}
	}
	return false
}

func (r *PocketIDUserGroupReconciler) reconcileDelete(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) (ctrl.Result, error) {
	r.EnsureClient(r.Client)
	referencedByOIDCClient, err := r.isUserGroupReferencedByOIDCClient(ctx, userGroup)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to check PocketIDOIDCClient references")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	if referencedByOIDCClient {
		logf.FromContext(ctx).Info("User group is referenced by PocketIDOIDCClient, blocking deletion", "userGroup", userGroup.Name)
		if !controllerutil.ContainsFinalizer(userGroup, oidcClientUserGroupFinalizer) {
			controllerutil.AddFinalizer(userGroup, oidcClientUserGroupFinalizer)
			if err := r.Update(ctx, userGroup); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	if controllerutil.ContainsFinalizer(userGroup, oidcClientUserGroupFinalizer) {
		controllerutil.RemoveFinalizer(userGroup, oidcClientUserGroupFinalizer)
		if err := r.Update(ctx, userGroup); err != nil {
			if errors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	return r.ReconcileDeleteWithPocketID(
		ctx,
		userGroup,
		userGroup.Status.GroupID,
		userGroup.Spec.InstanceSelector,
		userGroupFinalizer,
		func(ctx context.Context, client *pocketid.Client, id string) error {
			return client.DeleteUserGroup(ctx, id)
		},
	)
}

func (r *PocketIDUserGroupReconciler) requestsForUser(ctx context.Context, obj client.Object) []reconcile.Request {
	user, ok := obj.(*pocketidinternalv1alpha1.PocketIDUser)
	if !ok {
		return nil
	}

	userGroups := &pocketidinternalv1alpha1.PocketIDUserGroupList{}
	if err := r.List(ctx, userGroups, client.MatchingFields{
		userGroupUserRefIndexKey: client.ObjectKeyFromObject(user).String(),
	}); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list user groups for user", "user", client.ObjectKeyFromObject(user))
		return nil
	}

	requests := make([]reconcile.Request, 0, len(userGroups.Items))
	for i := range userGroups.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&userGroups.Items[i]),
		})
	}

	return requests
}

func (r *PocketIDUserGroupReconciler) requestsForOIDCClient(ctx context.Context, obj client.Object) []reconcile.Request {
	oidcClient, ok := obj.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
	if !ok {
		return nil
	}

	if len(oidcClient.Spec.AllowedUserGroups) == 0 {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(oidcClient.Spec.AllowedUserGroups))
	for _, ref := range oidcClient.Spec.AllowedUserGroups {
		if ref.Name == "" {
			continue
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: namespace, Name: ref.Name},
		})
	}

	return requests
}

func toCustomClaims(claims []pocketid.CustomClaim) []pocketidinternalv1alpha1.CustomClaim {
	if len(claims) == 0 {
		return nil
	}
	result := make([]pocketidinternalv1alpha1.CustomClaim, 0, len(claims))
	for _, claim := range claims {
		result = append(result, pocketidinternalv1alpha1.CustomClaim{
			Key:   claim.Key,
			Value: claim.Value,
		})
	}
	return result
}

// SetupWithManager sets up the controller with the Manager.
func (r *PocketIDUserGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDUserGroup{}, userGroupUserRefIndexKey, func(raw client.Object) []string {
		userGroup, ok := raw.(*pocketidinternalv1alpha1.PocketIDUserGroup)
		if !ok {
			return nil
		}

		if len(userGroup.Spec.UserRefs) == 0 {
			return nil
		}

		keys := make([]string, 0, len(userGroup.Spec.UserRefs))
		for _, ref := range userGroup.Spec.UserRefs {
			if ref.Name == "" {
				continue
			}
			namespace := ref.Namespace
			if namespace == "" {
				namespace = userGroup.Namespace
			}
			keys = append(keys, fmt.Sprintf("%s/%s", namespace, ref.Name))
		}
		return keys
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDUserGroup{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&pocketidinternalv1alpha1.PocketIDUser{}, handler.EnqueueRequestsFromMapFunc(r.requestsForUser)).
		Watches(&pocketidinternalv1alpha1.PocketIDOIDCClient{}, handler.EnqueueRequestsFromMapFunc(r.requestsForOIDCClient)).
		Named("pocketidusergroup").
		Complete(r)
}
