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

package usergroup

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	UserGroupFinalizer           = "pocketid.internal/user-group-finalizer"
	OIDCClientUserGroupFinalizer = "pocketid.internal/oidc-client-finalizer"
)

// OIDCClientAllowedGroupIndexKey is the index key for OIDC client allowed groups
const OIDCClientAllowedGroupIndexKey = "pocketidoidcclient.allowedGroup"

// UserGroupUserRefIndexKey is the index key for user group user references
const UserGroupUserRefIndexKey = "pocketidusergroup.userRef"

// Reconciler reconciles a PocketIDUserGroup object
type Reconciler struct {
	client.Client
	common.BaseReconciler
	APIReader client.Reader
	Scheme    *runtime.Scheme
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
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	r.EnsureClient(r.Client)

	userGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := r.Get(ctx, req.NamespacedName, userGroup); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDUserGroup", "name", userGroup.Name)

	if !userGroup.DeletionTimestamp.IsZero() {
		return r.ReconcileDelete(ctx, userGroup)
	}

	updatedFinalizers, err := r.ReconcileUserGroupFinalizers(ctx, userGroup)
	if err != nil {
		log.Error(err, "Failed to reconcile user group finalizers")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if updatedFinalizers {
		return ctrl.Result{Requeue: true}, nil
	}

	instance, err := common.SelectInstance(ctx, r.Client, userGroup.Spec.InstanceSelector)
	if err != nil {
		log.Error(err, "Failed to select PocketIDInstance")
		_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionFalse, "InstanceSelectionError", err.Error())
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Validate instance is ready using base reconciler
	if validationResult := r.ValidateInstanceReady(ctx, userGroup, instance); validationResult.ShouldRequeue {
		return ctrl.Result{RequeueAfter: validationResult.RequeueAfter}, validationResult.Error
	}

	// Get API client from pool
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
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	if err := r.updateUserGroupStatus(ctx, userGroup, current); err != nil {
		log.Error(err, "Failed to update user group status")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionTrue, "Reconciled", "User group is in sync")

	return common.ApplyResync(ctrl.Result{}), nil
}

// pocketIDUserGroupAPI defines the minimal interface needed for user group operations
type PocketIDUserGroupAPI interface {
	ListUserGroups(ctx context.Context, search string) ([]*pocketid.UserGroup, error)
	CreateUserGroup(ctx context.Context, name, friendlyName string) (*pocketid.UserGroup, error)
	GetUserGroup(ctx context.Context, id string) (*pocketid.UserGroup, error)
	UpdateUserGroup(ctx context.Context, id, name, friendlyName string) (*pocketid.UserGroup, error)
	UpdateUserGroupCustomClaims(ctx context.Context, id string, claims []pocketid.CustomClaim) ([]pocketid.CustomClaim, error)
	UpdateUserGroupUsers(ctx context.Context, id string, userIDs []string) error
}

// FindExistingUserGroup checks if a user group with the given name already exists in Pocket-ID.
// Returns the existing group if found, or nil if no matching group exists.
func (r *Reconciler) FindExistingUserGroup(ctx context.Context, apiClient PocketIDUserGroupAPI, name string) (*pocketid.UserGroup, error) {
	log := logf.FromContext(ctx)

	log.Info("Checking if user group exists in Pocket-ID", "name", name)
	existingGroups, err := apiClient.ListUserGroups(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("list user groups: %w", err)
	}

	// Check if name already exists
	for _, existingGroup := range existingGroups {
		if existingGroup.Name == name {
			log.Info("Found existing user group with matching name", "name", name, "groupID", existingGroup.ID)
			return existingGroup, nil
		}
	}

	return nil, nil
}

func (r *Reconciler) reconcileUserGroup(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, apiClient *pocketid.Client) (*pocketid.UserGroup, error) {
	log := logf.FromContext(ctx)

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
		// Check if user group already exists
		existingGroup, err := r.FindExistingUserGroup(ctx, apiClient, name)
		if err != nil {
			return nil, fmt.Errorf("find existing user group: %w", err)
		}

		if existingGroup != nil {
			log.Info("Adopting existing user group from Pocket-ID", "name", name, "groupID", existingGroup.ID)
			current = existingGroup
		} else {
			log.Info("Creating user group in Pocket-ID", "name", name)
			current, err = apiClient.CreateUserGroup(ctx, name, friendlyName)
			if err != nil {
				return nil, fmt.Errorf("create user group: %w", err)
			}
		}
	} else {
		current, err = apiClient.UpdateUserGroup(ctx, userGroup.Status.GroupID, name, friendlyName)
		if err != nil {
			return nil, fmt.Errorf("update user group: %w", err)
		}
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

func (r *Reconciler) resolveUserRefs(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) ([]string, error) {
	return helpers.ResolveUserReferences(ctx, r.Client, userGroup.Spec.UserRefs, userGroup.Namespace)
}

func (r *Reconciler) updateUserGroupStatus(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, current *pocketid.UserGroup) error {
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

func (r *Reconciler) ReconcileUserGroupFinalizers(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) (bool, error) {
	referencedByOIDCClient, err := r.isUserGroupReferencedByOIDCClient(ctx, userGroup)
	if err != nil {
		return false, err
	}

	updates := []helpers.FinalizerUpdate{
		{Name: UserGroupFinalizer, ShouldAdd: true},
		{Name: OIDCClientUserGroupFinalizer, ShouldAdd: referencedByOIDCClient},
	}

	return helpers.ReconcileFinalizers(ctx, r.Client, userGroup, updates)
}

func (r *Reconciler) isUserGroupReferencedByOIDCClient(ctx context.Context, group *pocketidinternalv1alpha1.PocketIDUserGroup) (bool, error) {
	groupKey := fmt.Sprintf("%s/%s", group.Namespace, group.Name)
	clients := &pocketidinternalv1alpha1.PocketIDOIDCClientList{}
	if err := r.List(ctx, clients, client.MatchingFields{OIDCClientAllowedGroupIndexKey: groupKey}); err == nil {
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

func (r *Reconciler) ReconcileDelete(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) (ctrl.Result, error) {
	r.EnsureClient(r.Client)
	referencedByOIDCClient, err := r.isUserGroupReferencedByOIDCClient(ctx, userGroup)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to check PocketIDOIDCClient references")
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}
	if referencedByOIDCClient {
		logf.FromContext(ctx).Info("User group is referenced by PocketIDOIDCClient, blocking deletion", "userGroup", userGroup.Name)
		if _, err := helpers.EnsureFinalizer(ctx, r.Client, userGroup, OIDCClientUserGroupFinalizer); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: common.Requeue}, nil
	}

	// Remove OIDCClientUserGroupFinalizer if not referenced
	if controllerutil.ContainsFinalizer(userGroup, OIDCClientUserGroupFinalizer) {
		if err := helpers.RemoveFinalizers(ctx, r.Client, userGroup, OIDCClientUserGroupFinalizer); err != nil {
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
		UserGroupFinalizer,
		func(ctx context.Context, client *pocketid.Client, id string) error {
			return client.DeleteUserGroup(ctx, id)
		},
	)
}

func (r *Reconciler) requestsForUser(ctx context.Context, obj client.Object) []reconcile.Request {
	user, ok := obj.(*pocketidinternalv1alpha1.PocketIDUser)
	if !ok {
		return nil
	}

	userGroups := &pocketidinternalv1alpha1.PocketIDUserGroupList{}
	if err := r.List(ctx, userGroups, client.MatchingFields{
		UserGroupUserRefIndexKey: client.ObjectKeyFromObject(user).String(),
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

func (r *Reconciler) requestsForOIDCClient(ctx context.Context, obj client.Object) []reconcile.Request {
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
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDUserGroup{}, UserGroupUserRefIndexKey, func(raw client.Object) []string {
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
		For(&pocketidinternalv1alpha1.PocketIDUserGroup{}).
		Watches(&pocketidinternalv1alpha1.PocketIDUser{}, handler.EnqueueRequestsFromMapFunc(r.requestsForUser)).
		Watches(&pocketidinternalv1alpha1.PocketIDOIDCClient{}, handler.EnqueueRequestsFromMapFunc(r.requestsForOIDCClient)).
		Named("pocketidusergroup").
		Complete(r)
}
