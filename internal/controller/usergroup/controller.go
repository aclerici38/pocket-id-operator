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
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
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
	UserGroupFinalizer           = "pocketid.internal/user-group-finalizer"
	OIDCClientUserGroupFinalizer = "pocketid.internal/oidc-client-finalizer"
)

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

	apiClient, result, err := r.GetAPIClientOrWait(ctx, userGroup, instance)
	if result != nil {
		return *result, err
	}

	// Sync status from Pocket ID
	if userGroup.Status.GroupID != "" {
		current, err := apiClient.GetUserGroup(ctx, userGroup.Status.GroupID)
		if err != nil {
			if pocketid.IsNotFoundError(err) {
				log.Info("User group was deleted externally, will recreate", "groupID", userGroup.Status.GroupID)
				if err := r.clearGroupStatus(ctx, userGroup); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{Requeue: true}, nil
			}
			if result, handled := r.HandleTransientDependencyError(
				ctx,
				userGroup,
				err,
				"InstanceUnavailable",
				fmt.Sprintf("Waiting for Pocket-ID instance '%s/%s' to become reachable", instance.Namespace, instance.Name),
			); handled {
				return *result, nil
			}
			_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionFalse, "GetError", err.Error())
			return ctrl.Result{RequeueAfter: common.Requeue}, nil
		}

		if err := r.updateUserGroupStatus(ctx, userGroup, current); err != nil {
			log.Error(err, "Failed to update user group status")
			return ctrl.Result{RequeueAfter: common.Requeue}, nil
		}
	}

	// Ensure resource exists or push state from CR
	if userGroup.Status.GroupID == "" {
		requeue, err := r.createOrAdoptUserGroup(ctx, userGroup, apiClient)
		if err != nil {
			if result, handled := r.HandleTransientDependencyError(
				ctx,
				userGroup,
				err,
				"InstanceUnavailable",
				fmt.Sprintf("Waiting for Pocket-ID instance '%s/%s' to become reachable", instance.Namespace, instance.Name),
			); handled {
				return *result, nil
			}
			log.Error(err, "Failed to create or adopt user group")
			_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionFalse, "ReconcileError", err.Error())
			return ctrl.Result{RequeueAfter: common.Requeue}, nil
		}
		if requeue {
			return ctrl.Result{Requeue: true}, nil
		}
		return common.ApplyResync(ctrl.Result{}), nil
	}

	if err := r.pushUserGroupState(ctx, userGroup, apiClient); err != nil {
		if common.IsDependencyNotReadyError(err) {
			log.Info("Referenced dependency is not ready yet, waiting before retry", "error", err.Error())
			_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionFalse, "DependencyNotReady", err.Error())
			return ctrl.Result{RequeueAfter: common.DependencyRequeue}, nil
		}
		if result, handled := r.HandleTransientDependencyError(
			ctx,
			userGroup,
			err,
			"DependencyUnavailable",
			"Waiting for dependent resources and Pocket-ID instance to become reachable",
		); handled {
			return *result, nil
		}
		log.Error(err, "Failed to push user group state")
		_ = r.SetReadyCondition(ctx, userGroup, metav1.ConditionFalse, "ReconcileError", err.Error())
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

	for _, existingGroup := range existingGroups {
		if existingGroup.Name == name {
			log.Info("Found existing user group with matching name", "name", name, "groupID", existingGroup.ID)
			return existingGroup, nil
		}
	}

	return nil, nil
}

// createOrAdoptUserGroup handles creation or adoption when no status ID exists.
// Returns (requeue, error). On success, sets the status ID and signals a requeue.
func (r *Reconciler) createOrAdoptUserGroup(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, apiClient *pocketid.Client) (bool, error) {
	name := userGroup.Spec.Name
	if name == "" {
		name = userGroup.Name
	}
	friendlyName := userGroup.Spec.FriendlyName
	if friendlyName == "" {
		friendlyName = name
	}

	result, err := common.CreateOrAdopt(ctx, common.CreateOrAdoptConfig[*pocketid.UserGroup]{
		ResourceKind: "user group",
		ResourceID:   name,
		Create: func() (*pocketid.UserGroup, error) {
			return apiClient.CreateUserGroup(ctx, name, friendlyName)
		},
		FindExisting: func() (*pocketid.UserGroup, error) {
			return r.FindExistingUserGroup(ctx, apiClient, name)
		},
		IsNil: func(g *pocketid.UserGroup) bool {
			return g == nil
		},
	})
	if err != nil {
		return false, err
	}

	if result.Resource == nil {
		return true, nil
	}

	if err := r.setGroupID(ctx, userGroup, result.Resource.ID); err != nil {
		return false, err
	}
	return true, nil
}

// pushUserGroupState pushes the desired state from the CR spec into Pocket ID.
func (r *Reconciler) pushUserGroupState(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, apiClient *pocketid.Client) error {
	name := userGroup.Spec.Name
	if name == "" {
		name = userGroup.Name
	}
	friendlyName := userGroup.Spec.FriendlyName
	if friendlyName == "" {
		friendlyName = name
	}

	if _, err := apiClient.UpdateUserGroup(ctx, userGroup.Status.GroupID, name, friendlyName); err != nil {
		return fmt.Errorf("update user group: %w", err)
	}

	if userGroup.Spec.CustomClaims != nil {
		claims := make([]pocketid.CustomClaim, 0, len(userGroup.Spec.CustomClaims))
		for _, claim := range userGroup.Spec.CustomClaims {
			claims = append(claims, pocketid.CustomClaim{Key: claim.Key, Value: claim.Value})
		}
		if _, err := apiClient.UpdateUserGroupCustomClaims(ctx, userGroup.Status.GroupID, claims); err != nil {
			return err
		}
	}

	if userGroup.Spec.Users != nil {
		userIDs, err := r.resolveUsers(ctx, userGroup, apiClient)
		if err != nil {
			return err
		}
		if err := apiClient.UpdateUserGroupUsers(ctx, userGroup.Status.GroupID, userIDs); err != nil {
			return err
		}
	}

	// Aggregate allowed OIDC clients from both directions and push
	clientIDs, err := r.aggregateAllowedOIDCClientIDs(ctx, userGroup)
	if err != nil {
		return fmt.Errorf("aggregate allowed OIDC clients: %w", err)
	}
	if clientIDs != nil {
		if err := apiClient.UpdateUserGroupAllowedOIDCClients(ctx, userGroup.Status.GroupID, clientIDs); err != nil {
			return err
		}
	}

	return nil
}

// aggregateAllowedOIDCClientIDs returns the union of:
// Direct refs from spec.allowedOIDCClients
// OIDCClients whose spec.allowedUserGroups references this group
// Returns nil if neither source contributes.
func (r *Reconciler) aggregateAllowedOIDCClientIDs(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) ([]string, error) {
	// Find OIDCClients whose spec.allowedUserGroups references this group
	groupKey := fmt.Sprintf("%s/%s", userGroup.Namespace, userGroup.Name)
	oidcClients := &pocketidinternalv1alpha1.PocketIDOIDCClientList{}
	if err := r.List(ctx, oidcClients, client.MatchingFields{
		common.OIDCClientAllowedGroupIndexKey: groupKey,
	}); err != nil {
		return nil, fmt.Errorf("list OIDC clients referencing user group: %w", err)
	}

	hasDirectRefs := len(userGroup.Spec.AllowedOIDCClients) > 0
	hasReverseRefs := len(oidcClients.Items) > 0

	if !hasDirectRefs && !hasReverseRefs {
		return nil, nil
	}

	clientIDSet := make(map[string]struct{})

	if hasDirectRefs {
		directIDs, err := helpers.ResolveOIDCClientReferences(ctx, r.Client, userGroup.Spec.AllowedOIDCClients, userGroup.Namespace)
		if err != nil {
			return nil, fmt.Errorf("resolve allowed OIDC clients: %w", err)
		}
		for _, id := range directIDs {
			clientIDSet[id] = struct{}{}
		}
	}

	// Reverse: extract status.ClientID from ready OIDCClients that reference this group
	for _, oc := range oidcClients.Items {
		if helpers.IsResourceReady(oc.Status.Conditions) && oc.Status.ClientID != "" {
			clientIDSet[oc.Status.ClientID] = struct{}{}
		}
	}

	clientIDs := make([]string, 0, len(clientIDSet))
	for id := range clientIDSet {
		clientIDs = append(clientIDs, id)
	}
	return clientIDs, nil
}

// setGroupID persists only the group ID to status.
func (r *Reconciler) setGroupID(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, id string) error {
	base := userGroup.DeepCopy()
	userGroup.Status.GroupID = id
	return r.Status().Patch(ctx, userGroup, client.MergeFrom(base))
}

// resolveUsers resolves userRefs, usernames, and userIds to Pocket-ID user IDs.
func (r *Reconciler) resolveUsers(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, apiClient *pocketid.Client) ([]string, error) {
	log := logf.FromContext(ctx)
	users := userGroup.Spec.Users
	if users == nil {
		return nil, nil
	}

	// Deduplicate user IDs
	userIDSet := make(map[string]struct{})

	// PocketIDUser CRs
	if len(users.UserRefs) > 0 {
		refIDs, err := helpers.ResolveUserReferences(ctx, r.Client, users.UserRefs, userGroup.Namespace)
		if err != nil {
			return nil, fmt.Errorf("resolve user references: %w", err)
		}
		for _, id := range refIDs {
			userIDSet[id] = struct{}{}
		}
	}

	// Lookup usernames in the instance
	for _, username := range users.Usernames {
		if username == "" {
			return nil, fmt.Errorf("username cannot be empty")
		}
		userID, err := r.resolveUsername(ctx, apiClient, username)
		if err != nil {
			return nil, fmt.Errorf("resolve username %q: %w", username, err)
		}
		log.V(1).Info("Resolved username to user ID", "username", username, "userID", userID)
		userIDSet[userID] = struct{}{}
	}

	// Add userIds directly
	for _, userID := range users.UserIDs {
		if userID == "" {
			return nil, fmt.Errorf("userId cannot be empty")
		}
		userIDSet[userID] = struct{}{}
	}

	userIDs := make([]string, 0, len(userIDSet))
	for id := range userIDSet {
		userIDs = append(userIDs, id)
	}

	return userIDs, nil
}

// resolveUsername looks up a username in Pocket-ID and returns the user ID.
func (r *Reconciler) resolveUsername(ctx context.Context, apiClient *pocketid.Client, username string) (string, error) {
	users, err := apiClient.ListUsers(ctx, username)
	if err != nil {
		return "", fmt.Errorf("list users: %w", err)
	}

	for _, user := range users {
		if user.Username == username {
			return user.ID, nil
		}
	}

	return "", fmt.Errorf("user with username %q not found in Pocket-ID", username)
}

// clearGroupStatus clears the GroupID from status, triggering recreation on next reconcile.
func (r *Reconciler) clearGroupStatus(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) error {
	return r.ClearStatusField(ctx, userGroup, func() {
		userGroup.Status.GroupID = ""
	})
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
	userGroup.Status.UserIDs = current.UserIDs
	userGroup.Status.CustomClaims = toCustomClaims(current.CustomClaims)
	userGroup.Status.AllowedOIDCClientIDs = current.AllowedOIDCClientIDs
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
	return common.IsReferencedByList(
		ctx,
		r.Client,
		common.OIDCClientAllowedGroupIndexKey,
		groupKey,
		&pocketidinternalv1alpha1.PocketIDOIDCClientList{},
		func(item client.Object) bool {
			oidcClient := item.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
			return oidcClientAllowsGroup(oidcClient, group.Namespace, group.Name)
		},
	)
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
		common.UserGroupUserRefIndexKey: client.ObjectKeyFromObject(user).String(),
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

	seen := make(map[client.ObjectKey]struct{})
	var requests []reconcile.Request

	// Forward: UserGroups referenced in this OIDCClient's spec.allowedUserGroups
	for _, ref := range oidcClient.Spec.AllowedUserGroups {
		if ref.Name == "" {
			continue
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}
		key := client.ObjectKey{Namespace: namespace, Name: ref.Name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			requests = append(requests, reconcile.Request{NamespacedName: key})
		}
	}

	// Reverse: UserGroups whose spec.allowedOIDCClients references this OIDCClient
	clientKey := client.ObjectKeyFromObject(oidcClient).String()
	userGroups := &pocketidinternalv1alpha1.PocketIDUserGroupList{}
	if err := r.List(ctx, userGroups, client.MatchingFields{
		common.UserGroupAllowedOIDCClientIndexKey: clientKey,
	}); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to list user groups for OIDC client", "oidcClient", clientKey)
		return requests
	}
	for i := range userGroups.Items {
		key := client.ObjectKeyFromObject(&userGroups.Items[i])
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			requests = append(requests, reconcile.Request{NamespacedName: key})
		}
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

func userDependencyPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return true },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		GenericFunc: func(event.GenericEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj, okOld := e.ObjectOld.(*pocketidinternalv1alpha1.PocketIDUser)
			newObj, okNew := e.ObjectNew.(*pocketidinternalv1alpha1.PocketIDUser)
			if !okOld || !okNew {
				return true
			}
			if oldObj.Generation != newObj.Generation {
				return true
			}
			if oldObj.Status.UserID != newObj.Status.UserID {
				return true
			}
			return helpers.IsResourceReady(oldObj.Status.Conditions) != helpers.IsResourceReady(newObj.Status.Conditions)
		},
	}
}

func oidcClientDependencyPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return true },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		GenericFunc: func(event.GenericEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj, okOld := e.ObjectOld.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
			newObj, okNew := e.ObjectNew.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
			if !okOld || !okNew {
				return true
			}
			if oldObj.Generation != newObj.Generation {
				return true
			}
			if oldObj.Status.ClientID != newObj.Status.ClientID {
				return true
			}
			return helpers.IsResourceReady(oldObj.Status.Conditions) != helpers.IsResourceReady(newObj.Status.Conditions)
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDUserGroup{}, common.UserGroupUserRefIndexKey, func(raw client.Object) []string {
		userGroup, ok := raw.(*pocketidinternalv1alpha1.PocketIDUserGroup)
		if !ok {
			return nil
		}

		if userGroup.Spec.Users == nil || len(userGroup.Spec.Users.UserRefs) == 0 {
			return nil
		}

		keys := make([]string, 0, len(userGroup.Spec.Users.UserRefs))
		for _, ref := range userGroup.Spec.Users.UserRefs {
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

	if err := mgr.GetFieldIndexer().IndexField(ctx, &pocketidinternalv1alpha1.PocketIDUserGroup{}, common.UserGroupAllowedOIDCClientIndexKey, func(raw client.Object) []string {
		userGroup, ok := raw.(*pocketidinternalv1alpha1.PocketIDUserGroup)
		if !ok {
			return nil
		}

		if len(userGroup.Spec.AllowedOIDCClients) == 0 {
			return nil
		}

		keys := make([]string, 0, len(userGroup.Spec.AllowedOIDCClients))
		for _, ref := range userGroup.Spec.AllowedOIDCClients {
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
		Watches(
			&pocketidinternalv1alpha1.PocketIDUser{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForUser),
			builder.WithPredicates(userDependencyPredicate()),
		).
		Watches(
			&pocketidinternalv1alpha1.PocketIDOIDCClient{},
			handler.EnqueueRequestsFromMapFunc(r.requestsForOIDCClient),
			builder.WithPredicates(oidcClientDependencyPredicate()),
		).
		Named("pocketidusergroup").
		Complete(r)
}
