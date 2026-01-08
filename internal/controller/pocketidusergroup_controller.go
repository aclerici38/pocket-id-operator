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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const userGroupFinalizer = "pocketid.internal/user-group-finalizer"

// PocketIDUserGroupReconciler reconciles a PocketIDUserGroup object
type PocketIDUserGroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusergroups/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch
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

	userGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := r.Get(ctx, req.NamespacedName, userGroup); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDUserGroup", "name", userGroup.Name)

	if !userGroup.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, userGroup)
	}

	if !controllerutil.ContainsFinalizer(userGroup, userGroupFinalizer) {
		controllerutil.AddFinalizer(userGroup, userGroupFinalizer)
		if err := r.Update(ctx, userGroup); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	instance, err := selectInstance(ctx, r.Client, userGroup.Spec.InstanceSelector)
	if err != nil {
		log.Error(err, "Failed to select PocketIDInstance")
		r.setReadyCondition(ctx, userGroup, metav1.ConditionFalse, "InstanceSelectionError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if !instanceReady(instance) {
		log.Info("PocketIDInstance not ready, requeuing")
		r.setReadyCondition(ctx, userGroup, metav1.ConditionFalse, "InstanceNotReady", "Waiting for PocketIDInstance to be ready")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	apiClient, err := apiClientForInstance(ctx, r.Client, instance)
	if err != nil {
		log.Error(err, "Failed to get API client")
		r.setReadyCondition(ctx, userGroup, metav1.ConditionFalse, "APIClientError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	current, err := r.reconcileUserGroup(ctx, userGroup, apiClient)
	if err != nil {
		log.Error(err, "Failed to reconcile user group")
		r.setReadyCondition(ctx, userGroup, metav1.ConditionFalse, "ReconcileError", err.Error())
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if err := r.updateUserGroupStatus(ctx, userGroup, current); err != nil {
		log.Error(err, "Failed to update user group status")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	r.setReadyCondition(ctx, userGroup, metav1.ConditionTrue, "Reconciled", "User group is in sync")

	return ctrl.Result{}, nil
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
			return nil, err
		}
		if err := apiClient.UpdateUserGroupUsers(ctx, current.ID, userIDs); err != nil {
			return nil, err
		}
	}

	latest, err := apiClient.GetUserGroup(ctx, current.ID)
	if err != nil {
		return nil, err
	}

	return latest, nil
}

func (r *PocketIDUserGroupReconciler) resolveUserRefs(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) ([]string, error) {
	userIDs := make([]string, 0, len(userGroup.Spec.UserRefs))
	for _, ref := range userGroup.Spec.UserRefs {
		if ref.Name == "" {
			return nil, fmt.Errorf("userRefs contains an empty name")
		}
		namespace := ref.Namespace
		if namespace == "" {
			namespace = userGroup.Namespace
		}
		user := &pocketidinternalv1alpha1.PocketIDUser{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, user); err != nil {
			return nil, fmt.Errorf("get user %s: %w", ref.Name, err)
		}
		if user.Status.UserID == "" {
			return nil, fmt.Errorf("user %s is not ready", ref.Name)
		}
		userIDs = append(userIDs, user.Status.UserID)
	}
	return userIDs, nil
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

func (r *PocketIDUserGroupReconciler) setReadyCondition(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup, status metav1.ConditionStatus, reason, message string) {
	base := userGroup.DeepCopy()
	meta.SetStatusCondition(&userGroup.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: userGroup.Generation,
	})
	if err := r.Status().Patch(ctx, userGroup, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "Failed to update condition")
	}
}

func (r *PocketIDUserGroupReconciler) reconcileDelete(ctx context.Context, userGroup *pocketidinternalv1alpha1.PocketIDUserGroup) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if userGroup.Status.GroupID != "" {
		instance, err := selectInstance(ctx, r.Client, userGroup.Spec.InstanceSelector)
		if err != nil {
			if errors.Is(err, errNoInstance) {
				log.Info("No PocketIDInstance found; skipping Pocket-ID deletion", "groupID", userGroup.Status.GroupID)
			} else {
				log.Error(err, "Failed to select PocketIDInstance for delete")
				return ctrl.Result{}, err
			}
		} else {
			apiClient, err := apiClientForInstance(ctx, r.Client, instance)
			if err != nil {
				log.Error(err, "Failed to get API client for delete")
				return ctrl.Result{}, err
			}
			log.Info("Deleting user group from Pocket-ID", "groupID", userGroup.Status.GroupID)
			if err := apiClient.DeleteUserGroup(ctx, userGroup.Status.GroupID); err != nil {
				log.Error(err, "Failed to delete user group from Pocket-ID")
				return ctrl.Result{}, err
			}
		}
	}

	controllerutil.RemoveFinalizer(userGroup, userGroupFinalizer)
	if err := r.Update(ctx, userGroup); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDUserGroup{}).
		Named("pocketidusergroup").
		Complete(r)
}
