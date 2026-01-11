package controller

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// ConditionedResource represents any resource that has status conditions
type ConditionedResource interface {
	client.Object
	GetConditions() *[]metav1.Condition
}

// BaseReconciler provides common reconciliation utilities for all controllers
type BaseReconciler struct {
	client.Client
}

// EnsureClient sets the base client if it hasn't been initialized.
func (r *BaseReconciler) EnsureClient(fallback client.Client) {
	if r.Client == nil {
		r.Client = fallback
	}
}

// SetReadyCondition updates the Ready condition on a resource
func (r *BaseReconciler) SetReadyCondition(ctx context.Context, obj ConditionedResource, status metav1.ConditionStatus, reason, message string) error {
	logger := log.FromContext(ctx)

	base := obj.DeepCopyObject().(client.Object)

	meta.SetStatusCondition(obj.GetConditions(), metav1.Condition{
		Type:               "Ready",
		Status:             status,
		ObservedGeneration: obj.GetGeneration(),
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})

	if err := r.Status().Patch(ctx, obj, client.MergeFrom(base)); err != nil {
		logger.Error(err, "Failed to update status condition")
		return err
	}

	return nil
}

// InstanceValidationResult contains the result of instance validation
type InstanceValidationResult struct {
	Instance      *pocketidv1alpha1.PocketIDInstance
	ShouldRequeue bool
	RequeueAfter  time.Duration
	Error         error
}

// ValidateInstanceReady performs the common instance validation flow
func (r *BaseReconciler) ValidateInstanceReady(ctx context.Context, obj ConditionedResource, instance *pocketidv1alpha1.PocketIDInstance) *InstanceValidationResult {
	if !instanceReady(instance) {
		_ = r.SetReadyCondition(ctx, obj, metav1.ConditionFalse, "InstanceNotReady",
			fmt.Sprintf("Waiting for PocketID instance '%s/%s' to be ready", instance.Namespace, instance.Name))
		return &InstanceValidationResult{
			Instance:      instance,
			ShouldRequeue: true,
			RequeueAfter:  Requeue,
		}
	}

	if !instance.Status.Bootstrapped {
		_ = r.SetReadyCondition(ctx, obj, metav1.ConditionFalse, "InstanceNotBootstrapped",
			fmt.Sprintf("Waiting for PocketID instance '%s/%s' to be bootstrapped", instance.Namespace, instance.Name))
		return &InstanceValidationResult{
			Instance:      instance,
			ShouldRequeue: true,
			RequeueAfter:  Requeue,
		}
	}

	return &InstanceValidationResult{
		Instance:      instance,
		ShouldRequeue: false,
	}
}

// GetAPIClientOrWait retrieves an API client for the instance from the pool
// The returned client has rate limiting applied at the HTTP transport layer.
func (r *BaseReconciler) GetAPIClientOrWait(ctx context.Context, obj ConditionedResource, instance *pocketidv1alpha1.PocketIDInstance) (*pocketid.Client, *ctrl.Result, error) {
	logger := log.FromContext(ctx)

	apiClient, err := GetAPIClient(ctx, r.Client, instance)
	if err != nil {
		if stderrors.Is(err, ErrAPIClientNotReady) {
			logger.Info("API client not ready, requeuing")
			_ = r.SetReadyCondition(ctx, obj, metav1.ConditionFalse, "APIClientNotReady",
				fmt.Sprintf("Waiting for API client for instance '%s/%s'", instance.Namespace, instance.Name))
			return nil, &ctrl.Result{RequeueAfter: Requeue}, nil
		}

		logger.Error(err, "Failed to get API client")
		_ = r.SetReadyCondition(ctx, obj, metav1.ConditionFalse, "APIClientError", err.Error())
		return nil, &ctrl.Result{RequeueAfter: Requeue}, err
	}

	return apiClient, nil, nil
}

// DeleteFromPocketIDFunc is a function that deletes a resource from PocketID by ID
type DeleteFromPocketIDFunc func(ctx context.Context, apiClient *pocketid.Client, id string) error

// removeFinalizer removes a finalizer from an object and updates it
func removeFinalizer(ctx context.Context, c client.Client, obj client.Object, finalizerName string) error {
	if !controllerutil.ContainsFinalizer(obj, finalizerName) {
		return nil
	}

	controllerutil.RemoveFinalizer(obj, finalizerName)
	return c.Update(ctx, obj)
}

// ReconcileDeleteWithPocketID provides a common deletion pattern for PocketID-backed resources
// statusID: the ID of the resource in PocketID (from status field)
// instanceSelector: the label selector for finding the PocketIDInstance
// finalizerName: the name of the finalizer to remove
// deleteFunc: the function to call to delete the resource from PocketID
func (r *BaseReconciler) ReconcileDeleteWithPocketID(
	ctx context.Context,
	obj client.Object,
	statusID string,
	instanceSelector *metav1.LabelSelector,
	finalizerName string,
	deleteFunc DeleteFromPocketIDFunc,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// If no ID in status, resource was never created in PocketID
	if statusID == "" {
		logger.Info("No status ID found, removing finalizer without API call")
		if err := removeFinalizer(ctx, r.Client, obj, finalizerName); err != nil {
			logger.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Select the instance
	instance, err := selectInstance(ctx, r.Client, instanceSelector)
	if err != nil {
		if stderrors.Is(err, errNoInstance) {
			logger.Info("No PocketIDInstance found, removing finalizer without API call", "statusID", statusID)
			if err := removeFinalizer(ctx, r.Client, obj, finalizerName); err != nil {
				logger.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to select instance")
		return ctrl.Result{}, err
	}

	// Get API client from pool
	apiClient, err := GetAPIClient(ctx, r.Client, instance)
	if err != nil {
		if stderrors.Is(err, ErrAPIClientNotReady) {
			logger.Info("API client not ready for delete, requeuing", "statusID", statusID)
			return ctrl.Result{RequeueAfter: Requeue}, nil
		}
		logger.Error(err, "Failed to get API client for delete")
		return ctrl.Result{}, err
	}

	// Delete from PocketID
	logger.Info("Deleting from PocketID", "statusID", statusID)
	if err := deleteFunc(ctx, apiClient, statusID); err != nil {
		logger.Error(err, "Failed to delete from PocketID")
		return ctrl.Result{}, err
	}

	// Remove finalizer
	if err := removeFinalizer(ctx, r.Client, obj, finalizerName); err != nil {
		logger.Error(err, "Failed to remove finalizer")
		return ctrl.Result{}, err
	}

	logger.Info("Successfully deleted")
	return ctrl.Result{}, nil
}
