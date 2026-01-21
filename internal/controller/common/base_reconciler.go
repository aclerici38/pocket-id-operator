package common

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
	logf "sigs.k8s.io/controller-runtime/pkg/log"

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
	APIReader client.Reader
}

// EnsureClient sets the base client if it hasn't been initialized.
func (r *BaseReconciler) EnsureClient(fallback client.Client) {
	if r.Client == nil {
		r.Client = fallback
	}
}

// SetReadyCondition updates the Ready condition on a resource
func (r *BaseReconciler) SetReadyCondition(ctx context.Context, obj ConditionedResource, status metav1.ConditionStatus, reason, message string) error {
	logger := logf.FromContext(ctx)

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
	if !InstanceReady(instance) {
		_ = r.SetReadyCondition(ctx, obj, metav1.ConditionFalse, "InstanceNotReady",
			fmt.Sprintf("Waiting for PocketID instance '%s/%s' to be ready", instance.Namespace, instance.Name))
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
	logger := logf.FromContext(ctx)

	apiClient, err := GetAPIClient(ctx, r.Client, r.APIReader, instance)
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
	logger := logf.FromContext(ctx)

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
	instance, err := SelectInstance(ctx, r.Client, instanceSelector)
	if err != nil {
		if stderrors.Is(err, ErrNoInstance) {
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
	apiClient, err := GetAPIClient(ctx, r.Client, r.APIReader, instance)
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

// CreateOrAdoptResult contains the result of a create-or-adopt operation.
type CreateOrAdoptResult[T any] struct {
	// Resource is the created or adopted resource from Pocket-ID
	Resource T
	// IsNewlyCreated is true if the resource was newly created (not adopted)
	IsNewlyCreated bool
}

// CreateOrAdoptConfig contains the configuration for a create-or-adopt operation.
type CreateOrAdoptConfig[T any] struct {
	// ResourceKind is the human-readable kind name for logging (e.g., "user", "OIDC client")
	ResourceKind string
	// ResourceID is the identifier for logging (e.g., username, clientID)
	ResourceID string
	// Create attempts to create the resource and returns the created resource
	Create func() (T, error)
	// Update attempts to update the resource and returns the updated resource
	Update func() (T, error)
	// FindExisting attempts to find an existing resource for adoption
	FindExisting func() (T, error)
	// ClearStatus clears the status ID to trigger recreation on next reconcile
	ClearStatus func() error
	// IsNil checks if the resource is nil (for generic nil checking)
	IsNil func(T) bool
}

// CreateOrAdopt implements the common create-or-adopt pattern for Pocket-ID resources.
// If statusID is empty, it tries to create the resource. If creation fails with "already exists",
// it attempts to find and adopt the existing resource.
// If statusID is not empty, it tries to update the resource. If update fails with "not found",
// it clears the status to trigger recreation on next reconcile.
func CreateOrAdopt[T any](ctx context.Context, statusID string, config CreateOrAdoptConfig[T]) (*CreateOrAdoptResult[T], error) {
	log := logf.FromContext(ctx)

	var zero T
	if statusID == "" {
		// Try to create first, then fallback to adopting if it already exists
		log.Info(fmt.Sprintf("Creating %s in Pocket-ID", config.ResourceKind), "id", config.ResourceID)
		resource, err := config.Create()
		if err != nil {
			if pocketid.IsAlreadyExistsError(err) {
				log.Info(fmt.Sprintf("%s already exists in Pocket-ID, attempting to adopt", config.ResourceKind), "id", config.ResourceID)
				existing, findErr := config.FindExisting()
				if findErr != nil {
					return nil, fmt.Errorf("find existing %s after create conflict: %w", config.ResourceKind, findErr)
				}
				if config.IsNil(existing) {
					return nil, fmt.Errorf("create %s failed with conflict but could not find existing: %w", config.ResourceKind, err)
				}
				log.Info(fmt.Sprintf("Adopting existing %s from Pocket-ID", config.ResourceKind), "id", config.ResourceID)
				return &CreateOrAdoptResult[T]{Resource: existing, IsNewlyCreated: false}, nil
			}
			return nil, fmt.Errorf("create %s: %w", config.ResourceKind, err)
		}
		return &CreateOrAdoptResult[T]{Resource: resource, IsNewlyCreated: true}, nil
	}

	// Update existing resource
	log.Info(fmt.Sprintf("Updating %s in Pocket-ID", config.ResourceKind), "id", config.ResourceID)
	resource, err := config.Update()
	if err != nil {
		if pocketid.IsNotFoundError(err) {
			log.Info(fmt.Sprintf("%s was deleted externally, will recreate", config.ResourceKind), "statusID", statusID)
			if clearErr := config.ClearStatus(); clearErr != nil {
				return nil, fmt.Errorf("clear status after external deletion: %w", clearErr)
			}
			return &CreateOrAdoptResult[T]{Resource: zero, IsNewlyCreated: false}, nil
		}
		return nil, fmt.Errorf("update %s: %w", config.ResourceKind, err)
	}
	return &CreateOrAdoptResult[T]{Resource: resource, IsNewlyCreated: false}, nil
}

// ClearStatusField clears a status field on an object using a patch.
func (r *BaseReconciler) ClearStatusField(ctx context.Context, obj client.Object, clearFunc func()) error {
	base := obj.DeepCopyObject().(client.Object)
	clearFunc()
	return r.Status().Patch(ctx, obj, client.MergeFrom(base))
}

// IsReferencedByList checks if a resource is referenced by any item in a list.
//
// Parameters:
//   - ctx: context for the operation
//   - c: the client to use for listing
//   - indexKey: the field index key to try first (e.g., common.UserGroupUserRefIndexKey)
//   - indexValue: the value to match in the index (e.g., "namespace/name")
//   - list: an empty ObjectList to populate (e.g., &PocketIDUserGroupList{})
//   - predicate: a function that checks if a single item references the resource
func IsReferencedByList(
	ctx context.Context,
	c client.Client,
	indexKey string,
	indexValue string,
	list client.ObjectList,
	predicate func(item client.Object) bool,
) (bool, error) {
	if err := c.List(ctx, list, client.MatchingFields{indexKey: indexValue}); err == nil {
		items, err := meta.ExtractList(list)
		if err != nil {
			return false, err
		}
		return len(items) > 0, nil
	}

	if err := c.List(ctx, list); err != nil {
		return false, err
	}

	items, err := meta.ExtractList(list)
	if err != nil {
		return false, err
	}

	for _, item := range items {
		if predicate(item.(client.Object)) {
			return true, nil
		}
	}

	return false, nil
}

// InstanceReady checks if a PocketIDInstance has the Ready condition set to True
func InstanceReady(instance *pocketidv1alpha1.PocketIDInstance) bool {
	for _, cond := range instance.Status.Conditions {
		if cond.Type == "Ready" && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

var (
	ErrNoInstance       = stderrors.New("no PocketIDInstance found")
	ErrMultipleInstance = stderrors.New("multiple PocketIDInstances found")
)

// SelectInstance finds a PocketIDInstance by label selector
func SelectInstance(ctx context.Context, c client.Client, selector *metav1.LabelSelector) (*pocketidv1alpha1.PocketIDInstance, error) {
	instances := &pocketidv1alpha1.PocketIDInstanceList{}
	listOpts := []client.ListOption{}

	selectorString := "default instance"
	if selector != nil {
		parsed, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return nil, fmt.Errorf("invalid instanceSelector: %w", err)
		}
		selectorString = parsed.String()
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: parsed})
	}

	if err := c.List(ctx, instances, listOpts...); err != nil {
		return nil, err
	}

	if len(instances.Items) == 0 {
		return nil, fmt.Errorf("%w for selector %q", ErrNoInstance, selectorString)
	}
	if len(instances.Items) > 1 {
		return nil, fmt.Errorf("%w for selector %q", ErrMultipleInstance, selectorString)
	}

	return &instances.Items[0], nil
}
