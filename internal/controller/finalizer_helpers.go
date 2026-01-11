package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FinalizerUpdate represents a finalizer that should be added or removed
type FinalizerUpdate struct {
	Name      string
	ShouldAdd bool
}

// ReconcileFinalizers manages multiple finalizers in a single update.
// Returns true if an update was performed, false otherwise.
func ReconcileFinalizers(ctx context.Context, c client.Client, obj client.Object, updates []FinalizerUpdate) (bool, error) {
	needsUpdate := false

	for _, update := range updates {
		hasFinalizer := controllerutil.ContainsFinalizer(obj, update.Name)

		if update.ShouldAdd && !hasFinalizer {
			controllerutil.AddFinalizer(obj, update.Name)
			needsUpdate = true
		} else if !update.ShouldAdd && hasFinalizer {
			controllerutil.RemoveFinalizer(obj, update.Name)
			needsUpdate = true
		}
	}

	if !needsUpdate {
		return false, nil
	}

	if err := c.Update(ctx, obj); err != nil {
		if errors.IsConflict(err) {
			return true, nil // Signal a requeue
		}
		return false, err
	}

	return true, nil
}

// EnsureFinalizer adds a single finalizer if it doesn't exist.
// Returns true if an update was performed, false otherwise.
func EnsureFinalizer(ctx context.Context, c client.Client, obj client.Object, finalizerName string) (bool, error) {
	if controllerutil.ContainsFinalizer(obj, finalizerName) {
		return false, nil
	}

	controllerutil.AddFinalizer(obj, finalizerName)
	if err := c.Update(ctx, obj); err != nil {
		if errors.IsConflict(err) {
			return true, nil
		}
		return false, err
	}

	return true, nil
}

// RemoveFinalizers removes multiple finalizers in a single update.
func RemoveFinalizers(ctx context.Context, c client.Client, obj client.Object, finalizerNames ...string) error {
	needsUpdate := false

	for _, name := range finalizerNames {
		if controllerutil.ContainsFinalizer(obj, name) {
			controllerutil.RemoveFinalizer(obj, name)
			needsUpdate = true
		}
	}

	if !needsUpdate {
		return nil
	}

	return c.Update(ctx, obj)
}
