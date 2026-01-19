package helpers

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func HasAnnotation(obj client.Object, annotationKey string, expectedValue string) bool {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return false
	}
	return annotations[annotationKey] == expectedValue
}

// RemoveAnnotation removes an annotation and updates the object.
// Returns true if the annotation was found and removed, false if it didn't exist.
func RemoveAnnotation(ctx context.Context, c client.Client, obj client.Object, annotationKey string) (bool, error) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return false, nil
	}

	if _, exists := annotations[annotationKey]; !exists {
		return false, nil
	}

	delete(annotations, annotationKey)
	obj.SetAnnotations(annotations)

	if err := c.Update(ctx, obj); err != nil {
		return false, err
	}

	return true, nil
}

// CheckAndRemoveAnnotation checks if an annotation exists with a specific value,
// and removes it if found, updating the object.
// Returns true if the annotation was found and removed.
func CheckAndRemoveAnnotation(
	ctx context.Context,
	c client.Client,
	obj client.Object,
	annotationKey string,
	expectedValue string,
) (bool, error) {
	if !HasAnnotation(obj, annotationKey, expectedValue) {
		return false, nil
	}

	return RemoveAnnotation(ctx, c, obj, annotationKey)
}
