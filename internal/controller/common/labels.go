package common

import (
	"maps"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ManagedByLabelKey   = "managed-by"
	ManagedByLabelValue = "pocket-id-operator"
)

func ManagedByLabels(labels map[string]string) map[string]string {
	merged := make(map[string]string, len(labels)+1)
	maps.Copy(merged, labels)
	merged[ManagedByLabelKey] = ManagedByLabelValue
	return merged
}

// IsManagedByOperator reports whether obj was created and is managed by this
// operator. The operator stamps every resource it creates with the managed-by
// label, so its absence means the resource was created by someone else (e.g. a
// user's own same-named resource) and must not be deleted during cleanup.
func IsManagedByOperator(obj metav1.Object) bool {
	return obj.GetLabels()[ManagedByLabelKey] == ManagedByLabelValue
}
