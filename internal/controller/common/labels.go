package common
import "maps"

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
