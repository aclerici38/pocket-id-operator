package controller

const (
	ManagedByLabelKey   = "managed-by"
	ManagedByLabelValue = "pocket-id-operator"
)

func managedByLabels(labels map[string]string) map[string]string {
	merged := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		merged[key] = value
	}
	merged[ManagedByLabelKey] = ManagedByLabelValue
	return merged
}
