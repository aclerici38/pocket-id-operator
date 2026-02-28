// Package metrics defines and registers Prometheus metrics for the pocket-id-operator.
// All metrics use the controller-runtime registry (not prometheus.DefaultRegisterer)
// so they are served on the same /metrics endpoint as controller-runtime's own metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// PocketIDAPIRequests counts calls made to the Pocket-ID API.
	// Labels:
	//
	//	operation - snake_case method name, e.g. "get_user", "create_user"
	//	result    - "success", "not_found", or "error"
	PocketIDAPIRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pocketid_operator_pocketid_api_requests_total",
			Help: "Total number of requests made to the Pocket-ID API, partitioned by operation and result.",
		},
		[]string{"operation", "result"},
	)

	// PocketIDAPIRequestDuration observes the latency of each Pocket-ID API call.
	// Labels:
	//
	//	operation - snake_case method name, e.g. "get_user", "create_user"
	PocketIDAPIRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "pocketid_operator_pocketid_api_request_duration_seconds",
			Help:    "Duration of requests made to the Pocket-ID API in seconds, partitioned by operation.",
			Buckets: append([]float64{0.001}, prometheus.DefBuckets...),
		},
		[]string{"operation"},
	)

	// ResourceOperations counts meaningful CRUD events at the Pocket-ID resource level.
	// Labels:
	//
	//	kind      - "PocketIDUser", "PocketIDUserGroup", "PocketIDOIDCClient"
	//	operation - "created", "adopted", "updated", "deleted"
	ResourceOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pocketid_operator_resource_operations_total",
			Help: "Total number of create/adopt/update/delete operations performed on Pocket-ID resources.",
		},
		[]string{"kind", "operation"},
	)

	// ResourceReady tracks the current readiness of each managed resource.
	// Value is 1 when the Ready condition is True, 0 otherwise.
	// Labels:
	//
	//	kind      - "PocketIDUser", "PocketIDUserGroup", "PocketIDOIDCClient", "PocketIDInstance"
	//	namespace - Kubernetes namespace of the resource
	//	name      - Kubernetes name of the resource
	ResourceReady = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_resource_ready",
			Help: "Whether the managed resource has its Ready condition set to True (1) or not (0).",
		},
		[]string{"kind", "namespace", "name"},
	)

	// APIKeyOperations counts API key lifecycle events within the user controller.
	// Labels:
	//
	//	instance_namespace - namespace of the PocketIDInstance
	//	instance_name      - name of the PocketIDInstance
	//	operation          - "created" or "deleted"
	APIKeyOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pocketid_operator_api_key_operations_total",
			Help: "Total number of API key create/delete operations performed for PocketIDUser resources.",
		},
		[]string{"instance_namespace", "instance_name", "operation"},
	)

	// ExternalDeletions counts resources that were deleted from Pocket-ID outside
	// the operator (i.e., detected during reconcile when a GET returns 404 for a
	// resource that should exist). The operator will recreate the resource.
	// Labels:
	//
	//	kind - "PocketIDUser", "PocketIDUserGroup", "PocketIDOIDCClient"
	ExternalDeletions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pocketid_operator_external_deletions_total",
			Help: "Total number of resources found to have been deleted in Pocket-ID outside the operator, triggering recreation.",
		},
		[]string{"kind"},
	)

	// InstanceInfo exposes metadata about each managed PocketIDInstance as a gauge
	// that is always 1. Use label values to identify version and deployment type.
	// Labels:
	//
	//	namespace       - Kubernetes namespace of the PocketIDInstance
	//	name            - Kubernetes name of the PocketIDInstance
	//	version         - Pocket-ID version string (e.g. "v2.3.0"), empty if not yet fetched
	//	deployment_type - "Deployment" or "StatefulSet"
	//	app_url         - value of spec.appUrl, empty if not set
	InstanceInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_instance_info",
			Help: "Information about a managed PocketIDInstance. Value is always 1; use labels to identify the instance.",
		},
		[]string{"namespace", "name", "version", "deployment_type", "app_url"},
	)

	// UserGroupMemberCount tracks the current number of members in each user group
	// as reported by the Pocket-ID API.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDUserGroup
	//	name      - Kubernetes name of the PocketIDUserGroup
	UserGroupMemberCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_usergroup_member_count",
			Help: "Current number of members in a PocketIDUserGroup as reported by the Pocket-ID API.",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientAllowedGroupCount tracks the current number of user groups allowed
	// to access each OIDC client, as resolved by the operator during reconcile.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientAllowedGroupCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_allowed_group_count",
			Help: "Current number of user groups allowed to access a PocketIDOIDCClient.",
		},
		[]string{"namespace", "name"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		PocketIDAPIRequests,
		PocketIDAPIRequestDuration,
		ResourceOperations,
		ResourceReady,
		APIKeyOperations,
		ExternalDeletions,
		InstanceInfo,
		UserGroupMemberCount,
		OIDCClientAllowedGroupCount,
	)
}

// RecordReadiness updates the ResourceReady gauge for a resource.
// ready=true sets the gauge to 1.0 (Ready), ready=false sets it to 0.0.
func RecordReadiness(kind, namespace, name string, ready bool) {
	val := 0.0
	if ready {
		val = 1.0
	}
	ResourceReady.WithLabelValues(kind, namespace, name).Set(val)
}

// DeleteReadinessGauge removes the ResourceReady gauge entry for a resource.
// Call this when a resource is fully deleted to avoid stale gauge values.
func DeleteReadinessGauge(kind, namespace, name string) {
	ResourceReady.DeleteLabelValues(kind, namespace, name)
}

// RecordInstanceInfo sets the InstanceInfo gauge for an instance to 1.
// oldVersion should be the previous version label value (may be empty) so that
// stale label sets from a version change can be deleted before writing the new one.
func RecordInstanceInfo(namespace, name, oldVersion, newVersion, deploymentType, appURL string) {
	if oldVersion != newVersion && oldVersion != "" {
		InstanceInfo.DeleteLabelValues(namespace, name, oldVersion, deploymentType, appURL)
	}
	InstanceInfo.WithLabelValues(namespace, name, newVersion, deploymentType, appURL).Set(1)
}

// DeleteInstanceInfo removes the InstanceInfo gauge entry for an instance.
// Call this when a PocketIDInstance is deleted.
func DeleteInstanceInfo(namespace, name, version, deploymentType, appURL string) {
	InstanceInfo.DeleteLabelValues(namespace, name, version, deploymentType, appURL)
}

// DeleteUserGroupMemberCount removes the UserGroupMemberCount gauge entry for a group.
// Call this when a PocketIDUserGroup is deleted.
func DeleteUserGroupMemberCount(namespace, name string) {
	UserGroupMemberCount.DeleteLabelValues(namespace, name)
}

// DeleteOIDCClientAllowedGroupCount removes the OIDCClientAllowedGroupCount gauge entry for a client.
// Call this when a PocketIDOIDCClient is deleted.
func DeleteOIDCClientAllowedGroupCount(namespace, name string) {
	OIDCClientAllowedGroupCount.DeleteLabelValues(namespace, name)
}
