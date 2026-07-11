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

	// OIDCClientPKCESupported tracks whether Pocket-ID has flagged an OIDC client as using PKCE
	// while spec.pkceEnabled is false. Value is 1 when PKCE can be enabled, 0 otherwise.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientPKCESupported = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_pkce_supported",
			Help: "Whether Pocket-ID observed a PocketIDOIDCClient using PKCE while pkceEnabled is false (1) or not (0).",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientRotationEnabled tracks whether scheduled client-secret rotation is enabled
	// for each OIDC client. Value is 1 when spec.clientSecretRotation.enabled is true, 0 otherwise.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientRotationEnabled = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_rotation_enabled",
			Help: "Whether scheduled client-secret rotation is enabled (1) or not (0) for a PocketIDOIDCClient.",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientRotationIntervalSeconds exposes the configured rotation interval in seconds.
	// Only set while rotation is enabled; removed when rotation is disabled.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientRotationIntervalSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_rotation_interval_seconds",
			Help: "Configured client-secret rotation interval in seconds for a PocketIDOIDCClient.",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientLastRotationTimestamp exposes the Unix timestamp (seconds) of the most recent
	// client-secret rotation, read from the managed secret's annotation. Only set while rotation
	// is enabled; removed when rotation is disabled.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientLastRotationTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_last_rotation_timestamp_seconds",
			Help: "Unix timestamp (seconds) of the most recent client-secret rotation for a PocketIDOIDCClient.",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientNextRotationTimestamp exposes the Unix timestamp (seconds) at which the client
	// secret next becomes eligible for rotation (rotation anchor + interval). The actual rotation
	// may still be delayed by the maintenance window or instance-wide min-spacing. Only set while
	// rotation is enabled; removed when rotation is disabled.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientNextRotationTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_next_rotation_timestamp_seconds",
			Help: "Unix timestamp (seconds) at which a PocketIDOIDCClient secret next becomes eligible for rotation.",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientRotationWindowOpen tracks whether a client's maintenance window is currently open.
	// Value is 1 while now falls inside the recurring window, 0 otherwise. Only set for enabled
	// clients that configure spec.clientSecretRotation.window; removed otherwise.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientRotationWindowOpen = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_rotation_window_open",
			Help: "Whether a PocketIDOIDCClient maintenance window is currently open (1) or closed (0).",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientRotationWindowNextOpenTimestamp exposes the Unix timestamp (seconds) at which the
	// maintenance window next opens. Only set for enabled clients that configure a window.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientRotationWindowNextOpenTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_rotation_window_next_open_timestamp_seconds",
			Help: "Unix timestamp (seconds) at which a PocketIDOIDCClient maintenance window next opens.",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientRotationWindowNextCloseTimestamp exposes the Unix timestamp (seconds) at which the
	// maintenance window next closes: the close of the currently-open window, or of the next window
	// to open when currently closed. Only set for enabled clients that configure a window.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	OIDCClientRotationWindowNextCloseTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "pocketid_operator_oidcclient_rotation_window_next_close_timestamp_seconds",
			Help: "Unix timestamp (seconds) at which a PocketIDOIDCClient maintenance window next closes.",
		},
		[]string{"namespace", "name"},
	)

	// OIDCClientSecretRotations counts client-secret rotation attempts that actually reached the
	// Pocket-ID regenerate call (i.e. the operator decided to rotate), partitioned by outcome and
	// what triggered them.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	//	result    - "success" or "error"
	//	trigger   - "scheduled", "manual", or "initial"
	OIDCClientSecretRotations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pocketid_operator_oidcclient_secret_rotations_total",
			Help: "Total client-secret rotations performed, partitioned by result and trigger.",
		},
		[]string{"namespace", "name", "result", "trigger"},
	)

	// OIDCClientRotationDeferred counts occasions where a scheduled rotation was due (its interval
	// had elapsed, or a maintenance window opened) but a downstream gate prevented it from firing.
	// Labels:
	//
	//	namespace - Kubernetes namespace of the PocketIDOIDCClient
	//	name      - Kubernetes name of the PocketIDOIDCClient
	//	reason    - "window_closed" (interval-driven, waiting for its window), "window_missed"
	//	            (window-driven, an opening passed unserved), "min_spacing", or "window_error"
	OIDCClientRotationDeferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pocketid_operator_oidcclient_rotation_deferred_total",
			Help: "Total times a due client-secret rotation was deferred, partitioned by reason.",
		},
		[]string{"namespace", "name", "reason"},
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
		OIDCClientPKCESupported,
		OIDCClientRotationEnabled,
		OIDCClientRotationIntervalSeconds,
		OIDCClientLastRotationTimestamp,
		OIDCClientNextRotationTimestamp,
		OIDCClientRotationWindowOpen,
		OIDCClientRotationWindowNextOpenTimestamp,
		OIDCClientRotationWindowNextCloseTimestamp,
		OIDCClientSecretRotations,
		OIDCClientRotationDeferred,
	)

	// Init ExternalDeletions to 0 so increase() works in rules
	for _, kind := range []string{"PocketIDUser", "PocketIDUserGroup", "PocketIDOIDCClient"} {
		ExternalDeletions.WithLabelValues(kind).Add(0)
	}
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

// SetOIDCClientPKCESupported records whether Pocket-ID has flagged the client as PKCE-supported.
func SetOIDCClientPKCESupported(namespace, name string, supported bool) {
	val := 0.0
	if supported {
		val = 1.0
	}
	OIDCClientPKCESupported.WithLabelValues(namespace, name).Set(val)
}

// DeleteOIDCClientPKCESupported removes the OIDCClientPKCESupported gauge entry for a client.
// Call this when a PocketIDOIDCClient is deleted.
func DeleteOIDCClientPKCESupported(namespace, name string) {
	OIDCClientPKCESupported.DeleteLabelValues(namespace, name)
}

// rotationResults and rotationTriggers enumerate the label values of the secret-rotation counter
// so its series can be pre-initialised to 0.
var (
	rotationResults  = []string{"success", "error"}
	rotationTriggers = []string{"scheduled", "manual", "initial"}
)

// InitOIDCClientRotationCounters ensures the OIDCClientSecretRotations series exist at 0 for every
// result/trigger combination of a client. Without this, a client's first rotation of a given kind
// is born as a fresh series at value 1, and increase()/rate() cannot measure a step that has no
// prior sample — so that first rotation is silently dropped from event timelines and rate-based
// alerts (e.g. a one-off manual rotation never appears). Pre-seeding 0 makes it a visible 0→1 step.
// Safe to call every reconcile; Add(0) is a no-op once a series exists.
func InitOIDCClientRotationCounters(namespace, name string) {
	for _, result := range rotationResults {
		for _, trigger := range rotationTriggers {
			OIDCClientSecretRotations.WithLabelValues(namespace, name, result, trigger).Add(0)
		}
	}
}

// SetOIDCClientRotationEnabled records whether scheduled rotation is enabled for a client.
func SetOIDCClientRotationEnabled(namespace, name string, enabled bool) {
	val := 0.0
	if enabled {
		val = 1.0
	}
	OIDCClientRotationEnabled.WithLabelValues(namespace, name).Set(val)
}

// SetOIDCClientRotationSchedule records the rotation schedule gauges for an enabled client:
// the configured interval, the last rotation timestamp, and the next-eligible timestamp
// (all in seconds). A non-positive value means the gauge does not apply (e.g. intervalSeconds
// and nextUnix for a window-driven client, or lastUnix when the client has never rotated); the
// corresponding series is deleted rather than left stale, so a client that switches modes (e.g.
// interval-driven to window-driven) does not keep exporting an obsolete value.
func SetOIDCClientRotationSchedule(namespace, name string, intervalSeconds, lastUnix, nextUnix float64) {
	setOrDelete(OIDCClientRotationIntervalSeconds, namespace, name, intervalSeconds)
	setOrDelete(OIDCClientLastRotationTimestamp, namespace, name, lastUnix)
	setOrDelete(OIDCClientNextRotationTimestamp, namespace, name, nextUnix)
}

// setOrDelete sets the gauge for (namespace, name) when value is positive, otherwise deletes the
// series so a no-longer-applicable value does not linger.
func setOrDelete(gauge *prometheus.GaugeVec, namespace, name string, value float64) {
	if value > 0 {
		gauge.WithLabelValues(namespace, name).Set(value)
		return
	}
	gauge.DeleteLabelValues(namespace, name)
}

// SetOIDCClientRotationWindow records the maintenance window gauges for a client: whether the
// window is currently open, when it next opens, and when it next closes (Unix seconds). Pass a
// non-positive nextOpenUnix or nextCloseUnix to skip the corresponding gauge.
func SetOIDCClientRotationWindow(namespace, name string, open bool, nextOpenUnix, nextCloseUnix float64) {
	val := 0.0
	if open {
		val = 1.0
	}
	OIDCClientRotationWindowOpen.WithLabelValues(namespace, name).Set(val)
	if nextOpenUnix > 0 {
		OIDCClientRotationWindowNextOpenTimestamp.WithLabelValues(namespace, name).Set(nextOpenUnix)
	}
	if nextCloseUnix > 0 {
		OIDCClientRotationWindowNextCloseTimestamp.WithLabelValues(namespace, name).Set(nextCloseUnix)
	}
}

// DeleteOIDCClientRotationWindow removes the maintenance window gauges for a client. Used when
// the client has no window configured (or its window config is invalid).
func DeleteOIDCClientRotationWindow(namespace, name string) {
	OIDCClientRotationWindowOpen.DeleteLabelValues(namespace, name)
	OIDCClientRotationWindowNextOpenTimestamp.DeleteLabelValues(namespace, name)
	OIDCClientRotationWindowNextCloseTimestamp.DeleteLabelValues(namespace, name)
}

// DeleteOIDCClientRotationSchedule removes the interval/last/next and maintenance window gauges
// for a client while leaving the enabled gauge in place. Used when rotation is disabled so the
// dashboard can still report the client as not rotating.
func DeleteOIDCClientRotationSchedule(namespace, name string) {
	OIDCClientRotationIntervalSeconds.DeleteLabelValues(namespace, name)
	OIDCClientLastRotationTimestamp.DeleteLabelValues(namespace, name)
	OIDCClientNextRotationTimestamp.DeleteLabelValues(namespace, name)
	DeleteOIDCClientRotationWindow(namespace, name)
}

// DeleteOIDCClientRotationMetrics removes all rotation gauge entries for a client. Call this when
// a PocketIDOIDCClient is deleted, to avoid stale series. The rotation counters are intentionally
// left in place (matching ResourceOperations) so historical rates remain queryable.
func DeleteOIDCClientRotationMetrics(namespace, name string) {
	OIDCClientRotationEnabled.DeleteLabelValues(namespace, name)
	DeleteOIDCClientRotationSchedule(namespace, name)
}
