# Metrics

The operator exposes Prometheus metrics over HTTP on the `/metrics` endpoint of its metrics server, which listens on the address given by the manager's `--metrics-bind-address` flag. The binary's default of `0` disables the server.

## Enabling the Metrics Endpoint

**Helm:** set `metrics.enabled: true`. The chart then binds the server to `metrics.port` (default `8080`) and creates the `pocket-id-operator-metrics-service` Service with an `http` port, labelled `control-plane: controller-manager`.

**Kustomize / `dist/install.yaml`:** the metrics server is enabled on port `8080`, with the same Service in the `pocket-id-operator-system` namespace.

### ServiceMonitor

If you are using the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), the chart creates a `ServiceMonitor` with `metrics.serviceMonitor.enabled: true`. To apply it manually instead:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: pocket-id-operator-metrics
  namespace: pocket-id-operator-system
spec:
  endpoints:
    - path: /metrics
      port: http
      scheme: http
      honorLabels: true
  selector:
    matchLabels:
      control-plane: controller-manager
      app.kubernetes.io/name: pocket-id-operator
```

### Static Scrape Config

Without the Prometheus Operator, point a scrape config at the metrics Service:

```yaml
- job_name: pocket-id-operator
  scheme: http
  static_configs:
    - targets: ['pocket-id-operator-metrics-service.pocket-id-operator-system.svc.cluster.local:8080']
```

## Grafana Dashboard

A pre-built dashboard is included in the chart at `charts/pocket-id-operator/files/grafana-dashboard.json`.

- **Helm (ConfigMap):** `metrics.dashboard.enabled: true` creates a ConfigMap labelled `grafana_dashboard: "1"` (set by `metrics.dashboard.labels`), which Grafana's sidecar picks up automatically.
- **Helm (GrafanaDashboard):** when the [grafana-operator](https://github.com/grafana/grafana-operator) CRDs are installed, the chart also creates a `GrafanaDashboard` referencing that ConfigMap. Its instance selector defaults to `grafana.internal/instance: grafana` and can be overridden with `metrics.dashboard.grafanaDashboard.instanceSelector.matchLabels`. Set `metrics.dashboard.grafanaDashboard.enabled: false` to skip it.
- **Manual import:** in Grafana go to Dashboards → Import → Upload JSON file, and select `charts/pocket-id-operator/files/grafana-dashboard.json` from the repository.

## Alerting Rules

The chart creates a `PrometheusRule` automatically when the `monitoring.coreos.com/v1` CRDs are installed. Disable it with `metrics.prometheusRule.enabled: false`, turn off individual rules with `metrics.prometheusRule.rules.<name>.enabled: false`, and append your own with `metrics.prometheusRule.additionalRules`. See [the template](https://github.com/aclerici38/pocket-id-operator/blob/main/charts/pocket-id-operator/templates/monitoring/prometheusrule.yaml) for the exact expressions.

| Rule | Severity | Fires when |
| --- | --- | --- |
| `PocketIDInstanceNotReady` | critical | A `PocketIDInstance` has not been Ready for 5 minutes. |
| `PocketIDResourceNotReady` | warning | Any other custom resource has not been Ready for 5 minutes. |
| `PocketIDAPIHighErrorRate` | critical | More than 50% of Pocket-ID API requests have failed for 5 minutes. |
| `PocketIDAPISlowRequests` | warning | Pocket-ID API p99 latency has been above 5 seconds for 5 minutes. |
| `PocketIDExternalDeletions` | warning | A resource was deleted outside the operator in the last 10 minutes. |
| `PocketIDReconcileErrors` | warning | A controller has produced reconcile errors continuously for 10 minutes. |
| `PocketIDWorkQueueBackup` | warning | A work queue has held more than 10 items for 10 minutes. |
| `PocketIDOIDCClientPKCESupported` | warning | A client uses PKCE but has `spec.pkceEnabled: false`. |
| `PocketIDOIDCClientRotationFailing` | warning | A client-secret rotation failed in the last hour. |
| `PocketIDOIDCClientRotationOverdue` | warning | A client with no maintenance window has been eligible for rotation for longer than its interval (capped at 48h) without rotating, usually from instance min-spacing starvation or a stalled operator. |
| `PocketIDOIDCClientRotationWindowMissed` | warning | A window-driven client has had its window open and close without rotating for over 24h. |
| `PocketIDOIDCClientRotationDeferrals` | info | A due rotation has been deferred by `min_spacing` or `window_error` for over 6 hours. The benign `window_closed` reason is excluded, and `window_missed` has its own rule. |

## Default Metrics

The following metrics are emitted by controller-runtime and are available automatically. They are **not** duplicated by the custom metrics below.

| Metric | Description |
| --- | --- |
| `controller_runtime_reconcile_total` | Total reconcile calls per controller and result |
| `controller_runtime_reconcile_errors_total` | Total reconcile errors per controller |
| `controller_runtime_reconcile_time_seconds` | Reconcile duration per controller |
| `workqueue_*` | Work-queue depth, latency, and processing time |

## Custom Metrics

### Pocket-ID API

#### `pocketid_operator_pocketid_api_requests_total`

**Type:** Counter · **Labels:** `operation`, `result`

Counts every call made to the Pocket-ID REST API, partitioned by operation and outcome. Use this to track error rates and call volumes for individual API operations.

| Label | Values |
| --- | --- |
| `operation` | Snake-case operation name, see below |
| `result` | `success`, `not_found`, or `error` |

<details>
<summary>All operation names</summary>

`get_current_version`, `list_users`, `get_user`, `create_user`, `update_user`, `update_user_custom_claims`, `delete_user`, `create_one_time_access_token`, `create_api_key_for_user`, `delete_api_key`, `list_user_groups`, `get_user_group`, `create_user_group`, `update_user_group`, `update_user_group_users`, `update_user_group_custom_claims`, `delete_user_group`, `list_oidc_clients`, `get_oidc_client`, `create_oidc_client`, `update_oidc_client`, `update_oidc_client_allowed_groups`, `delete_oidc_client`, `delete_oidc_client_logo`, `refresh_oidc_client_metadata`, `create_oidc_client_secret`, `delete_oidc_client_secret`, `get_oidc_client_scim_service_provider`, `create_scim_service_provider`, `update_scim_service_provider`, `delete_scim_service_provider`, `list_apis`, `get_api`, `create_api`, `update_api`, `update_api_permissions`, `set_api_cimd_access`, `delete_api`, `list_api_client_grants`, `set_api_client_grant`, `remove_api_client_grant`

</details>

#### `pocketid_operator_pocketid_api_request_duration_seconds`

**Type:** Histogram · **Labels:** `operation` · **Buckets:** 1ms, then the Prometheus defaults (5ms to 10s)

Latency of each Pocket-ID API call in seconds, partitioned by operation. Use this to identify slow API calls or to alert on p99 latency regressions.

### Resource Lifecycle

#### `pocketid_operator_resource_operations_total`

**Type:** Counter · **Labels:** `kind`, `operation`

Counts changes the operator made in Pocket-ID. An increment means the operator actually created, adopted, updated, or deleted something, not just that a reconcile ran.

| Label | Values |
| --- | --- |
| `kind` | `PocketIDUser`, `PocketIDUserGroup`, `PocketIDOIDCClient`, `PocketIDAPI` |
| `operation` | `created`, `adopted`, `updated`, `deleted` |

- **`created`**: the resource did not exist in Pocket-ID and was created.
- **`adopted`**: the resource already existed in Pocket-ID and was taken over without being recreated.
- **`updated`**: the operator detected drift and pushed a change to Pocket-ID.
- **`deleted`**: the operator deleted the resource from Pocket-ID while finalizing the custom resource.

#### `pocketid_operator_resource_ready`

**Type:** Gauge · **Labels:** `kind`, `namespace`, `name`

Current readiness of each custom resource: `1` when the `Ready` condition is `True`, `0` otherwise. The series is removed when the resource is deleted, so stale series do not accumulate.

| Label | Values |
| --- | --- |
| `kind` | `PocketIDInstance`, `PocketIDUser`, `PocketIDUserGroup`, `PocketIDOIDCClient`, `PocketIDAPI` |
| `namespace` | Namespace of the resource |
| `name` | Name of the resource |

#### `pocketid_operator_external_deletions_total`

**Type:** Counter · **Labels:** `kind`

Counts resources deleted from Pocket-ID **outside** the operator, e.g. in the Pocket-ID UI or through its API. The operator detects this when a lookup of a resource it manages returns 404, and recreates it. A non-zero value typically indicates out-of-band changes in Pocket-ID.

| Label | Values |
| --- | --- |
| `kind` | `PocketIDUser`, `PocketIDUserGroup`, `PocketIDOIDCClient`, `PocketIDAPI` |

### API Keys

#### `pocketid_operator_api_key_operations_total`

**Type:** Counter · **Labels:** `instance_namespace`, `instance_name`, `operation`

Counts `PocketIDUser` API keys the operator created or deleted, per `PocketIDInstance`. Keys provided through `spec.apiKeys[].secretRef` are not counted.

| Label | Values |
| --- | --- |
| `instance_namespace` | Namespace of the user's `PocketIDInstance` |
| `instance_name` | Name of the user's `PocketIDInstance` |
| `operation` | `created` or `deleted` |

### Instance

#### `pocketid_operator_instance_info`

**Type:** Gauge (info-style, always `1`) · **Labels:** `namespace`, `name`, `version`, `deployment_type`, `app_url`

Metadata about each `PocketIDInstance`. The value is always `1`; use the labels to identify the instance. When the Pocket-ID version changes, the old series is deleted and replaced so stale series do not accumulate.

| Label | Values |
| --- | --- |
| `namespace` | Namespace of the `PocketIDInstance` |
| `name` | Name of the `PocketIDInstance` |
| `version` | Pocket-ID version (e.g. `v2.14.0`), empty until fetched |
| `deployment_type` | `Deployment` or `StatefulSet` |
| `app_url` | Value of `spec.appUrl`, empty if not set |

### User Groups

#### `pocketid_operator_usergroup_member_count`

**Type:** Gauge · **Labels:** `namespace`, `name`

Number of members in each `PocketIDUserGroup`, including those not managed by the operator, as reported by Pocket-ID after each successful reconcile. The series is removed when the group is deleted.

### OIDC Clients

#### `pocketid_operator_oidcclient_allowed_group_count`

**Type:** Gauge · **Labels:** `namespace`, `name`

Number of user groups allowed to access each `PocketIDOIDCClient`, from both `spec.allowedUserGroups` and groups listing the client in `spec.allowedOIDCClients`. `0` means the client is not group-restricted. The series is removed when the client is deleted.

#### `pocketid_operator_oidcclient_pkce_supported`

**Type:** Gauge (`0`/`1`) · **Labels:** `namespace`, `name`

Mirrors `status.pkceSupported`: `1` when Pocket-ID observed the client using PKCE during an authorization flow while `spec.pkceEnabled` is `false`, signalling PKCE can be enabled. Use `sum(pocketid_operator_oidcclient_pkce_supported)` for the number of clients that should enable it. The series is removed when the client is deleted.

### Secret Rotation

These metrics track scheduled [client-secret rotation](pocketidoidcclient.md#client-secret-rotation), configured with `spec.clientSecretRotation` on a `PocketIDOIDCClient` and throttled by `spec.OIDCClientRotation.minSpacing` on a `PocketIDInstance`. A rotation fires only when its trigger is due (an elapsed interval, a window opening, or both), the maintenance window is open when one is configured, and the instance's minimum spacing is satisfied.

All of them carry the labels `namespace` and `name` of the `PocketIDOIDCClient`, and are removed when the client is deleted.

#### `pocketid_operator_oidcclient_rotation_enabled`

**Type:** Gauge (`0`/`1`)

Whether scheduled rotation is enabled for the client (`spec.clientSecretRotation.enabled`). Use `sum(pocketid_operator_oidcclient_rotation_enabled)` for the number of clients with rotation on. When rotation is disabled this is `0` and the schedule gauges below are removed.

#### `pocketid_operator_oidcclient_rotation_interval_seconds`

**Type:** Gauge

The configured rotation interval in seconds. Present for interval-driven clients; absent for window-driven clients (no `interval`), whose schedule is described by the window gauges below.

#### `pocketid_operator_oidcclient_last_rotation_timestamp_seconds`

**Type:** Gauge (Unix seconds)

Time of the most recent client-secret rotation, read from the credentials Secret's `pocketid.internal/last-rotated-at` annotation. Compute the time since the last rotation with `time() - pocketid_operator_oidcclient_last_rotation_timestamp_seconds`. Absent until the client has rotated at least once.

#### `pocketid_operator_oidcclient_next_rotation_timestamp_seconds`

**Type:** Gauge (Unix seconds)

Time at which the secret next becomes **eligible** for rotation: the rotation anchor plus the interval. The rotation may still be delayed by the maintenance window or the instance's minimum spacing, so a value in the past means "eligible now" rather than "rotating now". Present for interval-driven clients; for window-driven clients, see `pocketid_operator_oidcclient_rotation_window_next_open_timestamp_seconds` instead.

#### `pocketid_operator_oidcclient_rotation_window_open`

**Type:** Gauge (`0`/`1`)

Whether the client's maintenance window is currently open, refreshed on every reconcile (by default every ~2 minutes). The bundled dashboard shows it as the **Window** column of the Rotation Schedule table, and it also works well in a state-timeline panel. Only present for clients that configure `spec.clientSecretRotation.window`.

#### `pocketid_operator_oidcclient_rotation_window_next_open_timestamp_seconds`

**Type:** Gauge (Unix seconds)

Time at which the maintenance window next opens. While the window is open, this is the following opening. Render the time until the next window with `pocketid_operator_oidcclient_rotation_window_next_open_timestamp_seconds - time()`. Only present for clients that configure a window.

#### `pocketid_operator_oidcclient_rotation_window_next_close_timestamp_seconds`

**Type:** Gauge (Unix seconds)

Time at which the maintenance window next closes: the close of the current window while it is open, otherwise the close of the next one. Render the time until it closes with `pocketid_operator_oidcclient_rotation_window_next_close_timestamp_seconds - time()`. The bundled dashboard shows it as the **Window Closes (in)** column of the Rotation Schedule table. Only present for clients that configure a window.

#### `pocketid_operator_oidcclient_secret_rotations_total`

**Type:** Counter · **Additional labels:** `result`, `trigger`

Counts client-secret rotations that reached Pocket-ID, partitioned by outcome and what triggered them. Use it to track rotation success and failure rates, and to alert on failed scheduled rotations.

All eight `result` × `trigger` series are seeded at `0` the first time the operator reconciles a client with a secret, so a client's first rotation of any kind shows up as a `0` → `1` step. Without the seed, `increase()` and `rate()` could not measure it, and a one-off rotation would be dropped from the dashboard's event timeline and the alerts.

| Label | Values |
| --- | --- |
| `result` | `success`, `error` |
| `trigger` | `scheduled` (interval- or window-driven rotation), `manual` (the `regenerate-client-secret` annotation), `initial` (no credentials Secret existed yet, e.g. a newly created or adopted client), `drift` (the stored secret was deleted in Pocket-ID and replaced) |

#### `pocketid_operator_oidcclient_secrets`

**Type:** Gauge

How many secrets Pocket-ID holds for the client, expired ones included, as read at the start of the last reconcile, so a secret created or retired during that reconcile shows up on the next one. Only confidential clients report it. Pocket-ID allows at most 20 secrets per client, so a value climbing towards that means superseded secrets are not being retired, usually from repeated retirement failures.

A `0` means every secret was deleted outside the operator. Unless the secret is managed externally (`spec.secret.storeClientSecret: false`), the operator creates a replacement on the next reconcile, so this should not persist.

#### `pocketid_operator_oidcclient_secrets_retired_total`

**Type:** Counter · **Additional labels:** `reason`

Counts superseded secrets the operator deleted from Pocket-ID. In steady state this tracks rotations one-for-one.

| Label | Values |
| --- | --- |
| `reason` | `superseded` (the [overlap](pocketidoidcclient.md#client-secret-overlap) elapsed), `cap` (the client hit Pocket-ID's 20-secret limit, so a secret was retired early to make room for a replacement) |

#### `pocketid_operator_oidcclient_rotation_deferred_total`

**Type:** Counter · **Additional labels:** `reason`

Counts times a scheduled rotation was **due** (an elapsed interval, or an unserved window opening in window-driven mode) but another gate kept it from firing.

| Label | Values |
| --- | --- |
| `reason` | `window_closed` (interval-driven: an elapsed interval is waiting for its window to open, which is healthy), `window_missed` (window-driven: an opening came and went unserved, so the rotation has fallen a full cycle behind), `min_spacing` (the instance's minimum spacing is not yet satisfied), `window_error` (invalid window configuration) |
