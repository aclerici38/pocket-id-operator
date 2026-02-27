# Metrics

The operator exposes Prometheus metrics on the `/metrics` endpoint of the metrics server.
By default the server listens on port `8080` (HTTP). This can be changed with the
`--metrics-bind-address` flag on the manager binary.

## Enabling the Metrics Endpoint

The metrics server is started automatically. The metrics `Service` is created in the
operator's namespace with the label `control-plane: controller-manager`.

### ServiceMonitor

If you are using the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator),
apply a `ServiceMonitor` to enable scraping. The Helm chart can create this automatically
via `metrics.serviceMonitor.enabled: true`; or apply it manually:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: pocket-id-operator-metrics
  namespace: pocket-id-operator-system
spec:
  endpoints:
    - path: /metrics
      port: https
      scheme: https
      bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
      tlsConfig:
        insecureSkipVerify: true
  selector:
    matchLabels:
      control-plane: controller-manager
      app.kubernetes.io/name: pocket-id-operator
```

### Static Scrape Config

If you are not using the Prometheus Operator, point your scrape config directly at the
metrics service (port `8080`, HTTP):

```yaml
- job_name: pocket-id-operator
  scheme: https
  tls_config:
    insecure_skip_verify: true
  bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  static_configs:
    - targets: ['pocket-id-operator-metrics-service.pocket-id-operator-system.svc.cluster.local:8443']
```

---

## Grafana Dashboard

A pre-built dashboard is included in the chart at `dist/chart/files/grafana-dashboard.json`.

**Helm (ConfigMap):** set `metrics.dashboard.enabled: true` — the chart creates a ConfigMap
with the label `grafana_dashboard: "1"` that Grafana's sidecar will pick up automatically.

**Helm (GrafanaDashboard CRD):** set `metrics.dashboard.grafanaDashboard.enabled: true` —
the chart additionally creates a `GrafanaDashboard` resource (requires
[grafana-operator](https://github.com/grafana/grafana-operator)) that references the
ConfigMap. The `instanceSelector` labels can be overridden via
`metrics.dashboard.grafanaDashboard.instanceSelector.matchLabels`.

**Manual import:** in Grafana go to Dashboards → Import → Upload JSON file, and select
`dist/chart/files/grafana-dashboard.json` from the repository.

---

## Default Metrics

The following metrics are emitted by controller-runtime and are available automatically.
They are **not** duplicated by the custom metrics below.

| Metric | Description |
|--------|-------------|
| `controller_runtime_reconcile_total` | Total reconcile calls per controller and result |
| `controller_runtime_reconcile_errors_total` | Total reconcile errors per controller |
| `controller_runtime_reconcile_time_seconds` | Reconcile duration per controller |
| `workqueue_*` | Work-queue depth, latency, and processing time |

---

## Custom Metrics

### Pocket-ID API

#### `pocketid_operator_pocketid_api_requests_total`

**Type:** Counter
**Labels:** `operation`, `result`

Counts every call made to the Pocket-ID REST API, partitioned by operation name and
outcome. Use this to track error rates and call volumes for individual API operations.

| Label | Values |
|-------|--------|
| `operation` | Snake-case method name — see the table below |
| `result` | `success`, `not_found`, or `error` |

<details>
<summary>All operation names</summary>

`get_current_version`, `get_user`, `list_users`, `create_user`, `update_user`,
`delete_user`, `create_api_key_for_user`, `delete_api_key`,
`create_one_time_access_token`, `list_oidc_clients`, `create_oidc_client`,
`update_oidc_client`, `get_oidc_client`, `delete_oidc_client`,
`update_oidc_client_allowed_groups`, `regenerate_oidc_client_secret`,
`get_oidc_client_scim_service_provider`, `create_scim_service_provider`,
`update_scim_service_provider`, `delete_scim_service_provider`,
`list_user_groups`, `create_user_group`, `update_user_group`, `get_user_group`,
`delete_user_group`, `update_user_group_users`,
`update_user_group_allowed_oidc_clients`, `update_user_group_custom_claims`

</details>

---

#### `pocketid_operator_pocketid_api_request_duration_seconds`

**Type:** Histogram
**Labels:** `operation`
**Buckets:** Prometheus default (5ms → 10s)

Latency of each Pocket-ID API call in seconds, partitioned by operation. Use this to
identify slow API calls or to alert on p99 latency regressions.

---

### Resource Lifecycle

#### `pocketid_operator_resource_operations_total`

**Type:** Counter
**Labels:** `kind`, `operation`

Counts meaningful CRUD events at the Pocket-ID resource level. A new increment means
the operator actually created, updated, or deleted something in Pocket-ID — not just
that a reconcile loop ran.

| Label | Values |
|-------|--------|
| `kind` | `PocketIDUser`, `PocketIDUserGroup`, `PocketIDOIDCClient` |
| `operation` | `created`, `adopted`, `updated`, `deleted` |

- **`created`** — the resource did not exist in Pocket-ID and was created.
- **`adopted`** — the resource already existed in Pocket-ID (matched by name/email) and
  was claimed by the operator without re-creating it.
- **`updated`** — the operator detected drift and pushed a state change to Pocket-ID.
- **`deleted`** — the operator deleted the resource from Pocket-ID during finalization.

---

#### `pocketid_operator_resource_ready`

**Type:** Gauge
**Labels:** `kind`, `namespace`, `name`

Current readiness of each managed resource. Value is `1` when the `Ready` condition is
`True`, `0` otherwise. The gauge is removed entirely when a resource is deleted, so
stale series will not accumulate.

| Label | Values |
|-------|--------|
| `kind` | `PocketIDUser`, `PocketIDUserGroup`, `PocketIDOIDCClient`, `PocketIDInstance` |
| `namespace` | Kubernetes namespace of the resource |
| `name` | Kubernetes name of the resource |

---

#### `pocketid_operator_external_deletions_total`

**Type:** Counter
**Labels:** `kind`

Counts resources that were deleted from Pocket-ID **outside** the operator (e.g.,
manually via the Pocket-ID UI or API). The operator detects this during reconcile when
a GET returns 404 for a resource that should already exist, and will recreate it
automatically. A non-zero value here typically indicates out-of-band changes in Pocket-ID.

| Label | Values |
|-------|--------|
| `kind` | `PocketIDUser`, `PocketIDUserGroup`, `PocketIDOIDCClient` |

---

### API Keys

#### `pocketid_operator_api_key_operations_total`

**Type:** Counter
**Labels:** `instance_namespace`, `instance_name`, `operation`

Counts API key lifecycle events per `PocketIDInstance`. Only keys managed by the
operator are counted; keys provided via `spec.apiKeys[].secretRef` (pre-existing
secrets) do not increment this counter.

| Label | Values |
|-------|--------|
| `instance_namespace` | Namespace of the `PocketIDInstance` the user belongs to |
| `instance_name` | Name of the `PocketIDInstance` the user belongs to |
| `operation` | `created` or `deleted` |

---

### Instance

#### `pocketid_operator_instance_info`

**Type:** Gauge (info-style, always `1`)
**Labels:** `namespace`, `name`, `version`, `deployment_type`

Exposes metadata about each managed `PocketIDInstance`. The value is always `1`; use
the label values to identify the instance. When the Pocket-ID version changes, the old
label set is deleted and replaced so stale series do not accumulate.

| Label | Values |
|-------|--------|
| `namespace` | Kubernetes namespace of the `PocketIDInstance` |
| `name` | Kubernetes name of the `PocketIDInstance` |
| `version` | Pocket-ID version string (e.g. `v2.3.0`), empty if not yet fetched |
| `deployment_type` | `Deployment` or `StatefulSet` |

---

#### `pocketid_operator_usergroup_member_count`

**Type:** Gauge
**Labels:** `namespace`, `name`

Current number of members in each `PocketIDUserGroup` as reported by the Pocket-ID API
after each successful reconcile. The gauge is removed when the group is deleted.

| Label | Values |
|-------|--------|
| `namespace` | Kubernetes namespace of the `PocketIDUserGroup` |
| `name` | Kubernetes name of the `PocketIDUserGroup` |
