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
      port: http
      scheme: http
      honorLabels: true
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

## Alerting Rules (PrometheusRule)

The Helm chart includes a `PrometheusRule` that is created automatically when the
`monitoring.coreos.com/v1` CRD is available on the cluster. It can be disabled with
`metrics.prometheusRule.enabled: false`. Additional rules can be appended via
`metrics.prometheusRule.additionalRules`.

These are the current default rules:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: pocket-id-operator
  namespace: pocket-id-operator-system
spec:
  groups:
    - name: pocket-id-operator
      rules:
        # Pocket-ID instance not ready for over 5 minutes
        - alert: PocketIDInstanceNotReady
          expr: pocketid_operator_resource_ready{kind="PocketIDInstance"} == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: >-
              Pocket-ID instance {{ $labels.namespace }}/{{ $labels.name }} is not ready
            description: >-
              The PocketIDInstance {{ $labels.namespace }}/{{ $labels.name }} has been
              in a non-ready state for more than 5 minutes.

        # Managed resource not ready for over 5 minutes
        - alert: PocketIDResourceNotReady
          expr: pocketid_operator_resource_ready{kind!="PocketIDInstance"} == 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: >-
              {{ $labels.kind }} {{ $labels.namespace }}/{{ $labels.name }} is not ready
            description: >-
              The {{ $labels.kind }} {{ $labels.namespace }}/{{ $labels.name }} has been
              in a non-ready state for more than 5 minutes.

        # Pocket-ID API error rate exceeds 50%
        - alert: PocketIDAPIHighErrorRate
          expr: |-
            (
              sum(rate(pocketid_operator_pocketid_api_requests_total{result="error"}[5m]))
              / sum(rate(pocketid_operator_pocketid_api_requests_total[5m]))
            ) > 0.5
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: Pocket-ID API error rate is above 50%
            description: >-
              More than 50% of Pocket-ID API requests have been failing for over 5 minutes.
              This usually indicates the Pocket-ID server is unreachable or unhealthy.

        # Pocket-ID API p99 latency exceeds 5 seconds
        - alert: PocketIDAPISlowRequests
          expr: |-
            histogram_quantile(0.99,
              sum by (le) (
                rate(pocketid_operator_pocketid_api_request_duration_seconds_bucket[5m])
              )
            ) > 5
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: Pocket-ID API p99 latency is above 5 seconds
            description: >-
              The 99th percentile latency of Pocket-ID API requests has exceeded 5 seconds
              for more than 5 minutes.

        # Resources deleted outside the operator
        - alert: PocketIDExternalDeletions
          expr: increase(pocketid_operator_external_deletions_total[10m]) > 0
          labels:
            severity: warning
          annotations:
            summary: >-
              {{ $labels.kind }} resources deleted externally
            description: >-
              {{ $value }} {{ $labels.kind }} resource(s) were deleted outside the
              operator in the last 10 minutes. The operator will recreate them, but this
              may indicate manual interference or a competing controller.

        # Controller reconciliation errors sustained over 10 minutes
        - alert: PocketIDReconcileErrors
          expr: rate(controller_runtime_reconcile_total{result="error"}[5m]) > 0
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: >-
              {{ $labels.controller }} controller has sustained reconcile errors
            description: >-
              The {{ $labels.controller }} controller has been producing reconcile
              errors continuously for over 10 minutes.

        # Work queue depth growing, indicating the operator is falling behind
        - alert: PocketIDWorkQueueBackup
          expr: workqueue_depth > 10
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: >-
              {{ $labels.name }} work queue depth is {{ $value }}
            description: >-
              The {{ $labels.name }} work queue has had more than 10 pending items
              for over 10 minutes, indicating the operator may be falling behind due to errors.
```

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
**Labels:** `namespace`, `name`, `version`, `deployment_type`, `app_url`

Exposes metadata about each managed `PocketIDInstance`. The value is always `1`; use
the label values to identify the instance. When the Pocket-ID version changes, the old
label set is deleted and replaced so stale series do not accumulate.

| Label | Values |
|-------|--------|
| `namespace` | Kubernetes namespace of the `PocketIDInstance` |
| `name` | Kubernetes name of the `PocketIDInstance` |
| `version` | Pocket-ID version string (e.g. `v2.3.0`), empty if not yet fetched |
| `deployment_type` | `Deployment` or `StatefulSet` |
| `app_url` | Value of `spec.appUrl`, empty string if not set |

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
