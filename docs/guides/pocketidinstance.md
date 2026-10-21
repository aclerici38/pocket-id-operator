# PocketIDInstance

A `PocketIDInstance` provisions Pocket-ID in the cluster. It creates a Deployment or a StatefulSet, a Service exposing port 1411, and a Secret with the static API key used by the operator for authentication.

Most of the configuration available in this custom resource simply sets the corresponding [environment variables](https://pocket-id.org/docs/configuration/environment-variables). These are exposed as custom resource fields instead of just relying on `spec.env` to offer a better experience deploying in Kubernetes and simplify the configuration (automatically setting `UI_CONFIG_DISABLED` when necessary, setting HTTPRoute hostname, `TRUST_PROXY` config, etc.). Any of these fields can be overwritten by setting the variable in `spec.env` if preferred.

## Minimal Example
For full documentation on each field in this CRD see [the API reference](../reference/pocketidinstance.md). For common configurations see [the examples](../examples/pocketidinstance.md), including a [full featured example](../examples/pocketidinstance.md#full-featured-example).
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pocket-id-encryption
  namespace: pocket-id
stringData:
  key: "e2e-test-encryption-key-32chars!"
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: pocket-id
  namespace: pocket-id
spec:
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "https://pocket-id.example.com"
```

## Image

!!! warning
    I finally learned how CRDs work. Instances created before v0.14.2 (08/24/26) have an image hardcoded into `spec.image` even if they never set one. Earlier operators declared the default in the CRD schema, so the API server stamped it into the object at creation, leaving those instances pinned to whichever Pocket-ID version was current when they were created. In addition to missing out on updates, these instances will eventually drift below the operator's minimum supported version. To fix, drop the field from the custom resource:
    ```sh
    kubectl patch pocketidinstance <name> -n <namespace> \
      --type=json -p '[{"op":"remove","path":"/spec/image"}]'
    ```

`spec.image` is optional. When it is omitted the operator runs the Pocket-ID version it was released and tested against.

To set it to pin a specific version:

```yaml
spec:
  image: ghcr.io/pocket-id/pocket-id:v2.19.0-distroless
```

## S3 File Backend

When the `s3` block is present, the operator automatically sets `FILE_BACKEND=s3`. See [the example configuration](../examples/pocketidinstance.md#s3-file-backend), for up to date documentation on all supported fields see [the API reference](../reference/pocketidinstance.md#pocketidinstancespecs3).

## SMTP

When the `smtp` block is present, the operator automatically sets `SMTP_ENABLED=true`. See [the example configuration](../examples/pocketidinstance.md#smtp), for up to date documentation on all supported fields see [the API reference](../reference/pocketidinstance.md#pocketidinstancespecsmtp).

## LDAP

When the `ldap` block is present, the operator automatically sets `LDAP_ENABLED=true`. See [example](../examples/pocketidinstance.md#ldap).

## UI Configuration

The operator automatically sets `UI_CONFIG_DISABLED=true` when any of the `ui`, `userManagement`, `webauthn`, `smtp`, `emailNotifications`, or `ldap` sections, or `cimdUrlAllowlist`, are configured.

## Tracing

When the `tracing` block is present, the operator sets `OTEL_TRACES_EXPORTER=otlp`. Due to the nature of OTEL, the only supported field in the resource is `spec.tracing.endpoint`. To configure any other exporter-specific `OTEL_*` variables, use the freeform env fields at `spec.env`.

```yaml
spec:
  tracing:
    endpoint: "http://otel-collector:4318/v1/traces"
```

## Persistence

The `persistence` block controls the data volume mounted into the pocket-id container. See examples for a [custom mount path and subPath](../examples/pocketidinstance.md#custom-mount-path-and-subpath) and a [StatefulSet with an operator-managed PVC](../examples/pocketidinstance.md#statefulset-with-operator-managed-pvc).

Pocket-ID can be run statelessly when using Postgres as the database and either Postgres or S3 as the file backend; see [stateless deployment](../examples/pocketidinstance.md#stateless-deployment).

### Fields
The table below describes the behavior when each field is set.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Mount a persistent volume at `path` |
| `existingClaim` | — | Use a pre-existing PVC instead of creating one |
| `size` | `1Gi` | Size of the operator-managed PVC (ignored when `existingClaim` is set) |
| `storageClassName` | — | StorageClass for the operator-managed PVC |
| `accessModes` | `[ReadWriteOnce]` | Access modes for the operator-managed PVC |
| `path` | `/app/data` | Mount path for the data volume inside the container |
| `subPath` | — | `subPath` within the volume to mount |
| `extraVolumeMounts` | — | Additional volume mounts to inject into the pocket-id container |

### Extra Volume Mounts

`extraVolumeMounts` lets you mount volumes that are defined in `spec.podTemplate` directly into the pocket-id container. This is useful for config maps, secrets, or other volumes that need to be visible to the pod. See [example](../examples/pocketidinstance.md#extra-volume-mounts).

## HTTPRoute (Gateway API)

You can optionally have the operator manage a `HTTPRoute` for the instance. See [example](../examples/pocketidinstance.md#httproute-gateway-api).

Requirements:
- Gateway API CRDs must be installed in the cluster (`gateway.networking.k8s.io/v1`).
- At least one `parentRef` is required.

Behavior:
- If `spec.route.hostnames` is omitted, the operator derives the hostname from `spec.appUrl`.
- If Gateway API CRDs are missing and route is enabled, reconcile logs an error and does not create the route.
- Created HTTPRoute defaults to the name of the PocketIDInstance
- Enabling the route also sets a sensible `TRUST_PROXY` default of private CIDRs (see [Trusted Proxies](#trusted-proxies)).

### Freeform Route Spec

`spec.route.template` accepts an arbitrary `HTTPRouteSpec` that is merged with the operator-built route, for fields the structured config doesn't cover (additional rules, matches, filters, timeouts, etc.). The operator always wins: `parentRefs` and `hostnames` come from the structured config, and the default rule routing to the Service on port 1411 is always injected first. Any `rules` you set in the template are appended after it. See [example](../examples/pocketidinstance.md#freeform-route-spec).

## TLS

`spec.tls` terminates HTTPS inside the Pocket-ID pod instead of at a proxy in front of it. The referenced `kubernetes.io/tls` Secret is mounted read-only at `/etc/pocket-id/tls` and Pocket-ID is pointed at it with `TLS_CERT_FILE` / `TLS_KEY_FILE`. Pocket-ID watches the mount, so certificate renewals apply without restarting the pod. The certificate is NOT verified to allow access over the cluster dns.

Enabling TLS also:
- switches the operator's default readiness/liveness probes to `scheme: HTTPS` unless overridden.
- sets `appProtocol: https` on the Service's `http` port.

See [example with cert-manager](../examples/pocketidinstance.md#tls-with-cert-manager).

## Trusted Proxies

`spec.trustedProxies` controls which upstream proxies Pocket-ID trusts for `X-Forwarded-*` headers (the `TRUST_PROXY` environment variable). This determines the client IP Pocket-ID sees, which feeds rate limiting, audit-log IPs, and GeoIP.

`enabled: true` maps to `TRUST_PROXY=true`. To restrict trust, list explicit `cidrs`. This will likely be your k8s pod network.

| Spec | Resulting `TRUST_PROXY` |
|---|---|
| unset, `spec.route.enabled: true` | private/loopback ranges (see below) |
| unset, no managed route | `false` (trust nothing) |
| `{enabled: false}` | `false` even if `spec.route` is configured |
| `{enabled: true}` | `true` (any IP) |
| `{enabled: true, cidrs: [...]}` | the listed CIDRs |

When the operator manages the route (`spec.route.enabled: true`) and you leave `trustedProxies` unset, the operator sets the private/loopback ranges `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.1/32, ::1/128, fd00::/8`.

Also see [example behind Cloudflare](../examples/pocketidinstance.md#trusted-proxies-behind-cloudflare).

## Metrics and ServiceMonitor

The operator can enable a Prometheus metrics endpoint on the Pocket ID instance. Note that Pocket ID does not yet expose any useful metrics beyond the default OTEL SDK metrics. See [pocket-id/pocket-id#1318](https://github.com/pocket-id/pocket-id/issues/1318).

To enable metrics, set `spec.metrics.enabled: true` on the `PocketIDInstance`. The operator will inject the required OpenTelemetry environment variables and add a `metrics` port to the Service. See [example](../examples/pocketidinstance.md#enable-metrics).

If installing via the Helm chart, you can also deploy a `ServiceMonitor` for the instance. See [example](../examples/pocketidinstance.md#servicemonitor-via-helm).

This creates a `ServiceMonitor` that scrapes the `metrics` port if the Prometheus Operator CRDs are installed.

If you're not using the Helm chart, you can deploy a `ServiceMonitor` directly. See [example](../examples/pocketidinstance.md#standalone-servicemonitor).

## Pod Template

`spec.podTemplate` allows editing the instance's pod spec to add custom init containers, sidecars, tolerations, affinity, node selectors, extra volumes, etc. The instance's spec is merged on top of `spec.podTemplate`, therefore the pocket-id container remains managed by the operator and changes here will not affect it. The rest of the pod is freely editable.

See examples for an [init container](../examples/pocketidinstance.md#init-container), [tolerations and node selector](../examples/pocketidinstance.md#tolerations-and-node-selector), and a [sidecar](../examples/pocketidinstance.md#sidecar).

## Service Template

`spec.serviceTemplate` accepts an arbitrary `ServiceSpec` that is merged with the operator-built Service, for fields the operator doesn't expose (e.g. `type: LoadBalancer`, `sessionAffinity`, `externalTrafficPolicy`, extra ports). The operator configuration always takes preference over anything set here, managing the `selector` and the `http` port (plus the `metrics` port when metrics are enabled). Extra ports will be added as long as their names do not conflict (`http`, `metrics`). See [example](../examples/pocketidinstance.md#service-template).

## External Instance

Configuring `spec.external` allows the operator to manage an instance deployed outside of the PocketIDInstance CRD, e.g. a deployment in a remote cluster, a handwritten deployment, community helm chart, etc. All workload configuration (`spec.encryptionKey`, `spec.smtp`, `spec.persistence`, etc.) is ignored in this mode. There are no limitations for the other custom resources, they will all work as-documented. `spec.external` and `spec.encryptionKey` are mutually exclusive. To migrate from an external instance to an internal one or vice versa, the instance must be recreated.

See [example](../examples/pocketidinstance.md#external-instance).

## Generated Resources And Environment

- Service name: `<instance>`, port 1411.
- Static API key Secret: `<instance>-static-api-key`, key `token`.
- Environment variables always set by the operator (managed instances only):
  - `ENCRYPTION_KEY` (from `spec.encryptionKey`)
  - `STATIC_API_KEY` (secret reference)
- Conditionally set from spec fields:
  - `UI_CONFIG_DISABLED=true` (when `spec.ui`, `spec.userManagement`, `spec.webauthn`, `spec.smtp`, `spec.emailNotifications`, `spec.ldap`, or `spec.cimdUrlAllowlist` is configured)
  - `DB_CONNECTION_STRING` (from `spec.databaseUrl`)
  - `APP_URL` (from `spec.appUrl`)
  - `INTERNAL_APP_URL` (from `spec.internalAppUrl`)
  - `FILE_BACKEND` (from `spec.fileBackend`) NOTE: `FILE_BACKEND` is set to `s3` if `spec.s3` is configured
  - `FILE_BACKEND=s3` + `S3_*` (from `spec.s3`)
  - `SMTP_ENABLED=true` + `SMTP_*` (from `spec.smtp`)
  - `EMAIL_*_ENABLED`, `EMAIL_LOGIN_NOTIFICATION_MODE` (from `spec.emailNotifications`)
  - `LDAP_ENABLED=true` + `LDAP_*` (from `spec.ldap`)
  - `TLS_CERT_FILE`, `TLS_KEY_FILE` (from `spec.tls`, pointing at the mounted Secret)
  - `LOG_LEVEL`, `LOG_JSON`, `LOG_QUERY_ARGS` (from `spec.logging`)
  - `OTEL_TRACES_EXPORTER=otlp` (from `spec.tracing`)
  - `OTEL_METRICS_EXPORTER=prometheus` + `OTEL_*` (from `spec.metrics`)
  - `APP_NAME`, `SESSION_DURATION`, `HOME_PAGE_URL`, `DISABLE_ANIMATIONS`, `ACCENT_COLOR` (from `spec.ui`)
  - `EMAILS_VERIFIED`, `ALLOW_OWN_ACCOUNT_EDIT`, `REQUIRE_USER_EMAIL`, `ALLOW_USER_SIGNUPS`, `SIGNUP_DEFAULT_*` (from `spec.userManagement`)
  - `WEBAUTHN_USER_VERIFICATION`, `WEBAUTHN_ALLOW_SYNCED_PASSKEYS`, `WEBAUTHN_AUTHENTICATOR_ATTACHMENT` (from `spec.webauthn`)
  - `CIMD_URL_ALLOWLIST` (JSON-encoded from `spec.cimdUrlAllowlist`)
  - `MAXMIND_LICENSE_KEY`, `GEOLITE_DB_PATH`, `GEOLITE_DB_URL` (from `spec.geoip`)
  - `TZ` (from `spec.timezone`)
  - `LOCAL_IPV6_RANGES` (from `spec.localIPv6Ranges`)
  - `TRUST_PROXY` (from `spec.trustedProxies`; when unset, defaults to the private/loopback ranges if `spec.route.enabled` is set, otherwise left unset)
  - `S3_DISABLE_DEFAULT_INTEGRITY_CHECKS` (from `spec.s3.disableDefaultIntegrityChecks`)
  - `AUDIT_LOG_RETENTION_DAYS`, `ANALYTICS_DISABLED`, `VERSION_CHECK_DISABLED`
  - `DISABLE_RATE_LIMITING=true` (set only when `spec.rateLimitingDisabled` is enabled)
  - Any additional values from `spec.env` (applied last, can override anything above)

*Note:* For all options and an up-to-date spec see [the API reference](../reference/pocketidinstance.md) or use `kubectl explain PocketIDInstance`.
