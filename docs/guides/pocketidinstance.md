# PocketIDInstance

A `PocketIDInstance` provisions Pocket-ID in the cluster. It creates a Deployment or a StatefulSet, a Service exposing port 1411, and a Secret with the static API key used by the operator for authentication.

Most of the configuration available in this custom resource simply sets the corresponding [environment variables](https://pocket-id.org/docs/configuration/environment-variables). These are exposed as custom resource fields instead of just relying on `spec.env` to offer a better experience deploying in Kubernetes and simplify the configuration (setting HTTPRoute hostname, `TRUST_PROXY` config, etc.). Any of these fields can be overwritten by setting the variable in `spec.env` if preferred.

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
  image: ghcr.io/pocket-id/pocket-id:v2.19.3
```

## S3 File Backend

When the `s3` block is present, the operator automatically sets `FILE_BACKEND=s3`. See [the example configuration](../examples/pocketidinstance.md#s3-file-backend), for up to date documentation on all supported fields see [the API reference](../reference/pocketidinstance.md#pocketidinstancespecs3).

## SMTP

See [the example configuration](../examples/pocketidinstance.md#smtp), for up to date documentation on all supported fields see [the API reference](../reference/pocketidinstance.md#pocketidinstancespecsmtp).

## LDAP

When the `ldap` block is present, the operator automatically sets `LDAP_ENABLED=true`. See [example](../examples/pocketidinstance.md#ldap).

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
| `cache` | — | Persistence and mount path for the cache folder, see [Cache](#cache) |

### Cache

Pocket-ID keeps files it can download or render again (the GeoLite database, FIDO metadata and default profile pictures) in `/app/cache`. By default this is an emptyDir, so the cache is rebuilt after every restart. Set `cache` to persist it on its own volume; it accepts `enabled`, `existingClaim`, `storageClass`, `size`, `accessModes` and `subPath` with the same defaults as the data volume, and the operator-managed PVC is named `<instance>-cache`. `cache.path` moves the mount and sets `CACHE_PATH` to match. With a StatefulSet the cache PVC comes from a volumeClaimTemplate, so `cache` can't be changed after the instance is created.

```yaml
spec:
  persistence:
    cache:
      enabled: true
      size: 512Mi
```

### Extra Volume Mounts

`extraVolumeMounts` lets you mount volumes that are defined in `spec.podTemplate` directly into the pocket-id container. This is useful for config maps, secrets, or other volumes that need to be visible to the pod. See [example](../examples/pocketidinstance.md#extra-volume-mounts).

## High Availability

`spec.replicas` above 1 runs Pocket-ID active-active and sets `HA_ENABLED=true`. So does `spec.updateStrategy: RollingUpdate` at 1 replica, which starts the new pod before stopping the old one. Every replica must share the database and files, so it needs a Postgres `databaseUrl` and `fileBackend: database` or [S3](#s3-file-backend). See [example](../examples/pocketidinstance.md#high-availability).

Behavior:
- The replicas reach each other directly on UDP port 1414 of their pod IPs, so NetworkPolicies must allow that between them. No extra Service is needed.
- Deployments roll one pod at a time with `HA_ENABLED`, and use `Recreate` without it (the default at 1 replica).
- Turning `HA_ENABLED` on or off stops every pod before starting the new ones, because Pocket-ID refuses to join replicas running with a different `HA_ENABLED`.
- `spec.francis` connects the replicas to a [standalone Francis runtime](https://gofrancis.dev) instead of the one embedded in each pod.

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

## Outbound Allowlists

Pocket-ID v2.19.0+ blocks private and reserved IPs when it fetches URLs for client logos, client metadata documents, SCIM, back-channel logout, federated JWKS and LDAP pictures. `spec.outboundAllowedHosts` sets the per-feature `OUTBOUND_ALLOWED_HOSTS_*` allowlists; unset fields keep Pocket-ID's defaults.

```yaml
spec:
  outboundAllowedHosts:
    clientLogo: ["logos.internal.example.com"]
    scim: ["none"]
    ldapPicture: ["private"]
```

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

`spec.external.url` is the instance's public URL: the operator publishes issuer, endpoint, and login URLs from it. When the operator should reach the API another way, such as through an in-cluster Service rather than a public gateway, set `spec.external.apiUrl`. The operator then sends API requests there and still publishes URLs from `url`. It verifies TLS against its system trust store, so a certificate from a private CA requires that CA in the operator's trust store.

The operator authenticates with either an API key in `spec.external.apiKeySecretRef` or an OIDC client in `spec.external.clientCredentials`. An API key acts as the user who created it and always expires, so the operator stops working when that user is deleted, disabled, or demoted. A client has no owner, and its secret needs no expiry. See [example](../examples/pocketidinstance.md#external-instance).

### Client Credentials

`spec.external.clientCredentials` authenticates with the client credentials grant of a confidential OIDC client:

- Grant the client client permissions on the built-in Pocket ID API, with the scopes below. Its token carries every scope it is granted.
- The token's resource is `<APP_URL>/api`, read from the instance's issuer, so `url` doesn't have to match `APP_URL`.
- The operator caches the token and requests a new one when it expires or the Secret changes. Removing a scope makes Pocket ID reject the token, and the operator requests a new one on its next request. Added scopes apply once the current token expires.

#### Client From Another Operator

The client can be a `PocketIDOIDCClient` on the operator that manages the instance, such as one deploying Pocket ID in a home cluster for an operator in a cloud cluster to adopt. Grant the scopes in a `builtIn: true` entry of its `spec.apiAccess`, and give the other operator the `client_id` and `client_secret` of its [credentials Secret](pocketidoidcclient.md#credentials-secret). See [example](../examples/pocketidinstance.md#client-from-another-cluster).

- In the same namespace, point `clientCredentials` at the credentials Secret. Across clusters, copy it, e.g. with External Secrets through a store both clusters can reach.
- The operator reads the Secret every reconcile, so a rotated secret is picked up once the copy syncs. Until then the copied secret is invalid, unless `spec.clientSecretOverlap` keeps it valid for longer than the sync takes.
- Deleting the `PocketIDOIDCClient` deletes the client and locks the other operator out of the instance.

#### Managing the Operator's Own Client

A `PocketIDOIDCClient` targeting the external instance can also manage the client that instance authenticates with. Deleting it leaves the client in Pocket ID, so the operator keeps its access. Adopting it rewrites the client's secrets and grants, so the resource must keep them working:

- Set `spec.clientSecretRef` to the Secret key the instance's `clientSecretRef` reads. Otherwise adopting the client generates a new secret and deletes the one the instance uses.
- Grant every scope the operator needs in a `builtIn: true` entry of `spec.apiAccess`, plus `admin-access:write`, which changing a client with access to Pocket ID's own API requires. Removing a scope the operator needs locks it out, and the grant then has to be restored in the Pocket ID UI.

### API Scopes

The API key in `spec.external.apiKeySecretRef`, or the client in `spec.external.clientCredentials`, only needs the scopes of the resources the operator manages, listed in [API Scopes](../reference/api-scopes.md). Some scopes are only used by optional fields:

- `PocketIDOIDCClient`: `oidc-clients:read` and `oidc-clients:write` manage the client. `groups:read` resolves `spec.allowedUserGroups`, and `apis:read` and `apis:write` grant `spec.apiAccess`.
- `PocketIDUser`: `users:login-codes` creates the first login code and opens the user session that manages `spec.apiKeys`.
- `PocketIDInstance`: `apis:read` and `apis:write` are only used by `spec.builtInAPI`.

The credential also needs `admin-access:write` for any change that decides who holds admin access:

- creating, editing, or deleting an admin user, or making a user an admin
- creating a login code for an admin user, which managing their `spec.apiKeys` also does
- changing which clients may use Pocket ID's own API, through `spec.builtInAPI` or `spec.apiAccess`
- changing an OIDC client that may use Pocket ID's own API, including which groups may use it

Creating an API key with `admin-access:write` requires re-authenticating with a passkey, which the operator can't do, so `PocketIDUser` `spec.apiKeys` rejects it. Create it in the Pocket ID UI.

## Generated Resources And Environment

- Service name: `<instance>`, port 1411.
- Static API key Secret: `<instance>-static-api-key`, key `token`.
- Environment variables always set by the operator (managed instances only):
  - `ENCRYPTION_KEY` (from `spec.encryptionKey`)
  - `STATIC_API_KEY` (secret reference)
- Conditionally set from spec fields:
  - `DB_CONNECTION_STRING` (from `spec.databaseUrl`)
  - `APP_URL` (from `spec.appUrl`)
  - `INTERNAL_APP_URL` (from `spec.internalAppUrl`)
  - `FILE_BACKEND` (from `spec.fileBackend`) NOTE: `FILE_BACKEND` is set to `s3` if `spec.s3` is configured
  - `FILE_BACKEND=s3` + `S3_*` (from `spec.s3`)
  - `SMTP_*` (from `spec.smtp`)
  - `EMAIL_*_ENABLED`, `EMAIL_LOGIN_NOTIFICATION_MODE`, `EMAIL_VERIFICATION` (from `spec.emailNotifications`)
  - `LDAP_ENABLED=true` + `LDAP_*` (from `spec.ldap`)
  - `TLS_CERT_FILE`, `TLS_KEY_FILE` (from `spec.tls`, pointing at the mounted Secret)
  - `LOG_LEVEL`, `LOG_JSON`, `LOG_QUERY_ARGS` (from `spec.logging`)
  - `OTEL_TRACES_EXPORTER=otlp` (from `spec.tracing`)
  - `OTEL_METRICS_EXPORTER=prometheus` + `OTEL_*` (from `spec.metrics`)
  - `APP_NAME`, `SESSION_DURATION`, `HOME_PAGE_URL`, `APPEARANCE` (from `spec.ui`)
  - `EMAILS_VERIFIED`, `ALLOW_OWN_ACCOUNT_EDIT`, `REQUIRE_USER_EMAIL`, `ALLOW_USER_SIGNUPS`, `SIGNUP_DEFAULT_*` (from `spec.userManagement`)
  - `WEBAUTHN_USER_VERIFICATION`, `WEBAUTHN_ALLOW_SYNCED_PASSKEYS`, `WEBAUTHN_AUTHENTICATOR_ATTACHMENT`, `WEBAUTHN_ATTESTATION`, `FIDO_MDS_URL`, `ALLOWED_FRAME_ANCESTORS` (from `spec.webauthn`)
  - `CIMD_URL_ALLOWLIST` (JSON-encoded from `spec.cimdUrlAllowlist`)
  - `ENABLED_FEATURES` (JSON-encoded from `spec.enabledFeatures`)
  - `OUTBOUND_ALLOWED_HOSTS_*` (comma-joined from `spec.outboundAllowedHosts`)
  - `MAXMIND_LICENSE_KEY`, `GEOLITE_DB_PATH`, `GEOLITE_DB_URL` (from `spec.geoip`)
  - `TZ` (from `spec.timezone`)
  - `LOCAL_IPV6_RANGES` (from `spec.localIPv6Ranges`)
  - `TRUST_PROXY` (from `spec.trustedProxies`; when unset, defaults to the private/loopback ranges if `spec.route.enabled` is set, otherwise left unset)
  - `S3_DISABLE_DEFAULT_INTEGRITY_CHECKS` (from `spec.s3.disableDefaultIntegrityChecks`)
  - `AUDIT_LOG_RETENTION_DAYS`, `ANALYTICS_DISABLED`, `VERSION_CHECK_DISABLED`
  - `HA_ENABLED=true` (when `spec.replicas` is above 1 or `spec.updateStrategy` is `RollingUpdate`)
  - `FRANCIS_RUNTIME_ADDRESS`, `FRANCIS_HOST_PSK`, `FRANCIS_HOST_JWT_FILE`, `FRANCIS_CA` (from `spec.francis`)
  - `CLUSTER_ADDRESS` (the pod IP, with either of the above)
  - `DISABLE_RATE_LIMITING=true` (set only when `spec.rateLimitingDisabled` is enabled)
  - Any additional values from `spec.env` (applied last, can override anything above)

*Note:* For all options and an up-to-date spec see [the API reference](../reference/pocketidinstance.md) or use `kubectl explain PocketIDInstance`.
