# PocketIDOIDCClient

A `PocketIDOIDCClient` manages an OIDC client in Pocket-ID and can create a Secret
containing client credentials and metadata.

## Client Secret

Pocket-ID does not expose the client-secret after it's created so the operator must regenerate it on 
creation/adoption of an OIDC Client in order to store it in a Kubernetes Secret. This can lead to 
inconsistent behavior as there is no way for the operator to know whether or not the client-secret 
it created is up to date with the state of Pocket-ID. 

If the client secret is managed outside the cluster (e.g. pasted into an app's UI), set
`spec.secret.storeClientSecret: false`. The operator then never regenerates an **existing**
client secret:

- When the operator **adopts** an OIDC client that already exists in Pocket-ID, the secret is
  left alone and the Secret omits the `client_secret` key.
- When the operator **creates** the OIDC client itself, the initial client secret is still
  minted and stored. It is never regenerated afterward.
- The `pocketid.internal/regenerate-client-secret` annotation is ignored. To rotate the
  secret, flip `storeClientSecret` to `true` first.
- Enabling `spec.clientSecretRotation` together with `storeClientSecret: false` is rejected at
  admission.

## Regenerating Client Secrets

To regenerate a client-secret set the annotation `pocketid.internal/regenerate-client-secret` to "true". The operator will remove
it after processing.

```
kubectl annotate oidcclient OIDCCLIENTNAME pocketid.internal/regenerate-client-secret='true'
```

```yaml
metadata:
  annotations:
    pocketid.internal/regenerate-client-secret: "true"
```

## Client Secret Rotation

**Note:** For an accurate cron schedule be sure to set the `TZ` environment variable to your local TZ.
In the helm chart this is `operator.timezone`; if you have an instance configured **via the chart** the value
can be derived from `instance.spec.timezone` in the chart values.

When `spec.clientSecretRotation.enabled` is true, the operator automatically regenerates the
OIDC client secret on a schedule. Every scheduled rotation passes through up to three gates, in
order:

1. **Trigger** — the time-based condition that makes a rotation *due*. This is either the
   per-client `interval`, the per-client `window`, or both (see [Trigger modes](#trigger-modes)).
2. **Maintenance window** — when a `window` is configured, the rotation may only fire while the
   window is open.
3. **Instance min-spacing** — `spec.OIDCClientRotation.minSpacing` on the `PocketIDInstance`
   throttles how often *any* client on the instance rotates. Applies in every trigger mode.

A rotation only happens when all applicable gates pass on the same reconcile. The rotation
**anchor** is the last rotation or the client's creation time when it has never rotated.

### Trigger modes

You must configure at least one trigger (`interval`, `window`, or both) when rotation is
enabled.

| `interval` | `window` | Mode | When a rotation becomes due |
| --- | --- | --- | --- |
| set | unset | **Interval-driven** | As soon as `interval` has elapsed since the anchor. |
| set | set | **Interval-driven, window-confined** | `interval` has elapsed **and** the window is open. If the interval elapses while the window is closed, the rotation waits (and is reported as deferred) until the next time the window opens. |
| unset | set | **Window-driven** | Once per window opening: the window opening *is* the trigger. The secret rotates the first reconcile inside an opening it has not already rotated for. |
| unset | unset | — | Rejected by the API server (no trigger). |

When both are set, `window.closesAfter` must not exceed `interval`.

#### Window-driven mode (interval omitted)

With no `interval`, the maintenance window's cron `opens` schedule is the trigger. The secret
rotates **once per opening**: the first reconcile inside a given window after the anchor rotates,
and subsequent reconciles in that same opening do nothing. The next opening triggers the next
rotation.

If an opening is missed entirely — the operator was down, instance min-spacing consumed the whole
window, or the client was adopted with an existing secret but no recorded rotation — that pending
rotation is reported as deferred (`reason="window_missed"`) until the window next opens. This is a
distinct signal from interval mode's `window_closed` (an elapsed interval *healthily* waiting for
an upcoming window): a missed opening means the rotation has fallen a full cycle behind. (A
brand-new client with no secret yet takes the immediate `initial` path instead, not the window
trigger.)

### Examples

Interval-driven, optionally confined to a nightly window:

```yaml
spec:
  clientSecretRotation:
    enabled: true
    interval: "720h"                 # rotate after 30 days
    window:                          # optional: restrict to a time window
      opens: "0 1 * * *"            # cron (local TZ): 1am daily
      closesAfter: "4h"             # window is open for 4 hours
```

Window-driven — rotate once at every window opening, with no fixed interval:

```yaml
spec:
  clientSecretRotation:
    enabled: true
    window:
      opens: "0 3 * * 0"            # cron (local TZ): 3am every Sunday
      closesAfter: "1h"             # window is open for 1 hour
```

### Instance-wide minimum spacing

To throttle how frequently rotations happen across all clients on an instance — regardless of
trigger mode — set `spec.OIDCClientRotation.minSpacing` on the `PocketIDInstance`:

```yaml
spec:
  OIDCClientRotation:
    minSpacing: "1h"                 # at most one rotation per hour across all clients
```

### Manual regeneration interaction

Manual regeneration (setting the `pocketid.internal/regenerate-client-secret` annotation) is
accounted for by the per-client trigger on the respective OIDC client but **not** by the global
minimum spacing. For example, if `spec.OIDCClientRotation.minSpacing` is set to `4h` and 2 hours
have elapsed since the last auto-rotation, setting the annotation will NOT delay the auto-rotation
but it WILL reset the rotation anchor on the manually-rotated OIDC client.

## Callback URLs

List every redirect URI your client uses under `spec.callbackUrls`, and any
post-logout redirect URIs under `spec.logoutCallbackUrls`. Pocket-ID only allows
redirects to URLs that are registered on the client, so an authorization request
whose `redirect_uri` is not listed here will be rejected. Wildcards are supported.

```yaml
spec:
  callbackUrls:
    - "https://app.example.com/auth/callback"
  logoutCallbackUrls:
    - "https://app.example.com/logout"
```

## Minimal Public Client

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: web-portal
  namespace: pocket-id
spec:
  isPublic: true
  callbackUrls:
    - "https://app.example.com/auth/callback"
  logoutCallbackUrls:
    - "https://app.example.com/logout"
```

## Confidential Client With Secret Customization

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: internal-dashboard
  namespace: pocket-id
spec:
  description: "Internal admin dashboard"
  callbackUrls:
    - "https://internal.example.com/oidc/callback"
  logoutCallbackUrls:
    - "https://internal.example.com/logout"
  pkceEnabled: true
  requiresReauthentication: true
  skipConsent: true
  allowedUserGroups:
    - name: platform-admins
      namespace: pocket-id
  secret:
    name: internal-dashboard-oidc
    additionalLabels:
      label1: value1
    keys:
      clientID: client_id
      clientSecret: client_secret
      issuerUrl: issuer_url
      discoveryUrl: discovery_url
```

## Federated Identity Example

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: workload-identity
  namespace: pocket-id
spec:
  federatedIdentities:
    - issuer: "https://accounts.google.com"
      subject: "1234567890"
      audience: "pocket-id"
      jwks: "https://www.googleapis.com/oauth2/v3/certs"
```

## API Access

A client can be granted scoped access to one or more [`PocketIDAPI`](pocketidapi.md)
resources via `spec.apiAccess`. Each grant references an API and lists permission keys
for the user-delegated flow and/or the client-credentials (M2M) flow:

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: orders-frontend
  namespace: pocket-id
spec:
  apiAccess:
    - apiRef:
        name: orders-api
      delegatedPermissions:
        - read:orders
      clientPermissions:
        - sync:orders
```

`clientPermissions` require a confidential client (`isPublic: false`). The client is the
sole owner of its API access in Pocket-ID; see [PocketIDAPI](pocketidapi.md#granting-client-access)
for the full semantics.

## Logo Auto-Generation

The operator can automatically set logo URLs for OIDC clients using a configurable URL template.
By default it uses the [dashboard-icons](https://github.com/homarr-labs/dashboard-icons) CDN:

```
https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/{{name}}.png
https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/{{name}}-dark.png
```

The `{{name}}` placeholder in templates is replaced with the resource's `metadata.name` or `spec.logo.nameOverride`.

### Enabling / Disabling

Logo auto-generation is controlled at two levels:

1. **Global default** via the `AUTOGENERATE_LOGOS` env var on the operator. Defaults to `true`.
   Set to `false` to make logo auto-generation opt-in per client.
2. **Per-client override** via `spec.logo.autoGenerate`. When set, this takes precedence over
   the global default.

To disable auto-generation globally:

```yaml
env:
  - name: AUTOGENERATE_LOGOS
    value: "false"
```

Or through the chart

```yaml
operator:
  autoGenerateLogos: false
```

### Configuration

The `spec.logo` struct supports the following fields:

| Field            | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `autoGenerate`   | Override the global `AUTOGENERATE_LOGOS` default for this client.            |
| `nameOverride`   | Override the name used in `{{name}}` substitution. Defaults to `metadata.name`. |
| `logoUrl`        | URL for the light logo. Defaults to `DEFAULT_LOGO_URL` env var. |
| `darkLogoUrl`    | URL for the dark logo. Defaults to `DEFAULT_DARK_LOGO_URL` env var. |

### Precedence

Logo URLs are resolved in the following order:

1. **Deprecated `spec.logoUrl` / `spec.darkLogoUrl`**: if set, these are used as-is. If using these, please migrate to `spec.logo.logoUrl` and `spec.logo.darkLogoUrl`. You can still set a full URL without templating in these fields. 
2. **`spec.logo` struct**
3. **No logo**: if `autoGenerate` is disabled and `spec.logo.logoUrl`/`spec.logo.darkLogoUrl` are empty

Within the `spec.logo` struct, any entries in `spec.logo.logoUrl` or `spec.logo.darkLogoUrl` take precedence over the defaults set by env variables

### Operator Environment Variables

| Variable                  | Default | Description                                        |
|---------------------------|---------|----------------------------------------------------|
| `AUTOGENERATE_LOGOS`      | `true`  | Global default for `spec.logo.autoGenerate`.       |
| `DEFAULT_LOGO_URL`        | *(dashboard-icons PNG)* | Default URL template for light logos. |
| `DEFAULT_DARK_LOGO_URL`   | *(dashboard-icons PNG)* | Default URL template for dark logos.  |

### Examples

Use the default dashboard-icons logos (no extra configuration needed):

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: grafana
spec:
  logo: {}
```

This resolves to `https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/grafana.png`.

Override the icon name when it doesn't match the client name:

```yaml
spec:
  name: Portainer CE
  logo:
    nameOverride: portainer
```

Use a custom template for one client:

```yaml
spec:
  logo:
    logoUrl: "https://my-cdn.example.com/icons/{{name}}.png"
    darkLogoUrl: "https://my-cdn.example.com/icons/{{name}}-dark.png"
```

Disable auto-generation for a specific client when the global default is enabled:

```yaml
spec:
  logo:
    autoGenerate: false
```

The final URLs and status of the logos are displayed under `status` in the `PocketIDOIDCClient` resource

```yaml
status:
  darkLogoReachable: false
  darkLogoUrl: https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/immich-dark.png
  logoReachable: true
  logoUrl: https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/immich.png
```

Logs for the logos are set to `debug` by default to prevent spamming the console with unavailable logos.
To view the logs add the `--zap-log-level=debug` arg on the operator container.

## Generated Secret

- `spec.secret.name`: defaults to `<client>-oidc-credentials`.
- `spec.secret.storeClientSecret`: set to `false` to never regenerate an existing client
  secret; adopted clients get no `client_secret` key (see [Client Secret](#client-secret)).
  Defaults to `true`.
- `spec.secret.keys`: customize secret keys. Defaults are:
  `client_id`, `client_secret`, `issuer_url`, `callback_urls`,
  `logout_callback_urls`, `discovery_url`, `authorization_url`,
  `token_url`, `userinfo_url`, `jwks_url`, `end_session_url`.

## Secret Contents

When enabled, the operator writes a Secret containing:
- Client ID (always)
- Client secret (only for non-public clients; with `storeClientSecret: false`, only if the
  operator created the client and minted its initial secret)
- Issuer URL and discovery endpoints derived from the instance `spec.appUrl`
- Callback and logout URLs

## SCIM Provisioning

OIDC clients can optionally configure a SCIM service provider. When configured, Pocket ID
pushes user and group changes to the external SCIM endpoint.

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: hr-app
  namespace: pocket-id
spec:
  callbackUrls:
    - "https://hr.example.com/auth/callback"
  scim:
    endpoint: "https://hr.example.com/scim/v2"
    tokenSecretRef:
      name: hr-scim-token
      key: token
```

- `spec.scim.endpoint` (required): URL of the external SCIM service provider.
- `spec.scim.tokenSecretRef` (optional): reference to a Kubernetes Secret key containing
  the bearer token for authenticating with the SCIM endpoint. If omitted, no
  Authorization header is sent.
- `status.scimProviderID`: populated after the SCIM service provider is created in Pocket ID.

When `spec.scim` is removed the operator deletes the SCIM service provider from Pocket ID.

*Note:* For all options and an up-to-date spec `kubectl explain PocketIDOIDCClient` 
