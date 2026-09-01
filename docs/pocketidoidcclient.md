# PocketIDOIDCClient

A `PocketIDOIDCClient` manages an OIDC client in Pocket-ID and can create a Secret
containing client credentials and metadata.

## Client Secret

Pocket-ID only discloses a client secret's value at the moment it is created, so the operator
creates one when it creates or adopts an OIDC client in order to store it in a Kubernetes Secret.

A client can hold up to 20 secrets, all valid until deleted. The operator presents a single
credential, so it keeps the secret whose value is in the credentials Secret and deletes the rest,
including any added outside the operator — [`spec.clientSecretOverlap`](#client-secret-overlap)
being the one exception. It identifies its own secret by the first four characters of the value,
which Pocket-ID records in clear text. A generated secret that would share those four characters
with one the client already holds is discarded and replaced, so the operator never leaves a client
holding two secrets it cannot tell apart. If such a pair appears anyway — the same
`clientSecretRef` value pushed twice, or a secret added by hand that happens to collide — it leaves
both in place rather than risk retiring the live one, and the next rotation clears them up.

A secret deleted in Pocket-ID is replaced on the next reconcile, including when every secret on
the client is gone. With [`spec.clientSecretRef`](#declarative-client-secret) the declared value is
pushed again instead. `spec.secret.storeClientSecret: false` is exempt: that secret is managed
outside the cluster and is never minted over.

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

## Declarative Client Secret

Instead of letting the operator generate a secret, you can supply one from a Kubernetes Secret
with `spec.clientSecretRef`. This is useful when the secret is provisioned elsewhere (SOPS, External Secrets, Vault) and must
match a value your application already has.

```yaml
spec:
  clientSecretRef:
    name: my-app-credentials
    key: oidc-client-secret
```

The referenced Secret must live in the same namespace as the `PocketIDOIDCClient`. The value must
be **at least 16 printable ASCII characters**.

While `clientSecretRef` is set, the operator never generates or rotates the secret:

- `spec.clientSecretRotation.enabled` is rejected at admission — a rotation would replace your
  declared value with a random one.
- `spec.isPublic: true` is rejected at admission — public clients have no secret.
- The `pocketid.internal/regenerate-client-secret` annotation is ignored. It is still removed, and
  the reason is logged.
- `spec.secret.storeClientSecret: false` still works and simply omits `client_secret` from the
  generated Secret. The value is pushed to Pocket-ID either way.
- `spec.secret.enabled: false` also still pushes to Pocket-ID — the push does not depend on the
  operator writing a Secret of its own.

`spec.clientSecretRef` must not point at the operator's own generated Secret; that is rejected.

### How changes are detected

Pocket-ID stores client secrets hashed and never returns them, so the operator cannot read back
what is currently set. Instead it records the source Secret's revision in
`status.clientSecretSourceVersion` and pushes again whenever that revision changes. Editing the
referenced Secret is picked up on the next resync (default 2 minutes) — the referenced Secret is
not operator-managed, so it is not watched.

If you remove `clientSecretRef` later, the declared value stays in place until something else
changes it. Enabling `clientSecretRotation` at that point will usually rotate immediately, since
the rotation anchor falls back to the client's creation time.

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

## Client Secret Overlap

Replacing a client secret invalidates the old one at once, breaking any consumer that cached it and
has not reloaded. `spec.clientSecretOverlap` keeps the superseded secret valid so both work during
the handover:

```yaml
spec:
  clientSecretOverlap: "15m"
```

It applies to every replacement — scheduled rotations, the `regenerate-client-secret` annotation,
and `clientSecretRef` updates — and is measured from when the **replacement** was created, so a
superseded secret always gets the full window however long it had been in service.

Unset or `0` (the default) deletes the previous secret as soon as the replacement is written to the
credentials Secret, so only one is ever valid. Retirement always follows that write, so a failed
write cannot leave the cluster holding a secret Pocket-ID has stopped accepting.

Retirement happens on a reconcile, so a secret goes within one resync interval (default 2 minutes)
of its overlap elapsing rather than to the second. The maximum is `168h`, capped further at
`clientSecretRotation.interval` when set: an overlap outlasting the rotation period would
accumulate secrets against Pocket-ID's limit of 20. A client that reaches the limit anyway has its
oldest superseded secrets retired early rather than wedging rotation.

## Client Secret Rotation

**Note:** For an accurate cron schedule be sure to set the `TZ` environment variable to your local TZ.
In the helm chart this is `operator.timezone`; if you have an instance configured **via the chart** the value
can be derived from `instance.spec.timezone` in the chart values.

Rotation is mutually exclusive with [`spec.clientSecretRef`](#declarative-client-secret): the
operator cannot both keep a declared value and replace it on a schedule.

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

Set [`spec.clientSecretOverlap`](#client-secret-overlap) to keep the replaced secret working for a
while if your consumers do not pick up the new value immediately.

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

## Client ID Metadata Documents

A `cimd` client is synthesized by Pocket-ID from an OAuth Client ID Metadata Document that
the app publishes at an https URL, rather than being provisioned ahead of time. Enable the
feature with [`spec.cimdUrlAllowlist`](pocketidinstance.md#client-id-metadata-documents) on
the instance. `status.clientType` reports `standard` or `cimd`.

Set `spec.clientID` to the metadata document URL to manage one via the operator.

```yaml
spec:
  clientID: "https://apps.example.com/myapp/client-metadata.json"

  description: "Self-registered via metadata document"
  launchUrl: "https://apps.example.com/myapp"
  skipConsent: false
  requiresReauthentication: true
  accessTokenDurationMinutes: 15
  refreshTokenDurationMinutes: 1440
  allowedUserGroups:
    - name: platform-engineers
```

### What the operator manages

The fields Pocket-ID persists on an admin update of a `cimd` client: `description`,
`launchUrl`, `skipConsent`, `requiresReauthentication`,
`requiresPushedAuthorizationRequests`, `accessTokenDurationMinutes`, and
`refreshTokenDurationMinutes`.

The parts of the client that live outside that update are managed as usual, because
Pocket-ID applies them to any client type: `allowedUserGroups`, `logo`, `scim`, the
`apiAccess` delegated permissions, and the generated Kubernetes `secret`.

Note that an auto-generated logo is resolved from `metadata.name`, not from the document's
`client_name`. Set `logo.nameOverride` or disable `logo.autoGenerate` if that is wrong for
the app.

`name`, `callbackUrls`, `logoutCallbackUrls`, `isPublic`, `pkceEnabled`,
`federatedIdentities`, `clientSecretRef`, `clientSecretRotation`, and the `apiAccess`
client permissions are owned by the metadata document or unsupported for a public client,
and are rejected at admission. The document-owned ones still appear in `status` as observed
values.

### Lifecycle

The operator adopts a `cimd` client but never creates one — Pocket-ID materializes the
record when the app first authorizes. Until that happens the resource stays `Ready=False`
with reason `AwaitingFirstAuthorization`. Adoption requires an explicit `spec.clientID`.

Deleting the resource deletes the client from Pocket-ID, exactly as it does for a standard
client.

> **Deleting the resource does not revoke access.** The app's URL is still allowlisted on
> the instance, so it re-materializes from its metadata document on the next authorization.
> What the delete does remove is local state: every user's existing consent for the app,
> along with the settings below. To revoke access, remove its URL from
> `spec.cimdUrlAllowlist` on the instance.

To force a re-fetch of the metadata document ahead of the cache TTL, set the
`pocketid.internal/refresh-client-metadata` annotation (see
[annotations.md](annotations.md)).

## Token Lifetimes

`spec.accessTokenDurationMinutes` and `spec.refreshTokenDurationMinutes` set how long
tokens issued to this client stay valid. Both accept 1 to 525600 minutes (one year) and
default to Pocket-ID's own defaults — 60 minutes and 43200 minutes (30 days).

```yaml
spec:
  accessTokenDurationMinutes: 15
  refreshTokenDurationMinutes: 1440
```

## Allowed User Groups

`spec.allowedUserGroups` restricts the client to members of the listed groups. Each
entry names a group one of three ways:

```yaml
spec:
  allowedUserGroups:
    - name: platform-admins       # a PocketIDUserGroup CR
      namespace: pocket-id        # optional, defaults to the client's namespace
    - groupName: developers       # an existing Pocket-ID group, by name
    - groupID: 4f8c1b2e-...       # an existing Pocket-ID group, by ID
```

`groupName` and `groupID` reference a group that already exists in Pocket-ID and is
**not** managed by a `PocketIDUserGroup` in this cluster. The operator resolves the
group only to grant this client access; it never creates, modifies, or deletes it.

Every reference is resolved against Pocket-ID on each reconcile. If a referenced group
does not exist, the client's `Ready` condition reports reason `UserGroupNotFound` and
reconciliation retries until it appears. This applies equally to a group that is later
deleted in Pocket-ID. Pocket-ID accepts unknown group IDs without complaint, so without
this check a stale `groupID` would leave the client group-restricted with nothing
attached — locking every user out — while the resource still reported `Ready`.

Groups can also be attached from the other direction, using `spec.allowedOIDCClients`
on a `PocketIDUserGroup`; the final set is the union of both. That direction always
requires the oidcclient to reference a `PocketIDOIDCClient` in the same cluster.

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
    additionalAnnotations:
      reflector.v1.k8s.emberstack.com/reflection-allowed: "true"
      reflector.v1.k8s.emberstack.com/reflection-allowed-namespaces: "dashboard"
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

To grant a resource without any scopes — what a client following the MCP spec requests —
set `delegatedAccess` or `clientAccess` instead of listing permissions:

```yaml
  apiAccess:
    - apiRef:
        name: orders-api
      delegatedAccess: true
```

Both default to true when the matching permission list is non-empty, so existing grants keep
working unchanged. They exist to grant a flow that selects *no* permissions, so setting one to
`false` while listing permissions for that same flow is rejected at admission rather than
silently ignoring the list — drop the permissions to revoke the flow instead.

Removing the entry revokes the grant either way — the operator tracks the APIs it granted, not
just the permissions. `clientPermissions` and `clientAccess` require a confidential client
(`isPublic: false`). The client is the sole owner of its API access in Pocket-ID; see
[PocketIDAPI](pocketidapi.md#granting-client-access) for the full semantics.

### Requesting a Token

The credentials Secret carries what a token request needs, so nothing has to be copied out of
the `PocketIDAPI` by hand. Each API in `spec.apiAccess` gets a pair of keys, suffixed with the
name it is referenced by:

| Key                   | Value                                                              |
|-----------------------|--------------------------------------------------------------------|
| `resource_<api>`      | That API's audience, from its `spec.resource`.                     |
| `scopes_<api>`        | The `clientPermissions` it grants, space-delimited.                |
| `resource` / `scopes` | The same pair unsuffixed, written only while all the grants share an audience. |

`<api>` is the `apiRef.name`. The audience itself can't be used, since it is usually a URI and
Secret keys allow only letters, digits, `-`, `_` and `.`.

A `scopes` key is left out when the flow is granted no permissions — a request for the audience
alone. Two entries with the same `apiRef.name` in different namespaces would collide on one key
and are rejected.

Renaming `spec.secret.keys.resource` or `.scopes` renames the suffixed keys too: the setting is
the prefix.

A machine-to-machine exchange can then build its whole request from the Secret. Here with
[External Secrets Operator](https://external-secrets.io)'s `Webhook` generator, which reads a
Secret whole through a keyless `secretRef`:

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: inference-worker
  namespace: pocket-id
spec:
  apiAccess:
    - apiRef:
        name: inference-api
      clientPermissions:
        - inference:local
        - inference:cloud
  secret:
    additionalLabels:
      # The generator only reads a Secret carrying this label.
      external-secrets.io/type: webhook
---
apiVersion: generators.external-secrets.io/v1alpha1
kind: Webhook
metadata:
  name: inference-token
  namespace: pocket-id
spec:
  url: "{{ .creds.token_url }}"
  method: POST
  headers:
    Content-Type: application/x-www-form-urlencoded
  body: >-
    grant_type=client_credentials&client_id={{ .creds.client_id }}&client_secret={{ .creds.client_secret }}&resource={{ .creds.resource }}&scope={{ .creds.scopes }}
  secrets:
    - name: creds
      secretRef:
        name: inference-worker-oidc-credentials
        namespace: pocket-id
  result:
    jsonPath: "$.access_token"
```

The scopes follow `clientPermissions` as it changes, and the audience is never a second copy of
the one in the `PocketIDAPI`.

### More Than One API

A token is issued for one audience, so a client granted two APIs makes two token requests — a
second `Webhook` generator, pointed at the same Secret, reading the other API's keys. No second
Secret, label, or copy of the client secret.

The unsuffixed `resource` and `scopes` are only written while every grant shares an audience.
Granting a second one removes them instead of picking a winner, so anything reading them fails
loudly rather than asking for the wrong audience; dropping back to one API brings them back.
Read the suffixed keys to be unaffected either way. Go templates need `index` for a key holding
a `-` or `.`:

```yaml
  body: >-
    grant_type=client_credentials&client_id={{ .creds.client_id }}&client_secret={{ .creds.client_secret }}&resource={{ index .creds "resource_orders-api" }}&scope={{ index .creds "scopes_orders-api" }}
```

For clients that register themselves through a Client ID Metadata Document there is no CR
to grant from, so access is granted at the API instead via
[`spec.cimdAccess`](pocketidapi.md#granting-metadata-document-clients). That access is owned
by the API: `status.cimdGrantedAPIs` reports which API resources a `cimd` client reaches
this way, and removing an `apiAccess` entry does not revoke it.

## Logo Auto-Generation

The operator can set logo URLs for OIDC clients from a URL template. `{{name}}` in a template
is replaced with the resource's `metadata.name`, or `spec.logo.nameOverride`.

The templates come from two env vars on the operator, `DEFAULT_LOGO_URL` and
`DEFAULT_DARK_LOGO_URL`. An unset one means no logo is generated for that variant.

`spec.logo.autoGenerate` decides whether a client uses the default templates. `AUTOGENERATE_LOGOS`
is the same switch set globally, so it does not have to be repeated on every client, and
defaults to `true`. Setting `autoGenerate: false` on a client means the env vars are not used
for it.

`spec.logo.logoUrl` and `spec.logo.darkLogoUrl` give a client its own template, which is used
whatever `autoGenerate` says.

### Chart Configuration

The chart sets the light template to the
[dashboard-icons](https://github.com/homarr-labs/dashboard-icons) CDN and leaves the dark one
unset:

```yaml
operator:
  autoGenerateLogos: true
  defaultLogoUrl: "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/{{name}}.webp"
  # defaultDarkLogoUrl: "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/{{name}}-light.webp"
```

Removing a template's value stops that side being generated. The dark one starts out removed
because dashboard-icons publishes a `-light` variant only for the icons whose base image is
unreadable on a dark background, so most names have none, and Pocket-ID falls back to the
light logo when a client has no dark one.

### Configuration

The `spec.logo` struct supports the following fields:

| Field            | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `autoGenerate`   | Override the global `AUTOGENERATE_LOGOS` default for this client.            |
| `nameOverride`   | Override the name used in `{{name}}` substitution. Defaults to `metadata.name`. |
| `logoUrl`        | Template for the light logo, used whatever `autoGenerate` says. |
| `darkLogoUrl`    | Template for the dark logo, used whatever `autoGenerate` says. |

### Precedence

Logo URLs are resolved in the following order:

1. **Deprecated `spec.logoUrl` / `spec.darkLogoUrl`**: if set, these are used as-is. If using these, please migrate to `spec.logo.logoUrl` and `spec.logo.darkLogoUrl`. You can still set a full URL without templating in these fields. 
2. **`spec.logo` struct**
3. **No logo**: if `spec.logo.logoUrl`/`spec.logo.darkLogoUrl` are empty and either `autoGenerate` is disabled or the operator has no template for that side

Within the `spec.logo` struct, any entries in `spec.logo.logoUrl` or `spec.logo.darkLogoUrl` take precedence over the defaults set by env variables

### Operator Environment Variables

| Variable                  | Default | Description                                        |
|---------------------------|---------|----------------------------------------------------|
| `AUTOGENERATE_LOGOS`      | `true`  | Global default for `spec.logo.autoGenerate`.       |
| `DEFAULT_LOGO_URL`        | *(unset)* | Template for light logos. Unset generates none. |
| `DEFAULT_DARK_LOGO_URL`   | *(unset)* | Template for dark logos. Unset generates none. |

### Examples

Use the chart's light logo template (no extra configuration needed):

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: grafana
spec:
  logo: {}
```

This resolves to `https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/grafana.webp`.

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

### Ownership

The operator takes ownership of a light or dark logo only while a URL resolves for it.
`status.logoUrl` and `status.darkLogoUrl` record the URL the operator last successfully applied for that side:

```yaml
status:
  darkLogoUrl: https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/immich-light.webp
  darkLogoReachable: true
  logoUrl: https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/immich.webp
  logoReachable: true
```

- A logo uploaded through the Pocket-ID UI has no applied record, so the operator never
  touches it. Set `logo.autoGenerate: false` (with no explicit URL) to manage a client's
  logo by hand on the side you care about.
- When a light or dark logo stops resolving a URL but its applied record is set in the status, the operator deletes the
  logo it put there. It never deletes one it did not apply.
- The same applies when the spec moves to a URL Pocket-ID refuses: the logo the operator
  applied from the old URL is deleted rather than left in place, since no later reconcile would replace it. A refused URL that is still the one in the applied record is left alone.
- Ownership is per side, so a client that resolves only a light URL keeps an uploaded dark
  logo.

### Unusable logo URLs

A URL Pocket-ID rejects is remembered in memory and not attempted again for 24 hours, so a permanently missing icon costs one download attempt a day rather than one every resync. Restarting the operator also clears it.

## Generated Secret

- `spec.secret.name`: defaults to `<client>-oidc-credentials`.
- `spec.secret.storeClientSecret`: set to `false` to never regenerate an existing client
  secret; adopted clients get no `client_secret` key (see [Client Secret](#client-secret)).
  Defaults to `true`.
- `spec.secret.keys`: customize secret keys. Defaults are:
  `client_id`, `client_secret`, `issuer_url`, `callback_urls`,
  `logout_callback_urls`, `discovery_url`, `authorization_url`,
  `token_url`, `userinfo_url`, `jwks_url`, `end_session_url`,
  `resource`, `scopes`. The last two also prefix the per-API keys
  (`resource_<api>`, `scopes_<api>`).
- `spec.secret.additionalLabels`: extra labels to set on the Secret.
- `spec.secret.additionalAnnotations`: extra annotations to set on the Secret. Operator-managed
  annotations take precedence and cannot be overridden. Useful for tools that copy the Secret to
  other namespaces (e.g. [reflector](https://github.com/emberstack/kubernetes-reflector)).

## Secret Contents

When enabled, the operator writes a Secret containing:
- Client ID (always)
- Client secret (only for non-public clients; with `storeClientSecret: false`, only if the
  operator created the client and minted its initial secret. With
  [`spec.clientSecretRef`](#declarative-client-secret), the declared value)
- Issuer URL and discovery endpoints derived from the instance `spec.appUrl`
- Callback and logout URLs
- A `resource` and `scopes` pair per API, for clients with
  [`spec.apiAccess`](#requesting-a-token)

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
