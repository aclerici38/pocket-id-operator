# PocketIDOIDCClient

A `PocketIDOIDCClient` manages an OIDC client in Pocket-ID and, by default, writes a Secret containing the client's credentials and the instance's OIDC endpoints.

Like the other custom resources, the operator continuously reconciles the client in Pocket-ID to match the custom resource, so edits made in the UI to managed fields are overwritten on the next reconcile.

For full documentation on each field in this CRD see [the API reference](../reference/pocketidoidcclient.md). For common configurations see [the examples](../examples/pocketidoidcclient.md).

## Minimal Example

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: my-app
  namespace: pocket-id
spec:
  callbackUrls:
    - "https://app.example.com/auth/callback"
```

## Callback URLs

List every redirect URI the client uses under `spec.callbackUrls`, and any post-logout redirect URIs under `spec.logoutCallbackUrls`. Pocket-ID only redirects to URLs registered on the client, so an authorization request whose `redirect_uri` is not listed is rejected. Wildcards are supported.

## Credentials Secret

Unless `spec.secret.enabled` is `false`, the operator writes a Secret named `<client>-oidc-credentials` (override with `spec.secret.name`) containing:

- The client ID.
- The client secret, for confidential clients. See [Client Secret](#client-secret) for when it is omitted.
- The issuer URL and the discovery, authorization, token, userinfo, JWKS, and end-session endpoints, derived from the instance's `spec.appUrl`.
- The callback and logout callback URLs.
- A `resource` and `scopes` pair per API in `spec.apiAccess`. See [Requesting a Token](#requesting-a-token).

Every key name can be changed with `spec.secret.keys`; see [the reference](../reference/pocketidoidcclient.md#pocketidoidcclientspecsecretkeys) for the defaults. `spec.secret.additionalLabels` and `spec.secret.additionalAnnotations` add metadata to the Secret, e.g. for tools that copy it to other namespaces such as [reflector](https://github.com/emberstack/kubernetes-reflector). Operator-managed annotations take precedence and cannot be overridden. See [example](../examples/pocketidoidcclient.md#confidential-client-with-secret-customization).

## Client Secret

Pocket-ID only returns a client secret's value at the moment it is created, so the operator generates a new one when it creates or adopts a confidential client in order to store it in the credentials Secret.

A client can hold up to 20 secrets, all valid until deleted. The operator presents a single credential, so it keeps the secret whose value is in the credentials Secret and deletes the rest, including any added outside the operator. The one exception is [`spec.clientSecretOverlap`](#client-secret-overlap).

The operator identifies its own secret by the first four characters of the value, which Pocket-ID records in clear text. A generated secret that would share those four characters with one the client already holds is discarded and regenerated, so the operator never leaves a client holding two secrets it cannot tell apart. If such a pair appears anyway (the same `clientSecretRef` value pushed twice, or a secret added by hand that happens to collide), both are left in place rather than risk retiring the live one, and the next rotation clears them up.

A secret deleted in Pocket-ID is replaced on the next reconcile, including when every secret on the client is gone. With [`spec.clientSecretRef`](#declarative-client-secret) the declared value is pushed again instead to prevent drift.

### Externally Managed Secret

If the client secret is managed outside the cluster (e.g. pasted into an app's UI), set `spec.secret.storeClientSecret: false`. The operator then never regenerates an **existing** client secret:

- When the operator **adopts** an OIDC client that already exists in Pocket-ID, the secret is left alone and the credentials Secret omits the `client_secret` key.
- When the operator **creates** the OIDC client itself, the initial client secret is still generated and stored, but never regenerated afterward.
- A secret deleted in Pocket-ID is not replaced.
- The `pocketid.internal/regenerate-client-secret` annotation is ignored. To rotate the secret, set `storeClientSecret` back to `true` first.
- `spec.clientSecretRotation` cannot be enabled.

### Declarative Client Secret

Instead of letting the operator generate a secret, `spec.clientSecretRef` supplies one from a Kubernetes Secret in the same namespace. This is useful when the secret is provisioned elsewhere (SOPS, External Secrets, Vault) and must match a value an application already has. The value must be at least 16 printable ASCII characters, and the reference must not point at the operator's own credentials Secret. See [example](../examples/pocketidoidcclient.md#declarative-client-secret).

While `clientSecretRef` is set, the operator never generates or rotates the secret:

- `spec.clientSecretRotation` and `spec.isPublic: true` are rejected at admission.
- The `pocketid.internal/regenerate-client-secret` annotation is ignored. It is still removed, and the reason is logged.
- The value is always pushed to Pocket-ID, even with `spec.secret.storeClientSecret: false` (which only omits `client_secret` from the credentials Secret) or `spec.secret.enabled: false`.

Pocket-ID stores client secrets hashed and never returns them, so the operator cannot read back what is set. Instead it records the source Secret's revision in `status.clientSecretSourceVersion` and pushes again whenever that revision changes. The referenced Secret is not watched, so edits are picked up on the next resync (default 2 minutes).

If `clientSecretRef` is removed later, the declared value stays in place until something else replaces it. Enabling `clientSecretRotation` at that point will usually rotate immediately, since the rotation anchor falls back to the client's creation time.

### Regenerating the Client Secret

To regenerate a client secret, set the annotation `pocketid.internal/regenerate-client-secret: "true"`. The operator removes it after processing. See [example](../examples/pocketidoidcclient.md#regenerate-the-client-secret) and [the annotations guide](annotations.md#pocketidoidcclient).

### Client Secret Overlap

Replacing a client secret invalidates the old one immediately, breaking any consumer that cached it and has not reloaded. `spec.clientSecretOverlap` keeps the superseded secret valid for a while so both work during the handover. See [example](../examples/pocketidoidcclient.md#client-secret-overlap).

- It applies to every replacement: scheduled rotations, the `regenerate-client-secret` annotation, and `clientSecretRef` updates.
- The window is measured from when the **replacement** was created, so a superseded secret always gets the full window however long it had been in service.
- Unset or `0` (the default) deletes the previous secret as soon as the replacement is written to the credentials Secret, so only one is ever valid.
- Retirement happens on a reconcile, so a secret is deleted within one resync interval (default 2 minutes) of its overlap elapsing.
- The maximum is `168h`, and it may not exceed `clientSecretRotation.interval` when set, since an overlap outlasting the rotation period would accumulate secrets. A client that reaches the limit anyway has its oldest superseded secrets retired early rather than blocking rotation.

## Client Secret Rotation

!!! note
    For an accurate cron schedule, set the `TZ` environment variable on the operator to your local timezone. In the Helm chart this is `operator.timezone`; if an instance is configured **via the operator chart**, it can be derived from `pocket-id-instance.spec.timezone` in the chart values.

When `spec.clientSecretRotation.enabled` is `true`, the operator regenerates the client secret on a schedule. Rotation is mutually exclusive with [`spec.clientSecretRef`](#declarative-client-secret) and [`spec.secret.storeClientSecret: false`](#externally-managed-secret). Pair it with [`spec.clientSecretOverlap`](#client-secret-overlap) if consumers do not pick up the new value immediately or take time to rollout.

Every scheduled rotation passes through up to three gates, in order, and only happens when all of them pass on the same reconcile:

1. **Trigger**: the time-based condition that makes a rotation *due*: `interval`, `window`, or both (see [Trigger Modes](#trigger-modes)).
2. **Maintenance window**: when a `window` is configured, the rotation may only fire while it is open.
3. **Instance minimum spacing**: [`spec.OIDCClientRotation.minSpacing`](../reference/pocketidinstance.md#pocketidinstancespecoidcclientrotation) on the `PocketIDInstance` throttles how often *any* client on the instance rotates, in every trigger mode. See [example](../examples/pocketidoidcclient.md#instance-wide-minimum-spacing).

The rotation **anchor** is the last rotation, or the client's creation time if it has never rotated.

### Trigger Modes

At least one trigger must be configured. When both are set, `window.closesAfter` must not exceed `interval`.

| `interval` | `window` | Mode | When a rotation becomes due |
| --- | --- | --- | --- |
| set | unset | **Interval-driven** | As soon as `interval` has elapsed since the anchor. |
| set | set | **Interval-driven, window-confined** | `interval` has elapsed **and** the window is open. If the interval elapses while the window is closed, the rotation is deferred until the window next opens. |
| unset | set | **Window-driven** | Once per window opening: the first reconcile inside an opening it has not already rotated for. |
| unset | unset | — | Rejected at admission. |

See examples for [interval-driven](../examples/pocketidoidcclient.md#interval-driven-rotation) and [window-driven](../examples/pocketidoidcclient.md#window-driven-rotation) rotation.

In window-driven mode, if an opening is missed entirely (the operator was down, instance minimum spacing consumed the whole window, or the client was adopted with an existing secret but no recorded rotation), the pending rotation is reported as deferred with `reason="window_missed"` until the window next opens. This is distinct from interval mode's `window_closed`. A brand-new client with no secret yet gets its initial secret immediately. See the [rotation metrics](metrics.md#secret-rotation) for more info and how to monitor properly.

### Manual Regeneration

[Manual regeneration](#regenerating-the-client-secret) resets the rotation anchor of that client, but does **not** count toward the instance's minimum spacing. For example, with `minSpacing: 4h` and 2 hours elapsed since the last scheduled rotation on the instance, regenerating one client does not delay the next scheduled rotation of another.

## Allowed User Groups

`spec.allowedUserGroups` restricts the client to members of the listed groups. Each entry names a group one of three ways: `name` (and optionally `namespace`) for a `PocketIDUserGroup` custom resource, or `groupName` / `groupID` for a group to be looked up in Pocket-ID. See [example](../examples/pocketidoidcclient.md#allowed-user-groups).

Every reference is resolved against Pocket-ID on each reconcile. If a referenced group does not exist, including one later deleted in Pocket-ID, the `Ready` condition reports reason `UserGroupNotFound` and reconciliation retries until it appears. Pocket-ID accepts unknown group IDs, so without this check a stale `groupID` would leave the client restricted to nothing while still reporting `Ready`.

Groups can also be attached from the other direction with [`spec.allowedOIDCClients`](pocketidusergroup.md#allowed-oidc-clients) on a `PocketIDUserGroup`. The final set is the union of both.

## Federated Identities

`spec.federatedIdentities` lets workloads authenticate as this client with a JWT assertion from another issuer instead of a client secret.

Each identity verifies assertions with either a `jwks` URL, defaulting to `<issuer>/.well-known/jwks.json`, or a list of `publicKeys`. The two are mutually exclusive. See examples using a [JWKS URL](../examples/pocketidoidcclient.md#jwks-url) and [public keys](../examples/pocketidoidcclient.md#public-keys).

### Public Keys

Each `publicKeys` entry is either an inline JWK (`value`) or a ConfigMap or Secret key (`valueFrom`) holding a JWK or a whole JWKS document, whose keys are all used.

- Pocket-ID validates the keys: each needs a `kid`, must be an asymmetric public key, and may only have `use: sig`. Its error is reported in the `Ready` condition.
- A key containing private or symmetric key material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, or `k`) is refused before anything is sent, so a reference pointed at a signing key's Secret by mistake never sends that key out of the cluster.
- Referenced ConfigMaps and Secrets are not watched. They are re-read on every reconcile, so a key added to a JWKS during rotation reaches Pocket-ID on the next resync with no change to the resource.
- A missing ConfigMap, Secret, or key is an error unless the reference sets `optional: true`. An identity whose keys all resolve to nothing is also an error, since Pocket-ID would otherwise fall back to the issuer's JWKS URL.

## API Access

`spec.apiAccess` grants the client scoped access to one or more [`PocketIDAPI`](pocketidapi.md) resources. Each entry references an API and lists permission keys for the user-delegated flow (`delegatedPermissions`) and/or the client-credentials, machine-to-machine flow (`clientPermissions`). See [example](../examples/pocketidoidcclient.md#delegated-and-client-permissions).

- To grant a flow without any scopes (MCP client) set `delegatedAccess` or `clientAccess` instead of listing permissions. See [example](../examples/pocketidoidcclient.md#access-without-scopes). Both default to `true` when the matching permission list is non-empty. Setting one to `false` while listing permissions for the same flow is rejected at admission.
- `clientPermissions` and `clientAccess` require a confidential client (`isPublic: false`).
- Removing an entry revokes the grant, since the operator tracks the APIs it granted, not just the permissions.

The client is the sole owner of its API access in Pocket-ID; see [Granting Client Access](pocketidapi.md#granting-client-access) for the full details.

### Requesting a Token

The credentials Secret carries what a token request needs, so nothing has to be copied out of the `PocketIDAPI` by hand. Each API in `spec.apiAccess` gets a pair of keys, suffixed with its `apiRef.name`:

| Key | Value |
| --- | --- |
| `resource_<api>` | That API's audience, from its `spec.resource`. |
| `scopes_<api>` | The `clientPermissions` it grants, space-delimited. Omitted when the flow is granted no permissions, i.e. a request for the audience alone. |
| `resource` / `scopes` | The same pair unsuffixed, written only while all the grants share an audience. |

- The suffix is the `apiRef.name` because the audience is usually a URI, and Secret keys allow only letters, digits, `-`, `_` and `.`. Two entries with the same `apiRef.name` in different namespaces would collide on one key and are rejected.
- `spec.secret.keys.resource` and `spec.secret.keys.scopes` also set the prefix of the suffixed keys.
- A token is issued for one audience, so a client granted several APIs makes one token request per API. Granting a second audience removes the unsuffixed pair instead of picking one, so anything reading them fails loudly rather than requesting the wrong audience. Read the suffixed keys to be unaffected either way.

See examples for a [machine-to-machine token with External Secrets](../examples/pocketidoidcclient.md#machine-to-machine-token-with-external-secrets) and [more than one API](../examples/pocketidoidcclient.md#more-than-one-api).

### Metadata Document Clients

Clients registered through a [Client ID Metadata Document](#client-id-metadata-documents) often have no custom resource to grant from, so access can instead be granted to every such client at the API with [`spec.cimdAccess`](pocketidapi.md#granting-metadata-document-clients).

## Client ID Metadata Documents

A `cimd` client is created by Pocket-ID from an OAuth Client ID Metadata Document that the app publishes at an https URL, rather than being provisioned ahead of time. Enable the feature with [`spec.cimdUrlAllowlist`](../reference/pocketidinstance.md#pocketidinstancespec) on the instance. To manage one with the operator, set `spec.clientID` to the metadata document URL. `status.clientType` reports `standard` or `cimd`. See [example](../examples/pocketidoidcclient.md#client-id-metadata-document-client).

### What the Operator Manages

- The fields Pocket-ID persists on an admin update of a `cimd` client: `description`, `launchUrl`, `skipConsent`, `requiresReauthentication`, `requiresPushedAuthorizationRequests`, `accessTokenDurationMinutes`, and `refreshTokenDurationMinutes`.
- The parts Pocket-ID applies to any client type: `allowedUserGroups`, `logo`, `scim`, `apiAccess` delegated permissions, and the credentials `secret`.

`name`, `callbackUrls`, `logoutCallbackUrls`, `backchannelLogoutUrl`, `isPublic`, `pkceEnabled`, `federatedIdentities`, `clientSecretRef`, `clientSecretRotation`, and `apiAccess` client permissions are owned by the metadata document or unsupported for a public client, and are rejected at admission. The document-owned ones still appear in `status` as observed values.

An auto-generated logo is resolved from `metadata.name`, not from the document's `client_name`. Set `logo.nameOverride` or disable `logo.autoGenerate` if that is wrong for the app.

### Lifecycle

The operator adopts a `cimd` client but never creates one as Pocket-ID creates the record when the app first authorizes. Until then the resource stays `Ready=False` with reason `AwaitingFirstAuthorization`.

To force a re-fetch of the metadata document ahead of the cache TTL, set the [`pocketid.internal/refresh-client-metadata`](annotations.md#pocketidoidcclient) annotation.

Deleting the resource deletes the client from Pocket-ID, as it does for a standard client.

!!! warning
    Deleting the resource does not revoke access. The app's URL is still allowlisted on the instance, so the client is recreated from its metadata document on the next authorization. The delete only removes local state: every user's existing consent for the app, along with the settings the operator managed. To revoke access, remove its URL from `spec.cimdUrlAllowlist` on the instance.

## Logos

The operator can set a client's light and dark logo URLs from URL templates, where `{{name}}` is replaced with `spec.logo.nameOverride` or, if unset, the resource's `metadata.name`.

- The default templates come from the operator's `DEFAULT_LOGO_URL` and `DEFAULT_DARK_LOGO_URL` env vars. Unset generates no logo. The chart sets both to the [dashboard-icons](https://github.com/homarr-labs/dashboard-icons) CDN via `operator.defaultLogoUrl` and `operator.defaultDarkLogoUrl`. Setting one to `""` stops that side being generated. See [example](../examples/pocketidoidcclient.md#chart-logo-templates).
- `spec.logo.autoGenerate` decides whether a client uses the default templates. `AUTOGENERATE_LOGOS` (chart: `operator.autoGenerateLogos`, default `true`) sets it globally.
- `spec.logo.logoUrl` and `spec.logo.darkLogoUrl` give a client its own template, used regardless of `autoGenerate`.

Dashboard-icons publishes a `-light` variant for only about a sixth of its icons, so with the chart defaults most clients resolve a dark logo URL that 404s. Pocket-ID falls back to the light logo and each failed request logs an error and reports `status.darkLogoReachable: false`. The operator will retry any failed logo urls on its next rollout or after 24 hours has passed. The errors are harmless and will not affect the data reconciled to the instance in any way.

See examples to [use the default templates](../examples/pocketidoidcclient.md#use-the-default-templates), [override the icon name](../examples/pocketidoidcclient.md#override-the-icon-name), [set a custom template](../examples/pocketidoidcclient.md#custom-template), and [disable auto-generation](../examples/pocketidoidcclient.md#disable-auto-generation).

### Precedence

Each side's logo URL is resolved in this order:

1. The deprecated `spec.logoUrl` / `spec.darkLogoUrl`, used as-is. Migrate these to `spec.logo.logoUrl` and `spec.logo.darkLogoUrl`, which also accept a full URL without templating.
2. `spec.logo.logoUrl` / `spec.logo.darkLogoUrl`.
3. The operator's default template, when `autoGenerate` is enabled.
4. No logo.

### Ownership

The operator takes ownership of a light or dark logo only while a URL resolves for it. `status.logoUrl` and `status.darkLogoUrl` record the URL the operator last successfully applied for that side, and `status.logoReachable` / `status.darkLogoReachable` report whether Pocket-ID could fetch it.

- A logo uploaded through the Pocket-ID UI has no applied record, so the operator never touches it. Set `logo.autoGenerate: false` (with no explicit URL) to manage a client's logo by hand.
- When a side stops resolving a URL but has an applied record, the operator deletes the logo it put there. It never deletes one it did not apply.
- When the spec moves to a URL Pocket-ID refuses, the logo applied from the old URL is deleted rather than left in place, since no later reconcile would replace it. A refused URL that is still the one in the applied record is left alone.
- Ownership is per side, so a client that resolves only a light URL keeps an uploaded dark logo.

A URL Pocket-ID rejects is remembered in memory and not attempted again for 24 hours, so a permanently missing icon costs one download attempt a day rather than one every resync. Restarting the operator clears this.

## SCIM Provisioning

`spec.scim` configures a SCIM service provider for the client, so Pocket-ID pushes user and group changes to the external endpoint at `spec.scim.endpoint`. `spec.scim.tokenSecretRef` optionally references a Secret key holding the bearer token sent to the endpoint; without it no `Authorization` header is sent. `status.scimProviderID` is populated once the provider is created, and removing `spec.scim` deletes it from Pocket-ID. See [example](../examples/pocketidoidcclient.md#scim-provisioning).
