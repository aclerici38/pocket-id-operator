# PocketIDOIDCClient

A `PocketIDOIDCClient` manages an OIDC client in Pocket-ID and can create a Secret
containing client credentials and metadata.

## Client Secret

Pocket-ID does not expose the client-secret after it's created so the operator must regenerate it on 
creation/adoption of an OIDC Client in order to store it in a Kubernetes Secret. This can lead to 
inconsistent behavior as there is no way for the operator to know whether or not the client-secret 
it created is up to date with the state of Pocket-ID. 

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
  callbackUrls:
    - "https://internal.example.com/oidc/callback"
  logoutCallbackUrls:
    - "https://internal.example.com/logout"
  pkceEnabled: true
  requiresReauthentication: true
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

## Logo Auto-Generation

The operator can automatically set logo URLs for OIDC clients using a configurable URL template.
By default it uses the [dashboard-icons](https://github.com/homarr-labs/dashboard-icons) CDN:

```
https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/<name>.svg
https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/<name>-dark.svg
```

The `{{name}}` placeholder in templates is replaced with the resource's `metadata.name`.

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

### Configuration

The `spec.logo` struct supports the following fields:

| Field            | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `autoGenerate`   | Override the global `AUTOGENERATE_LOGOS` default for this client.            |
| `nameOverride`   | Override the name used in `{{name}}` substitution. Defaults to `metadata.name`. |
| `logoUrl`        | URL template for the light logo. Defaults to `DEFAULT_LOGO_URL` env var, then the hardcoded dashboard-icons template. |
| `darkLogoUrl`    | URL template for the dark logo. Defaults to `DEFAULT_DARK_LOGO_URL` env var, then the hardcoded dashboard-icons template. |

### Precedence

Logo URLs are resolved in the following order:

1. **Deprecated `spec.logoUrl` / `spec.darkLogoUrl`** — if set, these are used as-is. If using these, please migrate to `spec.logo.logoUrl` and `spec.logo.darkLogoUrl`.
2. **`spec.logo` struct** — if `autoGenerate` is enabled, templates are resolved with `{{name}}` substitution.
3. **No logo** — if `autoGenerate` is disabled and no deprecated fields are set.

Within the `spec.logo` struct, templates are resolved in this order:
per-client `logoUrl`/`darkLogoUrl` > `DEFAULT_LOGO_URL`/`DEFAULT_DARK_LOGO_URL` env vars > hardcoded dashboard-icons defaults.

### Operator Environment Variables

| Variable                  | Default | Description                                        |
|---------------------------|---------|----------------------------------------------------|
| `AUTOGENERATE_LOGOS`      | `true`  | Global default for `spec.logo.autoGenerate`.       |
| `DEFAULT_LOGO_URL`        | *(dashboard-icons SVG)* | Default URL template for light logos. |
| `DEFAULT_DARK_LOGO_URL`   | *(dashboard-icons SVG)* | Default URL template for dark logos.  |

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

This resolves to `https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/grafana.svg`.

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

## Generated Secret

- `spec.secret.name`: defaults to `<client>-oidc-credentials`.
- `spec.secret.keys`: customize secret keys. Defaults are:
  `client_id`, `client_secret`, `issuer_url`, `callback_urls`,
  `logout_callback_urls`, `discovery_url`, `authorization_url`,
  `token_url`, `userinfo_url`, `jwks_url`, `end_session_url`.

## Secret Contents

When enabled, the operator writes a Secret containing:
- Client ID (always)
- Client secret (only for non-public clients)
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
