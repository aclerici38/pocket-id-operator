# PocketIDOIDCClient

A `PocketIDOIDCClient` manages an OIDC client in Pocket-ID and can create a Secret
containing client credentials and metadata.

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

## Regenerating Client Secrets

Set the annotation below to force a client secret regeneration. The operator removes
it after processing.

```yaml
metadata:
  annotations:
    pocketid.internal/regenerate-client-secret: "true"
```

*Note:* For all options and an up-to-date spec `kubectl explain PocketIDOIDCClient` 
