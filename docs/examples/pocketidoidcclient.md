# PocketIDOIDCClient Examples

Common `PocketIDOIDCClient` configurations. For how each feature behaves see [the PocketIDOIDCClient guide](../guides/pocketidoidcclient.md), and for every field see [the API reference](../reference/pocketidoidcclient.md).

## Public Client

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
  backchannelLogoutUrl: "https://internal.example.com/oidc/backchannel-logout"
  pkceEnabled: true
  requiresReauthentication: true
  skipConsent: true
  accessTokenDurationMinutes: 15
  refreshTokenDurationMinutes: 1440
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

## Client Secret

### Declarative Client Secret

```yaml
spec:
  clientSecretRef:
    name: my-app-credentials
    key: oidc-client-secret
```

### Regenerate the Client Secret

```sh
kubectl annotate pocketidoidcclient <name> -n <namespace> pocketid.internal/regenerate-client-secret='true'
```

### Client Secret Overlap

```yaml
spec:
  clientSecretOverlap: "15m"
```

### Interval-Driven Rotation

Rotate every 30 days, optionally confined to a nightly window:

```yaml
spec:
  clientSecretRotation:
    enabled: true
    interval: "720h"        # rotate after 30 days
    window:                 # optional: restrict to a time window
      opens: "0 1 * * *"    # cron (local TZ): 1am daily
      closesAfter: "4h"     # window is open for 4 hours
```

### Window-Driven Rotation

Rotate once at every window opening, with no fixed interval:

```yaml
spec:
  clientSecretRotation:
    enabled: true
    window:
      opens: "0 3 * * 0"    # cron (local TZ): 3am every Sunday
      closesAfter: "1h"     # window is open for 1 hour
```

### Instance-Wide Minimum Spacing

Set on the `PocketIDInstance`:

```yaml
spec:
  OIDCClientRotation:
    minSpacing: "1h"        # at most one rotation per hour across all clients
```

## Allowed User Groups

```yaml
spec:
  allowedUserGroups:
    - name: platform-admins       # a PocketIDUserGroup CR
      namespace: pocket-id        # optional, defaults to the client's namespace
    - groupName: developers       # an existing Pocket-ID group, by name
    - groupID: 4f8c1b2e-...       # an existing Pocket-ID group, by ID
```

## Federated Identities

### JWKS URL

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

### Public Keys

```yaml
spec:
  federatedIdentities:
    - issuer: "https://kubernetes.default.svc"
      subject: "system:serviceaccount:apps:myapp"
      audience: "pocket-id"
      publicKeys:
        - value:
            kty: OKP
            crv: Ed25519
            kid: key-1
            x: "fxAuz6i2oJCZM8blM5bge1smljJn8qL-yysBgwHBnDA"
        - valueFrom:
            configMapKeyRef:
              name: cluster-oidc-jwks
              key: jwks.json
```

## API Access

### Delegated and Client Permissions

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

### Access Without Scopes

```yaml
spec:
  apiAccess:
    - apiRef:
        name: orders-api
      delegatedAccess: true
```

### Machine-to-Machine Token With External Secrets

Builds a client-credentials token request entirely from the credentials Secret, using [External Secrets Operator](https://external-secrets.io)'s `Webhook` generator, which reads a whole Secret through a keyless `secretRef`. `urlquery` form-encodes the values in case `scopes` holds more than one permission.

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
    Authorization: Basic {{ print .creds.client_id ":" .creds.client_secret | b64enc }}
  body: grant_type=client_credentials&resource={{ urlquery .creds.resource }}&scope={{ urlquery .creds.scopes }}
  secrets:
    - name: creds
      secretRef:
        name: inference-worker-oidc-credentials
  result:
    jsonPath: "$"
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: inference-token
  namespace: pocket-id
spec:
  # Well inside the token lifetime; each refresh mints a new one.
  refreshInterval: 168h
  target:
    template:
      data:
        INFERENCE_TOKEN: "{{ .access_token }}"
  dataFrom:
    - sourceRef:
        generatorRef:
          apiVersion: generators.external-secrets.io/v1alpha1
          kind: Webhook
          name: inference-token
```

### More Than One API

For a client granted several APIs, add one `Webhook` generator per API, all pointed at the same Secret, each reading that API's suffixed keys. Go templates need `index` for a key containing `-` or `.`:

```yaml
  body: >-
    grant_type=client_credentials&resource={{ urlquery (index .creds "resource_orders-api") }}&scope={{ urlquery (index .creds "scopes_orders-api") }}
```

## Client ID Metadata Document Client

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: myapp
  namespace: pocket-id
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

## Logos

### Chart Logo Templates

The chart sets both templates to the [dashboard-icons](https://github.com/homarr-labs/dashboard-icons) CDN:

```yaml
# values.yaml
operator:
  autoGenerateLogos: true
  defaultLogoUrl: "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/{{name}}.webp"
  defaultDarkLogoUrl: "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/{{name}}-light.webp"
```

Light logos only:

```yaml
# values.yaml
operator:
  defaultDarkLogoUrl: ""
```

### Use the Default Templates

With the chart defaults this resolves to `.../webp/grafana.webp` and `.../webp/grafana-light.webp`:

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: grafana
spec:
  logo: {}
```

### Override the Icon Name

```yaml
spec:
  name: Portainer CE
  logo:
    nameOverride: portainer
```

### Custom Template

```yaml
spec:
  logo:
    logoUrl: "https://my-cdn.example.com/icons/{{name}}.png"
    darkLogoUrl: "https://my-cdn.example.com/icons/{{name}}-dark.png"
```

### Disable Auto-Generation

```yaml
spec:
  logo:
    autoGenerate: false
```

## SCIM Provisioning

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
