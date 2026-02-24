# PocketIDInstance

A `PocketIDInstance` provisions Pocket-ID in the cluster. It creates either a Deployment
or a StatefulSet, a Service on port 1411, and a static API key Secret used by the
operator for authentication.

## Minimal Example

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

## Full Featured Example

```yaml
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
  databaseUrl:
    valueFrom:
      secretKeyRef:
        name: pocket-id-db
        key: uri
  persistence:
    enabled: true
    existingClaim: pocket-id-data
  smtp:
    host: "smtp.example.com"
    port: 587
    from: "noreply@example.com"
    user: "smtpuser"
    password:
      valueFrom:
        secretKeyRef:
          name: smtp-creds
          key: password
    tls: "starttls"
  emailNotifications:
    loginNotification: true
    oneTimeAccessAsAdmin: true
    apiKeyExpiration: true
    verification: true
  ui:
    appName: "My SSO"
    sessionDuration: 1440
    accentColor: "#3b82f6"
  userManagement:
    allowOwnAccountEdit: true
    allowUserSignups: "disabled"
  logging:
    level: "info"
    json: true
  metrics:
    enabled: true
  versionCheckDisabled: true
  auditLogRetentionDays: 30
```

## S3 File Backend

When the `s3` block is present, the operator automatically sets `FILE_BACKEND=s3`.

```yaml
spec:
  s3:
    bucket: "pocket-id-uploads"
    region: "us-east-1"
    endpoint: "https://minio.example.com"   # optional, for S3-compatible stores
    accessKeyId:
      valueFrom:
        secretKeyRef:
          name: s3-creds
          key: access-key
    secretAccessKey:
      valueFrom:
        secretKeyRef:
          name: s3-creds
          key: secret-key
    forcePathStyle: true                     # required for most S3-compatible stores
```

## SMTP

When the `smtp` block is present, the operator automatically sets `SMTP_ENABLED=true`.

```yaml
spec:
  smtp:
    host: "smtp.example.com"
    port: 587
    from: "noreply@example.com"
    user: "smtpuser"                         # optional
    password:                                # optional, supports value or valueFrom
      valueFrom:
        secretKeyRef:
          name: smtp-creds
          key: password
    tls: "starttls"                          # none, starttls, or tls (default: none)
    skipCertVerify: false                    # for self-signed certs
```

## Email Notifications

Controls which email notifications are sent. Only relevant when SMTP is configured.

```yaml
spec:
  emailNotifications:
    loginNotification: true                  # notify on login from new device
    oneTimeAccessAsAdmin: true               # admins can send login codes
    apiKeyExpiration: true                   # notify on expiring API keys
    oneTimeAccessAsUnauthenticated: false     # email-based login bypass (reduced security)
    verification: true                       # email verification on signup/change
```

## LDAP

When the `ldap` block is present, the operator automatically sets `LDAP_ENABLED=true`.

```yaml
spec:
  ldap:
    url: "ldaps://ldap.example.com"
    bindDN: "cn=admin,dc=example,dc=com"
    bindPassword:
      valueFrom:
        secretKeyRef:
          name: ldap-creds
          key: password
    base: "dc=example,dc=com"
    skipCertVerify: false
    softDeleteUsers: false                   # disable instead of delete removed users
    adminGroupName: "pocket-id-admins"       # LDAP group that grants admin
    userSearchFilter: "(objectClass=person)"
    userGroupSearchFilter: "(objectClass=groupOfNames)"
    attributeMapping:
      userUniqueIdentifier: "uid"
      userUsername: "uid"
      userEmail: "mail"
      userFirstName: "givenName"
      userLastName: "sn"
      groupMember: "member"
      groupName: "cn"
```

## UI Configuration

The operator always sets `UI_CONFIG_DISABLED=true` so that environment variable overrides take effect.

```yaml
spec:
  ui:
    appName: "My SSO"                        # display name
    sessionDuration: 60                      # session timeout in minutes
    homePageUrl: "/settings/account"         # post-login redirect
    disableAnimations: false
    accentColor: "#3b82f6"                   # any valid CSS color
```

## User Management

```yaml
spec:
  userManagement:
    emailsVerified: false                    # auto-verify emails
    allowOwnAccountEdit: true                # let users edit own details
    allowUserSignups: "disabled"             # disabled, withToken, or open
    signupDefaultCustomClaims: '[]'          # JSON array of default claims
    signupDefaultUserGroupIds:               # UUIDs of default groups
      - "550e8400-e29b-41d4-a716-446655440000"
```

## Logging

```yaml
spec:
  logging:
    level: "info"                            # debug, info, warn, error
    json: true                               # JSON log output
```

## Tracing

When the `tracing` block is present, the operator sets `TRACING_ENABLED=true`.
Configure exporter-specific `OTEL_*` variables via the `env` escape hatch.

```yaml
spec:
  tracing: {}
  env:
    - name: OTEL_EXPORTER_OTLP_ENDPOINT
      value: "http://otel-collector:4318"
```

## GeoIP

```yaml
spec:
  geoip:
    maxmindLicenseKey:
      valueFrom:
        secretKeyRef:
          name: maxmind
          key: license-key
    dbPath: ""                               # custom GeoLite2 DB path
    dbUrl:                                   # custom download URL (supports value or valueFrom)
      value: "https://custom.example.com/GeoLite2-City.mmdb"
```

## StatefulSet With Operator-Managed PVC

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: pocket-id
  namespace: pocket-id
spec:
  deploymentType: StatefulSet
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  persistence:
    enabled: true
    size: 5Gi
```

## HTTPRoute (Gateway API)

You can optionally have the operator manage a `HTTPRoute` for the instance.

Requirements:
- Gateway API CRDs must be installed in the cluster (`gateway.networking.k8s.io/v1`).
- At least one `parentRef` is required.

Behavior:
- If `spec.route.hostnames` is omitted, the operator derives hostname from `spec.appUrl`.
- If Gateway API CRDs are missing and route is enabled, reconcile logs an error and does not create the route.
- Created HTTPRoute defaults to the name of the PocketIDInstance

```yaml
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
  route:
    enabled: true
    name: pocket-id-route
    parentRefs:
      - group: gateway.networking.k8s.io
        kind: Gateway
        name: shared-gateway
        namespace: infra-gateway
```

## Metrics and ServiceMonitor

The operator can enable a Prometheus metrics endpoint on the Pocket ID instance.
Note that Pocket ID does not currently expose any useful metrics
beyond the default OTEL SDK metrics. See [pocket-id/pocket-id#1318](https://github.com/pocket-id/pocket-id/issues/1318).

To enable metrics, set `spec.metrics.enabled: true` on the `PocketIDInstance`. The operator
will inject the required OpenTelemetry environment variables and add a `metrics` port to
the Service.

```yaml
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
  metrics:
    enabled: true
    # port: 9464  # default
```

If installing via the Helm chart, you can also deploy a `ServiceMonitor` for the instance:

```yaml
# values.yaml
instance:
  enabled: true
  spec:
    metrics:
      enabled: true
  serviceMonitor:
    enabled: true
    # interval: 30s
    # labels: {}
```

This creates a `ServiceMonitor` that scrapes the `metrics` port. You must have the
Prometheus Operator CRDs installed for this to work.

If you're not using the Helm chart, you can deploy a `ServiceMonitor` directly:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: pocket-id
  namespace: pocket-id
  labels:
    app.kubernetes.io/name: pocket-id
    app.kubernetes.io/instance: pocket-id
spec:
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
  selector:
    matchLabels:
      app.kubernetes.io/name: pocket-id
      app.kubernetes.io/instance: pocket-id
```

## Generated Resources And Environment

- Service name: `<instance>`, port 1411.
- Static API key Secret: `<instance>-static-api-key`, key `token`.
- Environment variables always set by the operator:
  - `ENCRYPTION_KEY` (from `spec.encryptionKey`)
  - `TRUST_PROXY=true`
  - `DISABLE_RATE_LIMITING=true`
  - `UI_CONFIG_DISABLED=true`
  - `STATIC_API_KEY` (secret reference)
- Conditionally set from spec fields:
  - `DB_CONNECTION_STRING` (from `spec.databaseUrl`)
  - `APP_URL` (from `spec.appUrl`)
  - `INTERNAL_APP_URL` (from `spec.internalAppUrl`)
  - `FILE_BACKEND` (from `spec.fileBackend`) NOTE: `FILE_BACKEND` is set to `s3` if `spec.s3` is configured
  - `FILE_BACKEND=s3` + `S3_*` (from `spec.s3`)
  - `SMTP_ENABLED=true` + `SMTP_*` (from `spec.smtp`)
  - `EMAIL_*_ENABLED` (from `spec.emailNotifications`)
  - `LDAP_ENABLED=true` + `LDAP_*` (from `spec.ldap`)
  - `LOG_LEVEL`, `LOG_JSON` (from `spec.logging`)
  - `TRACING_ENABLED=true` (from `spec.tracing`)
  - `METRICS_ENABLED=true` + `OTEL_*` (from `spec.metrics`)
  - `APP_NAME`, `SESSION_DURATION`, `HOME_PAGE_URL`, `DISABLE_ANIMATIONS`, `ACCENT_COLOR` (from `spec.ui`)
  - `EMAILS_VERIFIED`, `ALLOW_OWN_ACCOUNT_EDIT`, `ALLOW_USER_SIGNUPS`, `SIGNUP_DEFAULT_*` (from `spec.userManagement`)
  - `MAXMIND_LICENSE_KEY`, `GEOLITE_DB_PATH`, `GEOLITE_DB_URL` (from `spec.geoip`)
  - `AUDIT_LOG_RETENTION_DAYS`, `ANALYTICS_DISABLED`, `VERSION_CHECK_DISABLED`
  - Any additional values from `spec.env` (applied last, can override anything above)

*Note:* For all options and an up-to-date spec `kubectl explain PocketIDInstance`
