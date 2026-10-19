# PocketIDInstance Examples

Common `PocketIDInstance` configurations. For how each feature behaves see [the PocketIDInstance guide](../guides/pocketidinstance.md), and for every field see [the API reference](../reference/pocketidinstance.md).

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
  timezone: "America/New_York"
  localIPv6Ranges: "fd00::/8,fe80::/10"
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

## Stateless Deployment

With Postgres as the database, no persistent volume is required as long as the instance is configured to use an alternative file backend via postgres or in [S3](#s3-file-backend).

### Postgres File Backend

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
  fileBackend: database
```

### S3 File Backend
Notice `fileBackend` is omitted, the operator automatically sets `FILE_BACKEND` to s3 when s3 is configured.

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
  s3:
    bucket: "pocket-id-uploads"
    region: "us-east-1"
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
```

## Persistence

### Custom Mount Path and SubPath

```yaml
spec:
  persistence:
    enabled: true
    size: 5Gi
    path: /data # override the default mount path
    subPath: pocket-id
```

### Extra Volume Mounts

```yaml
spec:
  podTemplate:
    spec:
      volumes:
        - name: custom-config
          configMap:
            name: pocket-id-custom-config
  persistence:
    extraVolumeMounts:
      - name: custom-config
        mountPath: /app/custom-config
        readOnly: true
```

## S3 File Backend

```yaml
spec:
  s3:
    bucket: "pocket-id-uploads"
    region: "us-east-1"
    endpoint: "https://minio.example.com"
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
    forcePathStyle: true
    disableDefaultIntegrityChecks: false
```

## SMTP

```yaml
spec:
  smtp:
    host: "smtp.example.com"
    port: 587
    from: "noreply@example.com"
    user: "smtpuser"
    password: # optional, supports value or valueFrom
      valueFrom:
        secretKeyRef:
          name: smtp-creds
          key: password
    tls: "starttls"
    skipCertVerify: false
```

## LDAP

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
    softDeleteUsers: false # disable instead of delete removed users
    adminGroupName: "pocket-id-admins"
    userSearchFilter: "(objectClass=person)"
    userGroupSearchFilter: "(objectClass=groupOfNames)"
    attributeMapping:
      userUniqueIdentifier: "uid"
      userUsername: "uid"
      userEmail: "mail"
      userFirstName: "givenName"
      userLastName: "sn"
      userDisplayName: "cn"
      groupMember: "member"
      groupName: "cn"
```

## User Management

```yaml
spec:
  userManagement:
    emailsVerified: false
    allowOwnAccountEdit: true
    requireUserEmail: true
    allowUserSignups: "disabled"
    signupDefaultCustomClaims: '[]' # JSON array of default claims
    signupDefaultUserGroupIds: # UUIDs of default groups
      - "550e8400-e29b-41d4-a716-446655440000"
```

## Logging

```yaml
spec:
  logging:
    level: "info" # debug, info, warn, error
    json: true # JSON log output
    queryArgs: false # SQL parameter values in debug logs and traces
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
    dbPath: "" # custom GeoLite2 DB path
    dbUrl: # custom download URL (supports value or valueFrom)
      value: "https://custom.example.com/GeoLite2-City.mmdb"
```

## HTTPRoute (Gateway API)

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

### Freeform Route Spec

```yaml
spec:
  route:
    enabled: true
    parentRefs:
      - name: shared-gateway
    template:
      rules:
        # Appended after the operator's default Service backend rule
        - matches:
            - path:
                type: PathPrefix
                value: /healthz
          filters:
            - type: RequestRedirect
              requestRedirect:
                statusCode: 302
                path:
                  type: ReplaceFullPath
                  replaceFullPath: /readyz
```

## TLS With cert-manager

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: pocket-id-tls
  namespace: pocket-id
spec:
  secretName: pocket-id-tls
  dnsNames:
    - pocket-id.example.com
  issuerRef:
    name: letsencrypt
    kind: ClusterIssuer
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
  tls:
    secretRef:
      name: pocket-id-tls
```

## Trusted Proxies Behind Cloudflare

```yaml
spec:
  # Pod is exposed directly to Cloudflare
  trustedProxies:
    enabled: true
    cidrs:
      - "173.245.48.0/20"
      - "103.21.244.0/22"
      # ... rest of https://www.cloudflare.com/ips/
```

## Metrics and ServiceMonitor

### Enable Metrics

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

### ServiceMonitor via Helm

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

### Standalone ServiceMonitor

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

## Pod Template

### Init container

```yaml
spec:
  podTemplate:
    spec:
      initContainers:
        - name: init-db
          image: ghcr.io/home-operations/postgres-init
          envFrom:
            - secretRef:
                name: pocket-id-db-secret
```

### Tolerations and node selector

```yaml
spec:
  podTemplate:
    spec:
      tolerations:
        - key: node-role
          operator: Equal
          value: storage
          effect: NoSchedule
      nodeSelector:
        kubernetes.io/arch: amd64
```

### Sidecar

```yaml
spec:
  podTemplate:
    spec:
      containers:
        - name: oauth2-proxy
          image: quay.io/oauth2-proxy/oauth2-proxy
          args:
            - --upstream=http://localhost:1411
            - --http-address=0.0.0.0:4180
```

## Service Template

```yaml
spec:
  serviceTemplate:
    type: LoadBalancer
    sessionAffinity: ClientIP
    ports:
      - name: extra
        port: 8080
        targetPort: 8080
```

## External Instance

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pocket-id-api-key
  namespace: pocket-id
stringData:
  key: "your-api-key-here"
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: pocket-id
  namespace: pocket-id
spec:
  external:
    url: "https://auth.example.com"
    apiKeySecretRef:
      name: pocket-id-api-key
      key: key
```
