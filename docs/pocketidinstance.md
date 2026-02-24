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

## Deployment with existing PVC, ENV vars

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: pocket-id
  namespace: pocket-id
spec:
  image: ghcr.io/pocket-id/pocket-id:v2.3.0-distroless@sha256:85a7485108325e34679b0fbca0baeb8418401f6d6cf59944d50f3ec013aafd09
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
  env:
    - name: UPDATE_CHECK_DISABLED
      value: "true"
    - name: SESSION_DURATION
      value: "1440"
    - name: FILE_BACKEND
      value: "database"
    - name: EMAIL_LOGIN_NOTIFICATION_ENABLED
      value: "true"
    - name: SMTP_HOST
      valueFrom:
        secretKeyRef:
          name: pocket-id
          key: smtp-host
    - name: SMTP_PORT
      value: "25"
    - name: SMTP_FROM
      value: "bot@${SECRET_DOMAIN}"
    - name: SMTP_TLS
      value: "none"
  persistence:
    enabled: true
    existingClaim: pocket-id-data
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "1411"
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

## Generated Resources And Environment

- Service name: `<instance>`, port 1411.
- Static API key Secret: `<instance>-static-api-key`, key `token`.
- Environment variables set by the operator:
  - `ENCRYPTION_KEY` (from `spec.encryptionKey`)
  - `DB_CONNECTION_STRING` (from `spec.databaseUrl`, if set)
  - `APP_URL` (from `spec.appUrl`, if set)
  - `TRUST_PROXY=true`
  - `DISABLE_RATE_LIMITING=true`
  - `STATIC_API_KEY` (secret reference)
  - Any additional values from `spec.env`

*Note:* For all options and an up-to-date spec `kubectl explain PocketIDInstance` 
