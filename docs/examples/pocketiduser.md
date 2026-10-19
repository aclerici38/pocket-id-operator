# PocketIDUser Examples

Common `PocketIDUser` configurations. For how each feature behaves see [the PocketIDUser guide](../guides/pocketiduser.md), and for every field see [the API reference](../reference/pocketiduser.md).

## Full Profile

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: alice
  namespace: pocket-id
spec:
  username:
    value: alice
  firstName:
    value: Alice
  lastName:
    value: Ng
  displayName:
    value: Alice Ng
  email:
    value: "alice@example.com"
  admin: true
  locale: en
```

## Profile From a Secret

### Single Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: alice-user-info
  namespace: pocket-id
stringData:
  username: "alice"
  firstName: "Alice"
  lastName: "Ng"
  email: "alice@example.com"
  displayName: "Alice Ng"
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: alice
  namespace: pocket-id
spec:
  userInfoSecretRef:
    name: alice-user-info
```

### Individual Fields

```yaml
spec:
  email:
    valueFrom:
      secretKeyRef:
        name: alice-private
        key: email
```

## Declarative User ID

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: alice
  namespace: pocket-id
spec:
  userID: 3f8a1c72-9b4d-4e61-8a0f-2c5d7e9b1a34
  email:
    value: "alice@example.com"
```

## Custom Claims

```yaml
spec:
  customClaims:
    - key: department
      value: engineering
    - key: employee_id
      value: "E-1042"
```

## API Keys

### Operator-Created Keys

Each key's token is written to the Secret `<user>-<key>-key` under `token`, here `ci-bot-deploy-key` and `ci-bot-ops-key`.

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: ci-bot
  namespace: pocket-id
spec:
  email:
    value: "ci-bot@example.com"
  admin: true
  apiKeys:
    - name: deploy
      description: "CI deploy key"
    - name: ops
      expiresAt: "2030-01-01T00:00:00Z"
```

### Pre-Existing Key Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: existing-api-key
  namespace: pocket-id
stringData:
  token: "pocket-id-api-key-token"
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: legacy-user
  namespace: pocket-id
spec:
  email:
    value: "legacy@example.com"
  apiKeys:
    - name: legacy
      secretRef:
        name: existing-api-key
        key: token
```

## Delete From Pocket-ID With the Resource

```yaml
metadata:
  annotations:
    pocketid.internal/delete-from-pocket-id: "true"
```
