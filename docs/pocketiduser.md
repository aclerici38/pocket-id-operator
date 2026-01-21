# PocketIDUser

A `PocketIDUser` manages a user in Pocket-ID and can optionally create API keys

## Minimal Example

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: alice
  namespace: pocket-id
spec:
  email:
    value: "alice@example.com"
```

## User With Instance Selector And Secret Inputs

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
  admin: true
  locale: en
```

## User With API Keys

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: ci-bot
  namespace: pocket-id
spec:
  email:
    value: "ci-bot@example.com"
  apiKeys:
    - name: deploy
      description: "CI deploy key"
    - name: ops
      expiresAt: "2030-01-01T00:00:00Z"
```

## Using A Pre-Existing API Key Secret

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

## Logging In

When a user is first created in pocket-id via a custom resource a one-time code is automatically
generated for them to use on first login. The code will be displayed in the resource's status under `oneTimeLoginToken`.
If `spec.appUrl` is set on the targeted `PocketIDInstance`, `oneTimeLoginURL` will contain a fqdn that will auto-login the user with the code.
This code expires after 15 minutes and is subsequently removed from the resource's status.

## Status Highlights

- `status.userID`: Pocket-ID user ID.
- `status.userInfoSecretName`: name of the output secret containing resolved user
  profile fields (`<user>-user-data`).
- `status.apiKeys`: observed API key state and secret references.
- `status.oneTimeLoginToken` and `status.oneTimeLoginURL`: set for new users.

## Deletion Annotation

By default when a PocketIDUser resource is deleted the user will **not** be deleted from the pocket-id database.
This is to prevent any accidental deletions of the resource requiring users to reset their passkeys.
If you **would** like user deletion to be synced to Pocket-ID, add this annotation:

```yaml
metadata:
  annotations:
    pocketid.internal/delete-from-pocket-id: "true"
```

*Note:* For all options and an up-to-date spec `kubectl explain PocketIDUser` 
