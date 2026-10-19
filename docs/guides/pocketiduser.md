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

## Declarative User ID

By default Pocket-ID assigns the user ID. Set `spec.userID` to pin it instead, which
keeps the `sub` claim stable across rebuilds of an instance.

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

Pocket-ID only accepts a lowercase UUID here. If a user with that ID already exists it
is adopted rather than recreated, so the field is also a way to bind a resource to a
user that was created elsewhere.

`spec.userID` is immutable: it cannot be changed, added, or removed after the resource
is created. To move a user to a different ID, delete the resource and create it again.

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

## User With Custom Claims

Claims declared here are attached to the user directly and are added to the claims the
user already inherits from their groups. Where the same key appears in both, the user
claim wins.

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: alice
  namespace: pocket-id
spec:
  email:
    value: "alice@example.com"
  customClaims:
    - key: department
      value: engineering
    - key: employee_id
      value: "E-1042"
```

The operator owns the full set of user-level claims: removing an entry from
`spec.customClaims` removes it from Pocket-ID, and claims added to the user outside the
operator are removed on the next reconcile. Group claims are unaffected — see
[pocketidusergroup.md](pocketidusergroup.md).

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
This code expires after 60 minutes and is subsequently removed from the resource's status.

## Status Highlights

- `status.userID`: Pocket-ID user ID.
- `status.userInfoSecretName`: name of the output secret containing resolved user
  profile fields (`<user>-user-data`).
- `status.apiKeys`: observed API key state and secret references.
- `status.customClaims`: resolved user-level claims.
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
