# PocketIDUser

A `PocketIDUser` manages a user in Pocket-ID, including their profile, admin status, custom claims, and optionally API keys stored in Kubernetes Secrets.

Like the other custom resources, the operator continuously reconciles the user in Pocket-ID to match the custom resource, so edits made in the UI to managed fields are overwritten on the next reconcile. A user deleted in Pocket-ID is recreated.

For full documentation on each field in this CRD see [the API reference](../reference/pocketiduser.md). For common configurations see [the examples](../examples/pocketiduser.md).

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

## Profile

`username`, `firstName`, `lastName`, `email`, and `displayName` each take either a plain `value` or a `valueFrom.secretKeyRef`. Alternatively, `spec.userInfoSecretRef` names a single Secret holding any of the keys `username`, `firstName`, `lastName`, `email`, and `displayName`. A field set directly on the spec takes precedence over the same key in that Secret, and missing keys are ignored. See examples for a [full profile](../examples/pocketiduser.md#full-profile) and [profiles from a Secret](../examples/pocketiduser.md#profile-from-a-secret).

Unset fields fall back to defaults, since Pocket-ID requires some of them:

| Field | Default |
| --- | --- |
| `username` | `metadata.name` |
| `firstName` | The username |
| `email` | `<username>@placeholder.local` |
| `displayName` | `<firstName> <lastName>` |

The operator writes the profile as stored in Pocket-ID to a Secret named `<user>-user-data`, with the same five keys. Its name is recorded in `status.userInfoSecretName`.

## Adopting Existing Users

When a `PocketIDUser` is created, the operator looks for an existing user in Pocket-ID before creating one: by `spec.userID` if set, otherwise by username, then by email. A match is adopted in place, so the user keeps their passkeys, audit logs, and group memberships. Make sure the spec matches the existing user before applying it, since the operator overwrites the profile on the next reconcile.

## Declarative User ID

By default Pocket-ID assigns the user ID. Set `spec.userID` to pin it instead, which keeps the `sub` claim stable across rebuilds of an instance. Pocket-ID only accepts a lowercase UUID. If a user with that ID already exists it is adopted rather than recreated, so the field is also a way to bind a resource to a user created elsewhere. See [example](../examples/pocketiduser.md#declarative-user-id).

`spec.userID` is immutable: it cannot be changed, added, or removed after the resource is created. To move a user to a different ID, delete the resource and create it again.

## Logging In

The first time the operator reconciles a user, whether created or adopted, it generates a one-time login code valid for 60 minutes and writes it to `status.oneTimeLoginToken`. `status.oneTimeLoginURL` holds a link that signs the user in with the code, built from the instance's `spec.appUrl` (or `spec.external.url` for an external instance), falling back to its internal Service URL. Both are cleared from status once the code expires, and the operator does not generate another.

## Custom Claims

`spec.customClaims` attaches claims to the user directly. They are added to the claims the user inherits from their [groups](pocketidusergroup.md), and the user's claim wins when the same key appears in both. See [example](../examples/pocketiduser.md#custom-claims).

## API Keys

Each entry in `spec.apiKeys` creates an API key for the user in Pocket-ID and writes its token to a Secret named `<user>-<key>-key` under the key `token`. `expiresAt` defaults to one year after creation. `status.apiKeys` records each key's ID, timestamps, and the Secret holding its token. See [example](../examples/pocketiduser.md#operator-created-keys).

- A key is only created once. Changing `expiresAt` or `description` on an existing entry has no effect, and an expired key is not renewed. To replace a key, remove the entry and add it again.
- Removing an entry deletes the key from Pocket-ID along with its Secret.
- With `secretRef` the operator records the referenced Secret key in status in place of a generated one. The Secret must exist in the user's namespace and contain the key. Removing the entry leaves both the key in Pocket-ID and the Secret in place. See [example](../examples/pocketiduser.md#pre-existing-key-secret).

## Deletion

By default, deleting a `PocketIDUser` does **not** delete the user from Pocket-ID, so an accidental deletion of the resource doesn't force the user to re-register their passkeys. To delete the user from Pocket-ID along with the resource, set the [`pocketid.internal/delete-from-pocket-id: "true"`](annotations.md#pocketiduser) annotation. See [example](../examples/pocketiduser.md#delete-from-pocket-id-with-the-resource).

Either way, the operator-created API key Secrets and the `<user>-user-data` Secret are removed with the resource. Deletion is blocked while a [`PocketIDUserGroup`](pocketidusergroup.md) still references the user in `spec.users.userRefs`.
