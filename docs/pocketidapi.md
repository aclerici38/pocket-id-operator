# PocketIDAPI

A `PocketIDAPI` manages an [API](https://pocket-id.org/docs/guides/apis) in Pocket-ID:
a protected resource that access tokens can be issued for. An API defines a `resource`
(the token **audience**) and a set of scoped **permissions** that OIDC clients can be
granted. Backends validate the issued JWTs against Pocket-ID's JWKS without any custom
session plumbing.

The operator is the **sole owner** of an API and its permissions: the set in Pocket-ID
is reconciled to exactly `spec.permissions`, so there is no need to manage these fields
in the Pocket-ID UI — any permission added out-of-band is removed on the next reconcile.
Because a permission's deletion cascades to any client grants that reference it, removing
a permission from `spec.permissions` also revokes it from every client that was granted it.

## Minimal Example

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDAPI
metadata:
  name: orders-api
  namespace: pocket-id
spec:
  resource: https://orders.example.com
```

## API With Permissions

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDAPI
metadata:
  name: orders-api
  namespace: pocket-id
spec:
  name: "Orders API"
  resource: https://orders.example.com
  permissions:
    - key: read:orders
      name: Read orders
      description: Read access to orders
    - key: write:orders
      name: Write orders
```

## Fields

| Field | Description |
|-------|-------------|
| `spec.name` | Friendly name in Pocket-ID. Defaults to `metadata.name`. |
| `spec.resource` | The audience identifier for issued tokens (typically a URI). **Immutable** and used to adopt an existing API. |
| `spec.permissions[].key` | Permission identifier requested as a token scope, e.g. `read:orders`. |
| `spec.permissions[].name` | Human-friendly label for the permission. |
| `spec.permissions[].description` | Optional description. |
| `spec.instanceSelector` | Selects the `PocketIDInstance` to reconcile against. Optional when exactly one instance exists. |

`spec.resource` is immutable: to change it, delete and recreate the resource. Because
`resource` is the permanent identifier, changing `spec.name` renames the API in place
while keeping the same audience.

## Granting Client Access

An API's permissions are granted to clients from the **`PocketIDOIDCClient`** side, via
`spec.apiAccess`. Each grant references a `PocketIDAPI` and lists the permission keys to
grant for the user-delegated (authorization code) flow and/or the client-credentials
(machine-to-machine) flow:

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

Notes:

- The client is the **sole owner** of its API access in Pocket-ID. While `spec.apiAccess`
  is set the operator keeps the access in sync and clears it if the field is later
  emptied. When it was never set, access configured out-of-band is left untouched.
- `clientPermissions` (machine-to-machine) require a **confidential** client
  (`spec.isPublic: false`), since M2M needs a client secret. This is enforced at admission.
- Permission keys are resolved to Pocket-ID permission IDs from the referenced API's
  status, so the `PocketIDAPI` must be `Ready` before the grant can be applied.
- A `PocketIDAPI` referenced by a client cannot be deleted until the client removes the
  reference, preventing dangling grants.

## Migrating from an existing setup

`spec.resource` is the audience, which is **globally unique** in Pocket-ID, so on
creation a `PocketIDAPI` is matched to an existing API by `spec.resource` and taken over
in place (the existing record's ID is kept — it is never deleted and recreated). Once
taken over, the operator enforces sole ownership: `spec.name` and `spec.permissions` are
made authoritative, so declare the full intended permission set in the CR before it
reconciles to avoid dropping permissions that existing clients rely on.

## Status

| Field | Description |
|-------|-------------|
| `status.apiID` | The ID assigned by Pocket-ID. |
| `status.resource` | The resolved audience identifier. |
| `status.permissions` | Permissions resolved from Pocket-ID, including their IDs. Used to resolve permission keys referenced by OIDC clients. |
| `status.conditions` | Standard conditions; `Ready` reflects sync state. |
