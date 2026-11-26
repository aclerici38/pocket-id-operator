# PocketIDAPI

A `PocketIDAPI` manages an [API](https://pocket-id.org/docs/guides/apis) in Pocket-ID: a protected resource that access tokens can be issued for. The configuration defines a `resource` (the token **audience**) and a set of scoped **permissions** that OIDC clients can be granted. Backends are then able to validate the issued JWTs against Pocket-ID's JWKS.

Like with the other custom resources, the operator takes over control of any API defined in a custom resource, constantly reconciling the state in pocket-id with the state in the custom resource. Any ui edits will be overwritten on a subsequent reconcile.

Because a permission's deletion cascades to any client grants that reference it, removing a permission from `spec.permissions` also revokes it from every client that was granted it.

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

See [the API reference](../reference/pocketidapi.md) for full documentation on each available field.

## Granting Client Access

An API's permissions are granted to clients from the **`PocketIDOIDCClient`** side, via `spec.apiAccess`. Each grant references a `PocketIDAPI` and lists the permission keys to grant for the user-delegated (authorization code) flow and/or the client-credentials (machine-to-machine) flow:

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

- The client is the **sole owner** of its API access in Pocket-ID: the operator keeps it in sync with `spec.apiAccess` and revokes any access granted outside the operator, including on a client that does not set `spec.apiAccess`.
- `delegatedAccess` and `clientAccess` grant a flow with no permissions selected, for a client that requests a resource without any scopes. Both default to true when the matching permission list is non-empty, so existing grants are unaffected.
- `clientPermissions` and `clientAccess` (machine-to-machine) require a **confidential** client (`spec.isPublic: false`), since M2M needs a client secret. This is enforced at admission.
- Permission keys are resolved to Pocket-ID permission IDs from the referenced API's status, so the `PocketIDAPI` must be `Ready` before the grant can be applied.
- A `PocketIDAPI` referenced by a client cannot be deleted until the client removes the reference, preventing dangling grants.

## Granting the Built-in Pocket ID API

Pocket-ID v3 has a built-in API for Pocket ID itself, whose resource is `<appUrl>/api` and whose permissions are Pocket ID's own scopes, e.g. `users:read`. It needs no `PocketIDAPI`: set `builtIn: true` instead of `apiRef` to grant it.

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: group-sync
  namespace: pocket-id
spec:
  isPublic: false
  apiAccess:
    - builtIn: true
      clientPermissions:
        - users:read
        - groups:read
```

Notes:

- The client-credentials flow can only be granted admin scopes, so an account scope in `clientPermissions` fails the reconcile.
- A token from the user-delegated flow carries only the scopes the signed-in user holds.
- To grant the built-in API to every CIMD client, set the `PocketIDInstance`'s `spec.builtInAPI.cimdPermissions`. An empty list turns the access off, and leaving `spec.builtInAPI` unset leaves the setting to the UI.

## Granting Metadata Document Clients

Clients registered through an OAuth **Client ID Metadata Document** (CIMD) register themselves, oftentimes making management through the oidcclient custom resource cumbersome and unnecessary. To permit all API permisions to all CIMD clients in Pocket-ID, set `spec.cimdAccess: true`. To only allow a subset of the permissions to CIMD clients, set `cimdAccess` on the individual permissions. See the example and table of possible configurations below.

```yaml
spec:
  resource: https://orders.example.com
  permissions:
    - key: read:orders
      name: Read orders
      cimdAccess: true
    - key: write:orders
      name: Write orders
```

| `spec.cimdAccess` | Permissions marked | Result |
|-------------------|--------------------|--------|
| unset | one or more | Access to the marked permissions |
| unset | none | No access |
| `true` | none | Access with no permissions, for a client requesting a resource without any scopes |
| `false` | one or more | No access; the marks stay in spec, so flipping it back restores them |

Notes:

- This grants **every** CIMD client. To limit access to just a subset of CIMD clients create a custom resource for each CIMD client and use the [PocketIDOIDCClient's `spec.apiAccess`](../reference/pocketidoidcclient.md#pocketidoidcclientspecapiaccess) instead.
- Access granted here is not visible from a client's `spec.apiAccess`, so removing an `apiAccess` entry for an API that also sets `cimdAccess` does **not** revoke the client's access. The client's `status.cimdGrantedAPIs` lists what it reaches this way.

## Migrating from an existing setup

`spec.resource` is the audience (`aud`), which is **globally unique** in Pocket-ID, so on creation a `PocketIDAPI` is matched to an existing API by `spec.resource` and taken over in place.

The built-in Pocket ID API is never adopted. Pocket-ID v3 reserves `<appUrl>`, `<appUrl>/api` and `<appUrl>/api/admin/mcp`, so a `PocketIDAPI` with one of these resources stays not `Ready`. Grant it with [`builtIn: true`](#granting-the-built-in-pocket-id-api) instead.
