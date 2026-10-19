# PocketIDUserGroup

A `PocketIDUserGroup` manages a user group in Pocket-ID, including its members, custom claims, and the OIDC clients its members may access.

Like the other custom resources, the operator continuously reconciles the group in Pocket-ID to match the custom resource, so edits made in the UI to managed fields are overwritten on the next reconcile. The one exception is Users added to the group outside the operator are left in place. A group deleted in Pocket-ID is recreated.

For full documentation on each field in this CRD see [the API reference](../reference/pocketidusergroup.md). For common configurations see [the examples](../examples/pocketidusergroup.md).

## Minimal Example

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: developers
  namespace: pocket-id
spec: {}
```

`spec.name` sets the group's name in Pocket-ID and defaults to `metadata.name`. `spec.friendlyName` sets its display name and defaults to the name.

## Adopting Existing Groups

On creation, a `PocketIDUserGroup` is matched to an existing group in Pocket-ID by its name and adopted in place. Make sure the spec matches the existing group before applying it, since the operator overwrites its friendly name and custom claims on the next reconcile.

## Members

`spec.users` lists the members the operator manages, in any of three ways. See [example](../examples/pocketidusergroup.md#group-with-claims-and-members).

- `userRefs` names `PocketIDUser` custom resources, defaulting to the group's namespace. Each user must be `Ready`. A referenced `PocketIDUser` cannot be deleted until the group stops referencing it.
- `usernames` names existing Pocket-ID users not managed by a `PocketIDUser`. Each must exist in Pocket-ID, or the group reports an error until it does.
- `userIDs` adds existing Pocket-ID users by ID.

The operator only removes members it added. It records the users it manages in `status.managedUserIDs`; removing one from the spec removes them from the group, while members added in the UI or by another tool are never removed. `status.totalUserCount` counts every member.

## Custom Claims

`spec.customClaims` attaches claims to every member of the group. A [user's own claim](pocketiduser.md#custom-claims) with the same key takes precedence. The operator owns the group's full set of claims: removing an entry removes it from Pocket-ID, and claims added outside the operator are removed on the next reconcile. `status.customClaims` reports the group's claims as stored in Pocket-ID.

## Allowed OIDC Clients

A group can restrict which OIDC clients its members may access. This can be configured from either direction, and the final set of allowed clients is the union of both:

1. From the user group, with `spec.allowedOIDCClients` listing `PocketIDOIDCClient` custom resources, defaulting to the group's namespace. Each client must be `Ready`. See [example](../examples/pocketidusergroup.md#allowed-oidc-clients).
2. From the OIDC client, with [`spec.allowedUserGroups`](pocketidoidcclient.md#allowed-user-groups) on a `PocketIDOIDCClient`.

The relationship is always written to Pocket-ID by the OIDC client's reconcile, which a change on either side triggers. `status.allowedOIDCClientIDs` reports the clients the group is allowed in Pocket-ID.

`spec.allowedOIDCClients` can only reference clients with a `PocketIDOIDCClient` in this cluster. To attach a client to a group that has no `PocketIDUserGroup` here, such as one owned by another cluster or created in the UI, use `groupName` or `groupID` in the client's `spec.allowedUserGroups` instead.

## Deletion

Deleting a `PocketIDUserGroup` deletes the group from Pocket-ID. Deletion is blocked while a `PocketIDOIDCClient` references the group in `spec.allowedUserGroups`.
