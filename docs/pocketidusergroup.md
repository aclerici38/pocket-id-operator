# PocketIDUserGroup

A `PocketIDUserGroup` manages a group in Pocket-ID. To reference any users **not** managed by a `PocketIDUser` custom resource
the spec also accepts usernames and user IDs existing in pocket-id. Any users added to the group outside the operator will **not** be overwritten when the resource is reconciled.


## Minimal Example

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: developers
  namespace: pocket-id
spec: {}
```

## Group With Claims And Members

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: platform-admins
  namespace: pocket-id
spec:
  friendlyName: "Platform Administrators"
  customClaims:
    - key: team
      value: platform
    - key: tier
      value: admin
  users:
    userRefs:
      - name: alice
      - name: bob
        namespace: pocket-id
    usernames:
      - charlie
    userIDs:
      - usr_1234567890
```

## Status Highlights

- `status.groupID`: Pocket-ID group ID.
- `status.userIDs`: resolved user IDs in the group.
- `status.customClaims`: resolved claims.

*Note:* For all options and an up-to-date spec `kubectl explain PocketIDUserGroup` 
