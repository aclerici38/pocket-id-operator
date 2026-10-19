# PocketIDUserGroup Examples

Common `PocketIDUserGroup` configurations. For how each feature behaves see [the PocketIDUserGroup guide](../guides/pocketidusergroup.md), and for every field see [the API reference](../reference/pocketidusergroup.md).

## Group With Claims and Members

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
      - name: jsmith                # a PocketIDUser CR
      - name: bob
        namespace: pocket-id        # optional, defaults to the group's namespace
    usernames:
      - charlie                     # an existing Pocket-ID user, by username
    userIDs:
      - 9c1e4b7a-2f3d-4a8e-b6c5-1d2e3f4a5b6c   # an existing Pocket-ID user, by ID
```

## Allowed OIDC Clients

```yaml
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: platform-admins
  namespace: pocket-id
spec:
  friendlyName: "Platform Administrators"
  allowedOIDCClients:
    - name: internal-dashboard
    - name: monitoring-app
      namespace: observability
  users:
    userRefs:
      - name: jsmith
```
