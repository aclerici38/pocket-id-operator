# pocket-id-instance

A Helm chart that packages the custom resources reconciled by
[pocket-id-operator](https://github.com/aclerici38/pocket-id-operator): a
`PocketIDInstance` plus the `PocketIDUser`, `PocketIDUserGroup`, and
`PocketIDOIDCClient` resources on it.

## Prerequisites

- The `pocket-id-operator` crds installed in the cluster. 
  This chart intentionally does **not** bundle the CRDs.

## Install

```sh
helm install my-pocket-id ./charts/pocket-id-instance \
  --namespace pocket-id --create-namespace \
  --set instance.spec.appUrl=https://auth.example.com \
  --set instance.spec.encryptionKey.valueFrom.secretKeyRef.name=pocket-id-encryption-key \
  --set instance.spec.encryptionKey.valueFrom.secretKeyRef.key=encryptionKey
```

This deploys a Pocket ID instance with persistence enabled. You must supply an
`ENCRYPTION_KEY` (see below) — the chart never generates one.

## Values

| Key | Description | Default |
| --- | --- | --- |
| `instance.enabled` | Render a `PocketIDInstance` | `true` |
| `instance.name` | Name of the instance resource | chart name (`pocket-id-instance`) |
| `instance.serviceMonitor.enabled` | Create a `ServiceMonitor` when the CRD is present | `true` |
| `instance.spec` | Passed through to the `PocketIDInstance` CRD | see `values.yaml` |
| `users` | List of `{name, spec, labels?, annotations?}` → `PocketIDUser` | `[]` |
| `userGroups` | List of `{name, spec, labels?, annotations?}` → `PocketIDUserGroup` | `[]` |
| `oidcClients` | List of `{name, spec, labels?, annotations?}` → `PocketIDOIDCClient` | `[]` |
| `apis` | List of `{name, spec, labels?, annotations?}` → `PocketIDAPI` | `[]` |

Every `spec` maps 1:1 to the corresponding CRD, so any operator field is
settable even if not listed above. See the per-resource docs:

- [PocketIDInstance](https://github.com/aclerici38/pocket-id-operator/blob/main/docs/pocketidinstance.md)
- [PocketIDUser](https://github.com/aclerici38/pocket-id-operator/blob/main/docs/pocketiduser.md)
- [PocketIDUserGroup](https://github.com/aclerici38/pocket-id-operator/blob/main/docs/pocketidusergroup.md)
- [PocketIDOIDCClient](https://github.com/aclerici38/pocket-id-operator/blob/main/docs/pocketidoidcclient.md)
- [PocketIDAPI](https://github.com/aclerici38/pocket-id-operator/blob/main/docs/pocketidapi.md)

## Values Schema

`values.schema.json` is **generated** — do not edit it directly. Changes will be overwritten.

To modify the schema, edit `values.schema.skeleton.json` (the base structure with
placeholder entries that get resolved to the full CRD schemas), then run:

```sh
mise run generate-schemas
```

This also emits a FluxCD HelmRelease schema with this chart's values embedded
(`dist/schemas/helmrelease_v2_pocket-id-instance.json`). See the
[schemas docs](https://github.com/aclerici38/pocket-id-operator/blob/main/docs/README.md#json-schemas)
for how to wire them into `yaml-language-server`.

## Encryption key

Pocket ID v2 requires a 16+ character `ENCRYPTION_KEY` for a deployed instance.
The chart **never** generates or manages this key.

Create the Secret yourself, then reference it:

```sh
kubectl -n pocket-id create secret generic pocket-id-encryption-key \
  --from-literal=encryptionKey="$(openssl rand -hex 16)"
```

```yaml
instance:
  spec:
    encryptionKey:
      valueFrom:
        secretKeyRef:
          name: pocket-id-encryption-key
          key: encryptionKey
```

A plain `instance.spec.encryptionKey.value` is also accepted but not
recommended. `encryptionKey` and `external` are mutually exclusive (enforced by
the CRD).

## Multi-instance / selector labels

Each `PocketIDUser`, `PocketIDUserGroup`, and `PocketIDOIDCClient` binds to an
instance via `spec.instanceSelector`. This chart wires that up automatically: it
labels the `PocketIDInstance` with `pocketid.internal/instance: <instance.name>`
and stamps a matching `instanceSelector` onto every child resource.

That means you can deploy this chart multiple times with different
`instance.name` values and each release's users/groups/clients stay bound to
their own instance without manually managing the label selectors. Notes:

- A resource that sets its own `spec.instanceSelector` is left untouched. To
  bind on a different label, add it via `instance.labels` and set the matching
  `spec.instanceSelector` on the resource.
- When `instance.enabled: false`, no selector is injected (the operator then
  expects exactly one instance in the cluster, or you set selectors yourself).

## Adopting an external instance

Point the operator at an existing Pocket ID instead of deploying one:

```yaml
instance:
  spec:
    external:
      url: https://auth.example.com
      apiKeySecretRef:
        name: pocket-id-api-key
        key: apiKey
```

`external` and `encryptionKey` are mutually exclusive.

## Example

```yaml
instance:
  spec:
    appUrl: https://auth.example.com
    encryptionKey:
      valueFrom:
        secretKeyRef:
          name: pocket-id-encryption-key
          key: encryptionKey

users:
  - name: admin
    spec:
      admin: true
      email:
        value: admin@example.com

userGroups:
  - name: admins
    spec:
      friendlyName: Admins
      users:
        userRefs:
          - name: admin

oidcClients:
  - name: grafana
    spec:
      callbackUrls:
        - https://grafana.example.com/login/generic_oauth
      pkceEnabled: true
      allowedUserGroups:
        - name: admins

apis:
  - name: orders-api
    spec:
      resource: https://orders.example.com
      permissions:
        - key: read:orders
          name: Read orders
```
