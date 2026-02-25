# Pocket-ID Operator Documentation

See the other docs in this folder for more detailed documentation on the configuration available in the CRDs.

# JSON Schemas

JSON schemas are provided for all CRDs, the Helm chart values, and a FluxCD HelmRelease with the values. Use them with `yaml-language-server` for autocompletion and validation.

Add to the top of any YAML file:
```yaml
# yaml-language-server: $schema=<schema-url>
```

**Available schemas:**

| Schema | File |
|--------|------|
| PocketIDInstance | `pocketidinstance_v1alpha1.json` |
| PocketIDUser | `pocketiduser_v1alpha1.json` |
| PocketIDUserGroup | `pocketidusergroup_v1alpha1.json` |
| PocketIDOIDCClient | `pocketidoidcclient_v1alpha1.json` |
| Helm values | `values.schema.json` |
| FluxCD HelmRelease | `helmrelease_v2_pocket-id-operator.json` |

**From a release (recommended):**
To always fetch the latest schemas:
```
https://github.com/aclerici38/pocket-id-operator/releases/download/latest/pocketidinstance_v1alpha1.json
```
To fetch for a specific tag:
```
https://github.com/aclerici38/pocket-id-operator/releases/download/<version>/pocketidinstance_v1alpha1.json
```

**From the repo (latest on main):**
```
https://raw.githubusercontent.com/aclerici38/pocket-id-operator/main/dist/schemas/pocketidinstance_v1alpha1.json
```

**From the repo (pinned to a tag):**
```
https://raw.githubusercontent.com/aclerici38/pocket-id-operator/<version>/dist/schemas/pocketidinstance_v1alpha1.json
```

Note: the Helm values schema is at `dist/chart/values.schema.json` instead of `dist/schemas/`.

# Migrating from an existing setup
This operator will only try to manage the resources present in k8s, not the Pocket-ID instance as a whole. In addition each resource created will adopt any existing resource in pocket-id if there's a match. This allows users, user groups, oidc clients to be migrated to custom resources gradually (or not at all) with no data loss.

*IMPORTANT*: Once the operator takes control of a resource its state will be continuously synced into pocket-id, so ensure any migrated custom resource contains the proper spec to prevent data loss.

**PocketIDInstance**

To migrate an existing PVC to the operator use `spec.persistence.existingClaim`. If using postgres set `spec.databaseUrl` to the full postgres database uri, e.g. `postgresql://user:password@host:port/dbname`

**PocketIDUser**

When a PocketIDUser resource is created the operator will lookup any existing user in pocket-id by username. If a matching username exists the existing user ID will be adopted into the custom resource, allowing users to maintain their passkeys, audit logs, and user group state.

**PocketIDUserGroup**

On creation a PocketIDUserGroup is matched to existing user groups by `spec.name` falling back to the resource's name if not specified.

**PocketIDOIDCClient**

On creation a PocketIDOIDCClient is matched to existing user groups by `spec.clientId` if it's specified, otherwise falling back to the resource's name. 

*IMPORTANT*: When an OIDC client is adopted the operator will generate a new client secret and store it in a k8s secret. This is due to the design of Pocket-ID, which prevents retrieval of the client secret after it is generated.

# Starting Fresh
If installing Pocket-ID for the first time with this operator the procedure should be straightforward. The only difference in features are with the `PocketIDUser` custom resources, when initialized through the operator a one-time passcode will be generated and stored in the status of the custom resource for 15 minutes.