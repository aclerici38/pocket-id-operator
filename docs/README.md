# Pocket-ID Operator Documentation

See the guides, examples, and API reference for more in-depth documentation how to use each custom resource.

# Starting Fresh
If installing Pocket-ID for the first time with this operator the procedure should be straightforward. The only difference in features are with the `PocketIDUser` custom resources, when a user is created through the operator a one-time passcode will be generated and stored in the status of the custom resource for 60 minutes.

# Migrating from an existing setup
This operator will only try to manage the resources present in k8s, not the Pocket-ID instance as a whole. In addition each resource created will adopt any existing resource in pocket-id if there's a match. This allows users, user groups, oidc clients, and APIs to be migrated to custom resources gradually (or not at all) with no data loss.

*IMPORTANT*: Once the operator takes control of a resource its state will be continuously synced into pocket-id, so ensure any migrated custom resource contains the proper spec to prevent data loss.

**PocketIDInstance**

To migrate an existing PVC to the operator use `spec.persistence.existingClaim`. If using postgres set `spec.databaseUrl` to the full postgres database uri, e.g. `postgresql://user:password@host:port/dbname`

**PocketIDUser**

On creation a PocketIDUser is matched to an existing user by `spec.userID` if it's specified, otherwise by username, then by email. A matching user is adopted into the custom resource, allowing users to maintain their passkeys, audit logs, and user group state. See [PocketIDUser](guides/pocketiduser.md#adopting-existing-users) for more details.

**PocketIDUserGroup**

On creation a PocketIDUserGroup is matched to existing user groups by `spec.name` falling back to the resource's `metadata.name` if not specified.

**PocketIDOIDCClient**

On creation a PocketIDOIDCClient is matched to an existing OIDC client by `spec.clientID` if it's specified, otherwise by `spec.name`, falling back to the resource's name.

*IMPORTANT*: When an OIDC client is adopted the operator will generate a new client secret and store it in a k8s secret. This is due to the design of Pocket-ID, which prevents retrieval of the client secret after it is generated. If you would not like the client secret to be regenerated set `spec.secret.storeClientSecret` to `false`. See more in [the oidcclient guide](guides/pocketidoidcclient.md#externally-managed-secret).

**PocketIDAPI**

On creation a PocketIDAPI is matched to an existing API in pocket-id by `spec.resource`, its permanent and immutable audience identifier. See [PocketIDAPI](guides/pocketidapi.md) for more details.


# JSON Schemas

JSON schemas are provided for all CRDs, the Helm chart values, and a FluxCD HelmRelease with the values. Use them with `yaml-language-server` for autocompletion and validation.

If you like the schemas approach here and would like to keep more of your CRD schemas versioned with the apps, check out [k8s-versioned-schemas](https://github.com/aclerici38/k8s-versioned-schemas)!

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
| PocketIDAPI | `pocketidapi_v1alpha1.json` |
| Helm values (operator chart) | `charts/pocket-id-operator/values.schema.json` |
| Helm values (instance chart) | `charts/pocket-id-instance/values.schema.json` |
| FluxCD HelmRelease (operator chart) | `helmrelease_v2_pocket-id-operator.json` |
| FluxCD HelmRelease (instance chart) | `helmrelease_v2_pocket-id-instance.json` |

**From a release:**
To always fetch the latest schemas:
```
https://github.com/aclerici38/pocket-id-operator/releases/latest/download/pocketidinstance_v1alpha1.json
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

Note: the Helm values schemas live next to their charts (`charts/<chart>/values.schema.json`). The HelmRelease schemas are in `dist/schemas/`.

**From my k8s-versioned-schemas project (latest):**
```
https://k8s-versioned-schemas.pages.dev/pocket-id-operator/latest/pocketidinstance_v1alpha1.json
```

**From my k8s-versioned-schemas project (tagged):**
```
https://k8s-versioned-schemas.pages.dev/pocket-id-operator/0.15.0/pocketidinstance_v1alpha1.json
```
