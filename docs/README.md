# Pocket-ID Operator Documentation

See the other docs in this folder for more detailed documentation on the configuration available in the CRDs.

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