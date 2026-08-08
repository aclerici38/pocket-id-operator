# Operator Annotations

The operator recognizes the following annotations.

## PocketIDUser

- `pocketid.internal/delete-from-pocket-id`: when set to `"true"`, the operator will
  delete the user in Pocket-ID when the `PocketIDUser` CR is deleted. Default behavior
  is to leave the Pocket-ID user intact.

## PocketIDOIDCClient

- `pocketid.internal/regenerate-client-secret`: when set to `"true"`, the operator
  regenerates the client secret and then removes the annotation. It is ignored (but still
  removed, and the reason logged) when `spec.clientSecretRef` is set or
  `spec.secret.storeClientSecret` is `false`.
- `pocketid.internal/refresh-client-metadata`: when set to `"true"`, the operator forces
  the adopted client to re-fetch its OAuth Client ID Metadata Document, bypassing the
  cache TTL. The annotation is removed before the call, so a rejected refresh (a
  `standard` client, or CIMD not enabled on the instance) fires once and surfaces on the
  `Ready` condition rather than retrying forever.

## Labels

All operator-managed resources include `managed-by: pocket-id-operator`. Labels from
`PocketIDInstance.spec.labels` are merged into workload and service labels.
