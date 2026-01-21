# Operator Annotations

The operator recognizes the following annotations. Apply them to the metadata of the
custom resource unless noted otherwise.

## PocketIDUser

- `pocketid.internal/delete-from-pocket-id`: when set to `"true"`, the operator will
  delete the user in Pocket-ID when the `PocketIDUser` CR is deleted. Default behavior
  is to leave the Pocket-ID user intact.

## PocketIDOIDCClient

- `pocketid.internal/regenerate-client-secret`: when set to `"true"`, the operator
  regenerates the client secret and then removes the annotation.

## Labels

All operator-managed resources include `managed-by: pocket-id-operator`. Labels from
`PocketIDInstance.spec.labels` are merged into workload and service labels.
