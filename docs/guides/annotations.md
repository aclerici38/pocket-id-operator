# Annotations and Labels

## Annotations

The operator recognizes the following annotations on its custom resources.

### PocketIDUser

- `pocketid.internal/delete-from-pocket-id`: when `"true"`, deleting the `PocketIDUser` also deletes the user from Pocket-ID. By default the Pocket-ID user is left intact. See [Deletion](pocketiduser.md#deletion).

### PocketIDOIDCClient

- `pocketid.internal/regenerate-client-secret`: when `"true"`, the operator regenerates the client secret and then removes the annotation. It is ignored (but still removed, and the reason logged) when `spec.clientSecretRef` is set or `spec.secret.storeClientSecret` is `false`. See [Regenerating the Client Secret](pocketidoidcclient.md#regenerating-the-client-secret).
- `pocketid.internal/refresh-client-metadata`: when `"true"`, the operator makes Pocket-ID re-fetch the client's OAuth Client ID Metadata Document, bypassing the cache TTL. The annotation is removed before the call, so a rejected refresh (on a `standard` client, or with CIMD not enabled on the instance) fires once and is reported on the `Ready` condition rather than retried forever. See [Client ID Metadata Documents](pocketidoidcclient.md#client-id-metadata-documents).

## Labels

Every resource the operator creates carries the label `managed-by: pocket-id-operator`, and the operator never deletes a resource without it, so a same-named resource you created yourself is left alone. Labels from `PocketIDInstance.spec.labels` are added to the instance's workload, pod template, Service, and PVC.
