# Helm Chart

## Deprecations

Declaring Pocket ID resources (`instance`, `users`, `userGroups`) in this chart is
**deprecated** and will be removed in a future release. The operator chart will then
manage only the controller, CRDs, and monitoring.

Migrate those resources to the dedicated
[`pocket-id-instance`](../pocket-id-instance) chart, or apply the `PocketID*` custom
resources directly. Set `instance.enabled=false` (and clear `users`/`userGroups`) once
migrated.

## Values Schema

`values.schema.json` is **generated** — do not edit it directly. Changes will be overwritten.

Each edit to the chart's values should be reflected in the schema.
To modify the schema, edit `values.schema.skeleton.json`. The skeleton file contains the base schema structure with placeholder `$ref` entries that get resolved to the full CRD schemas during generation.

### Regenerating

Run:

```sh
mise run generate-schemas
```

This will:

1. Convert the CRD OpenAPI specs in `config/crd/bases/` to standalone JSON schemas (output flat to `dist/schemas/`)
2. Merge those schemas into the skeleton to produce the final `values.schema.json`
3. Generate a FluxCD HelmRelease schema with the values schema embedded

Conversion uses [`crd-schema-publisher`](https://github.com/sholdee/crd-schema-publisher) (installed via mise here)
