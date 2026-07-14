# Helm Chart

## Deprecations

Declaring Pocket ID resources via the top-level `instance`, `users`, and `userGroups`
keys is **deprecated** and will be removed in a future release. Two migration options:

1. **In place (recommended, no resource recreation).** Move your config under the bundled
   [`pocket-id-instance`](../pocket-id-instance) subchart's `pocket-id-instance` key and set
   its `instance.enabled: true`. The deprecated top-level block then steps aside
   automatically, so resources stay in the same release and are patched in place rather than
   recreated.
2. **Separate release.** Install the standalone [`pocket-id-instance`](../pocket-id-instance)
   chart, or apply the `PocketID*` custom resources directly. Take care to avoid
   recreating an existing instance (Helm ownership moves to the new release).

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
