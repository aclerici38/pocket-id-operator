# Helm Chart

## Removed values

The top-level `instance`, `users`, and `userGroups` values were removed. Move them under
`pocket-id-instance` with the same names so Helm updates the existing resources in place.
The chart fails to render while the old values are still set, or while the release still
owns resources they created. `instance.enabled: false` is still accepted, but it does nothing
and can be removed.

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
