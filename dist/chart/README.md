# Helm Chart

## Values Schema

`values.schema.json` is **generated** — do not edit it directly. Changes will be overwritten.

Each edit to the chart's values should be reflected in the schema.
To modify the schema, edit `values.schema.skeleton.json`. The skeleton file contains the base schema structure with placeholder `$ref` entries that get resolved to the full CRD schemas during generation.

### Regenerating

Run:

```sh
make generate-schemas
```

This will:

1. Download the [`openapi2jsonschema.py`](https://github.com/yannh/kubeconform) script from kubeconform
2. Convert the CRD OpenAPI specs in `config/crd/bases/` to standalone JSON schemas (output to `dist/schemas/`)
3. Merge those schemas into the skeleton to produce the final `values.schema.json`
4. Generate a FluxCD HelmRelease schema with the values schema embedded

Requires [uv](https://docs.astral.sh/uv/) (used to run the Python script via `uvx` with the `pyyaml` dependency).
