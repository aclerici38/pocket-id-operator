# Pocket-ID Operator

A Kubernetes operator for managing Pocket-ID instances and related resources. It
provisions Pocket-ID workloads and keeps users, user groups, and OIDC clients in sync
with your cluster state.

## Resources
- `PocketIDInstance`
- `PocketIDUser`
- `PocketIDUserGroup`
- `PocketIDOIDCClient`

## Documentation
Start here for detailed configuration guides:
- `docs/README.md`
- `docs/pocketidinstance.md`
- `docs/pocketiduser.md`
- `docs/pocketidusergroup.md`
- `docs/pocketidoidcclient.md`
- `docs/annotations.md`

## Quickstart
It's recommended to install this operator via the helm chart.
**Note**: the tag below is not kept up-to-date. Check the releases or packeges to find the latest version.
`helm install oci://ghcr.io/aclerici38/charts/pocket-id-operator:v0.1.0`

There will also be a generated manifest to install without helm attached to each release.

## Development

Install CRDs and deploy the controller:

```sh
make install
make deploy IMG=<registry>/pocket-id-operator:tag
```

Apply a sample instance:

```sh
kubectl apply -k config/samples/
```

## Contributing

Run `make help` for available targets. See the docs in `docs/` for CRD usage and
examples.

## License

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
