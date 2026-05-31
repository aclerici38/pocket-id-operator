# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/aclerici38/pocket-id-operator:v0.6.1@sha256:2c6b9c89e2e7f4300eaeef7c2853cd7ca9961eeb19e676bbeccdc69c4282dd9c

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=pocket-id-operator-manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	@rm -rf dist/chart/crds
	@mkdir -p dist/chart/crds
	@cp config/crd/bases/*.yaml dist/chart/crds/
	@awk '/^metadata:$$/ { \
	  print; \
	  print "  labels:"; \
	  print "    {{- include \"chart.labels\" . | nindent 4 }}"; \
	  next \
	} 1' config/rbac/role.yaml > dist/chart/templates/rbac/manager-role.yaml

.PHONY: generate-schemas
generate-schemas: manifests ## Generate JSON schemas from CRDs for yaml-language-server support.
	@command -v uvx >/dev/null 2>&1 || { echo "Error: uvx not found. Install uv: https://docs.astral.sh/uv/getting-started/installation/"; exit 1; }
	@mkdir -p dist/schemas
	@rm -f dist/schemas/*.json
	@curl -sfL https://raw.githubusercontent.com/yannh/kubeconform/master/scripts/openapi2jsonschema.py -o /tmp/openapi2jsonschema.py
	@cd dist/schemas && uvx --with pyyaml python /tmp/openapi2jsonschema.py $(CURDIR)/config/crd/bases/*.yaml
	@jq --slurpfile instance dist/schemas/pocketidinstance_v1alpha1.json \
		--slurpfile user dist/schemas/pocketiduser_v1alpha1.json \
		--slurpfile usergroup dist/schemas/pocketidusergroup_v1alpha1.json \
		'.properties.instance.then.properties.spec = $$instance[0].properties.spec | .properties.users.items.properties.spec = $$user[0].properties.spec | .properties.userGroups.items.properties.spec = $$usergroup[0].properties.spec' \
		dist/chart/values.schema.skeleton.json > dist/chart/values.schema.json
	@curl -sfL https://datreeio.github.io/CRDs-catalog/helm.toolkit.fluxcd.io/helmrelease_v2.json -o /tmp/helmrelease_v2.json
	@jq --slurpfile values dist/chart/values.schema.json \
		'.properties.spec.properties.values = $$values[0]' \
		/tmp/helmrelease_v2.json > dist/schemas/helmrelease_v2_pocket-id-operator.json

.PHONY: generate
generate: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet test-only ## Run tests.

.PHONY: test-only
test-only: setup-envtest ## Run tests without generating manifests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out -timeout 90s

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# CertManager is installed by default; skip with:
CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= pocket-id-operator-test-e2e
# E2E_FOCUS_FILE optionally scopes e2e runs to a specific file/line pattern via ginkgo --focus-file.
# Example: E2E_FOCUS_FILE=test/e2e/httproute_test.go make test-e2e
E2E_FOCUS_FILE ?=

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster for e2e tests if it does not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet test-e2e-only ## Run the e2e tests. Expected an isolated environment using Kind.

.PHONY: test-e2e-only
test-e2e-only: setup-test-e2e ## Run e2e tests without generating manifests. Use E2E_FOCUS_FILE to run a specific e2e file.
	$(if $(filter file,$(origin IMG)),,IMG=$(IMG) )KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) "$(GINKGO)" -tags=e2e -v -procs=8 $(if $(strip $(E2E_FOCUS_FILE)),--focus-file='$(E2E_FOCUS_FILE)',) ./test/e2e/

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

.PHONY: lint
lint: ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name pocket-id-operator-builder
	$(CONTAINER_TOOL) buildx use pocket-id-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm pocket-id-operator-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply --server-side -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image ghcr.io/aclerici38/pocket-id-operator=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply --server-side -f -

.PHONY: deploy-e2e
deploy-e2e: manifests ## Deploy controller with a faster resync interval for e2e tests.
	cd config/manager && "$(KUSTOMIZE)" edit set image ghcr.io/aclerici38/pocket-id-operator=${IMG}
	"$(KUSTOMIZE)" build config/e2e | "$(KUBECTL)" apply --server-side -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

# Tool versions are managed by mise (see mise.toml), not this Makefile. Run
# `mise install` once (CI uses mise-action) so the pinned binaries are on PATH;
# the targets below just call them by name.

## Location envtest installs its downloaded Kubernetes binaries to.
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool binaries come from mise (see mise.toml)
## run `mise install` locally before any targets
## or set a custom path like `make deploy KUBECTL=/path/to/kubectl`.
KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= kustomize
CONTROLLER_GEN ?= controller-gen
ENVTEST ?= setup-envtest
GOLANGCI_LINT ?= golangci-lint
GINKGO ?= ginkgo

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

.PHONY: setup-envtest
setup-envtest: ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
