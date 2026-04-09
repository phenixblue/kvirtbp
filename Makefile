BINARY ?= kvirtbp

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: fmt
fmt:
	gofmt -w ./cmd ./internal

.PHONY: fmt-local
fmt-local:
	go mod tidy
	gofmt -w ./cmd ./internal

.PHONY: test
test:
	go test ./...

.PHONY: test-report-contract
test-report-contract:
	go test ./internal/report -run 'TestWriteJSON'

.PHONY: build
build:
	mkdir -p bin
	go build -o bin/$(BINARY) ./cmd/kvirtbp

.PHONY: e2e-kind-pass
e2e-kind-pass:
	bash ./scripts/e2e_kind_scan.sh pass

.PHONY: e2e-kind-fail
e2e-kind-fail:
	bash ./scripts/e2e_kind_scan.sh fail

.PHONY: lint
lint:
	golangci-lint run

.PHONY: rego-fmt
rego-fmt:
	opa fmt --v0-compatible --write ./policy/ ./internal/eval/rego/policy/ ./test/fixtures/

.PHONY: rego-check
rego-check:
	opa check --v0-compatible ./policy/ ./internal/eval/rego/policy/ ./test/fixtures/

.PHONY: rego-test
rego-test:
	opa test --v0-compatible ./policy/ -v

.PHONY: e2e-kind-custom-bundle-pass
e2e-kind-custom-bundle-pass:
	bash ./scripts/e2e_kind_custom_bundle.sh pass

.PHONY: e2e-kind-custom-bundle-fail
e2e-kind-custom-bundle-fail:
	bash ./scripts/e2e_kind_custom_bundle.sh fail

.PHONY: bench
bench:
	go test ./internal/checks ./internal/report -bench=. -benchmem -run='^$$'

.PHONY: perf
perf:
	go test ./internal/checks ./internal/report -run 'LatencyBudget|Scale' -v

.PHONY: release-snapshot
release-snapshot:
	goreleaser release --snapshot --clean --skip=publish

.PHONY: release-local
release-local:
	goreleaser release --snapshot --clean --skip=publish,sign

# lab-px-kubevirt stands up a kind cluster with Portworx Enterprise, KubeVirt,
# and two small VMs backed by Portworx ReadWriteMany volumes.  It is intended
# as a realistic target for the portworx-kubevirt collector + policy bundle.
#
# ARCHITECTURE: x86_64 (amd64) ONLY. Portworx px-runc is x86_64-only and
# cannot run under Rosetta 2 on Apple Silicon. Use an x86_64 Linux host.
#
# Prerequisites: kind, kubectl, docker.  A 30-day Portworx Enterprise trial
# starts automatically.  Recommended: 16 GB RAM, 6 CPU, 80 GB disk.
#
# All stages are controlled by environment variables; see the script header for
# the full list.  Example override:
#   make lab-px-kubevirt PX_VERSION=3.2.0 PX_OPERATOR_TAG=portworx-24.1.0 DISK_SIZE_GB=30
.PHONY: lab-px-kubevirt
lab-px-kubevirt:
	bash ./scripts/e2e_kind_px_kubevirt.sh

# lab-px-kubevirt-teardown deletes the kind cluster created by lab-px-kubevirt.
# Override CLUSTER_NAME to match a non-default cluster name.
.PHONY: lab-px-kubevirt-teardown
lab-px-kubevirt-teardown:
	kind delete cluster --name "$${CLUSTER_NAME:-kvirtbp-px-kubevirt}"

# lab-k3s-kubevirt stands up a k3d (k3s-in-Docker) cluster with Portworx
# Enterprise, KubeVirt, and two small VMs backed by Portworx ReadWriteMany
# volumes.  Uses k3s as the Kubernetes distribution instead of full upstream
# Kubernetes.  Intended as a realistic target for the portworx-kubevirt
# collector + policy bundle.
#
# ARCHITECTURE: x86_64 (amd64) ONLY. Same Portworx px-runc constraint as the
# kind variant. Use an x86_64 Linux host.
#
# Prerequisites: k3d, kubectl, docker.  A 30-day Portworx Enterprise trial
# starts automatically.  Recommended: 16 GB RAM, 6 CPU, 80 GB disk.
#
# All stages are controlled by environment variables; see the script header for
# the full list.  Example override:
#   make lab-k3s-kubevirt PX_VERSION=3.2.0 K3S_IMAGE=rancher/k3s:v1.29.2-k3s1
.PHONY: lab-k3s-kubevirt
lab-k3s-kubevirt:
	bash ./scripts/e2e_k3s_px_kubevirt.sh

# lab-k3s-kubevirt-teardown deletes the k3d cluster created by lab-k3s-kubevirt.
# Override CLUSTER_NAME to match a non-default cluster name.
.PHONY: lab-k3s-kubevirt-teardown
lab-k3s-kubevirt-teardown:
	k3d cluster delete "$${CLUSTER_NAME:-kvirtbp-k3s-kubevirt}"
