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
