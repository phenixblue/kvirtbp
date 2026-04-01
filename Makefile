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
