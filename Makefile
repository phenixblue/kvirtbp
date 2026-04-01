BINARY ?= kvirtbp

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: fmt
fmt:
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
