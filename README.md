# kapture

`kapture` is a Kubernetes cluster inspection CLI that collects runtime data and evaluates it against defined policy checks.

The functionality of the CLI is customizable via the `Collector` model

`Collectors` are short-lived Kubernetes Jobs that `kapture` deploys to gather node or cluster-level data that can't be obtained through the standard Kubernetes API alone — things like hugepage info, host-level metrics, or storage state.

Collectors are declared by a Policy Bundle consistung of a metadata.json file that explains specifics about the collector deployment (ie. container image, commands to run, permissions, etc.) and Rego policy file(s) to define checks. These Bundles can be hosted locally or via HTTP. [Read more about Collectors here](docs/collectors.md)

## Quickstart

```bash
make tidy
make build
./bin/kapture version
./bin/kapture checks
./bin/kapture scan --output table
./bin/kapture scan --output json
./bin/kapture scan --kubeconfig ~/.kube/config --context my-context
./bin/kapture scan --category production-readiness --severity warning
./bin/kapture scan --check kubevirt-api-availability --exclude-check bootstrap-placeholder
./bin/kapture scan --engine rego
./bin/kapture scan --engine rego --policy-file ./policy/custom.rego
./bin/kapture scan --engine rego --policy-bundle ./policy/bundle
./bin/kapture scan --engine rego --policy-bundle ./policy/baseline
./bin/kapture scan --namespace tenant-a --exclude-namespace tenant-a-shared
./bin/kapture scan --exclude-namespace "openshift-*" --exclude-namespace "cattle-*"
./bin/kapture scan --show-runbook --output table
./bin/kapture runbook
./bin/kapture runbook --id RUNBOOK-SEC-RBAC-001

# Collector workflow — gather node/cluster data then scan with it
./bin/kapture collect --bundle ./policy/baseline --output collector-data.json
./bin/kapture collect --collector-config ./my-collectors.json --output collector-data.json
./bin/kapture scan --engine rego --policy-bundle ./policy/baseline --collector-data collector-data.json

# Remote bundle (HTTPS tarball)
./bin/kapture collect --bundle https://github.com/myorg/policies/archive/refs/tags/v1.2.0.tar.gz --output collector-data.json
./bin/kapture scan --engine rego --policy-bundle https://github.com/myorg/policies/archive/refs/tags/v1.2.0.tar.gz --collector-data collector-data.json

# Remote monorepo (bundle lives under a subdirectory)
./bin/kapture scan --engine rego \
  --policy-bundle https://github.com/myorg/policies/archive/refs/tags/v1.2.0.tar.gz \
  --bundle-subdir policy/kubevirt --collector-data collector-data.json
```

## Homebrew

Install from the project tap:

```bash
brew tap phenixblue/tap
brew install kapture
```

Homebrew formula publishing is handled by GoReleaser on version tags (`v*`) via `.github/workflows/release.yml`.

See [docs/homebrew.md](docs/homebrew.md) for upgrade, uninstall, version pinning, integrity verification, and tap maintenance details.

Tap/release prerequisites:

- Tap repository exists and is writable (default target: `phenixblue/homebrew-tap`)
- GitHub Actions secret `HOMEBREW_TAP_GITHUB_TOKEN` is configured with repo write access to the tap repository
- Optional override environment variables for GoReleaser:
	- `HOMEBREW_TAP_OWNER`
	- `HOMEBREW_TAP_NAME`

To test release packaging without publishing:

```bash
make release-snapshot
```

For local dry runs that include SBOM generation and Homebrew formula output but skip signing:

```bash
make release-local
```

Release mode comparison:

| Mode | Command/Trigger | Publish GitHub Release | Publish Homebrew Tap | Generate SBOM | Sign Artifacts |
| --- | --- | --- | --- | --- | --- |
| Local snapshot | `make release-snapshot` | No | No | Yes | Yes (requires local cosign auth) |
| Local packaging dry run | `make release-local` | No | No | Yes | No |
| CI release | Push tag `v*` | Yes | Yes | Yes | Yes (OIDC in Actions) |

## Configuration

Environment variables use the `KAPTURE_` prefix.

- `KAPTURE_OUTPUT` (`table` or `json`, default: `table`)
- `KAPTURE_TIMEOUT` (Go duration string, default: `30s`)
- `KAPTURE_CONCURRENCY` (default: `4`)

Scan command supports:

- `--kubeconfig` to set a kubeconfig path
- `--context` to override kube context
- `--check` and `--exclude-check` to include/exclude by check ID
- `--namespace` and `--exclude-namespace` to scope namespace-based coverage controls (supports glob patterns like `tenant-*`)
- `--category` and `--severity` to filter findings
- `--engine` to select evaluator backend (`go` and `rego`)
- `--policy-file` to provide a custom Rego policy file with `data.kapture.findings` output
- `--policy-bundle` to provide a local directory or HTTPS `.tar.gz` URL of `.rego` files with optional `metadata.json`
- `--bundle-subdir` to point at a subdirectory within a remote archive (for monorepo layouts)
- `--show-runbook` to append compact runbook hints for failing findings
- `--collector-data` to inject pre-collected node/cluster data into `input.cluster.collectors` for Rego policies

Namespace scoping precedence for namespace-based coverage controls:

- system namespaces are always excluded first
- `--namespace` include filters are applied next (if provided)
- `--exclude-namespace` filters are applied last and win on conflicts

Rego finding contract is validated strictly. Each finding must include:

- `checkId`
- `title`
- `category`
- `severity` (`info`, `warning`/`warn`, or `error`)
- `message`

Baseline control findings also include:

- `reasonCode` for machine-parseable outcome classification
- `evidence` map with preflight signal states used in the decision
- `remediationId` for stable runbook lookup
- `remediation` guidance when action is required

Top-level JSON report metadata includes scan execution context:

- `metadata.engine` evaluator backend used (`go` or `rego`)
- `metadata.namespaceInclude` and `metadata.namespaceExclude` filters in effect
- `metadata.clusterContextHash` deterministic hash for cluster context correlation
- `metadata.clusterContextHashVersion` hash algorithm/input contract version (currently `v1`)
- `metadata.durationMillis` scan runtime in milliseconds
- `metadata.policyFile` and `metadata.policyBundle` when provided
- `metadata.kubeContext` and `metadata.kubeconfigProvided`

Runbook mappings are documented in [docs/runbooks.md](docs/runbooks.md).

Additional documentation:

- [docs/check-catalog.md](docs/check-catalog.md)
- [docs/policy-authoring.md](docs/policy-authoring.md)
- [docs/collectors.md](docs/collectors.md)
- [docs/operations.md](docs/operations.md)
- [docs/workflows.md](docs/workflows.md)

Policy bundle metadata (optional `metadata.json`):

- `schemaVersion`: currently `v1alpha1`
- `policyVersion`: informational version for your bundle
- `minBinaryVersion`: optional minimum CLI version (for example `1.2.0`)
- `collectors`: optional array of `CollectorConfig` objects that `kapture collect` will run automatically when `--bundle` is provided (see [docs/collectors.md](docs/collectors.md))

Checked-in baseline Rego bundle:

- `policy/baseline/baseline.rego`
- `policy/baseline/metadata.json`

If cluster connectivity is unavailable, the command emits degraded-mode findings instead of crashing.

Exit codes:

- `0`: no failing findings
- `2`: policy/check violations detected
- `3`: partial/degraded scan (for example, cluster connectivity/discovery limitations)

## Development

```bash
make fmt
make test
make build
make e2e-kind-pass
make e2e-kind-fail
```

### Kind + KubeVirt E2E Profiles

The `e2e-kind-pass` and `e2e-kind-fail` targets call `scripts/e2e_kind_scan.sh` to:

1. create a kind cluster profile
2. install/configure KubeVirt
3. run `kapture scan` against that cluster

Behavior:

- `make e2e-kind-pass`: expects scan exit code `0`
- `make e2e-kind-fail`: expects scan exit code to be non-zero

Useful environment variables:

- `KUBEVIRT_VERSION` (default `v1.2.2`)
- `SCAN_ENGINE` (default `go`)
- `VM_COUNT` (default `3`)
- `WAIT_FOR_VMIS` (`true` by default)
- `VMI_WAIT_TIMEOUT_SECONDS` (default `180`)
- `VMI_WAIT_INTERVAL_SECONDS` (default `5`)
- `CLUSTER_NAME` (mode-specific default)
- `TARGET_NAMESPACE` (mode-specific default)
- `RECREATE_CLUSTER` (`true` by default)

Manual CI execution:

- Use GitHub Actions workflow `e2e-manual` (`workflow_dispatch`) to run the same pass/fail profiles on demand.
