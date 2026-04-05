# Operations Guide

This guide covers running `kvirtbp` in clusters, required RBAC, degraded-mode behavior, waivers, and troubleshooting.

## RBAC prerequisites

The scanner expects read/list access to:

- `nodes`
- `namespaces`
- `networkpolicies`
- `resourcequotas`
- `limitranges`
- `poddisruptionbudgets`
- `kubevirt.io/virtualmachines`

Insufficient access is reported as explicit permission findings (`perm-list-*`) and may degrade security/availability baseline outcomes.

The `collect` subcommand creates Kubernetes Jobs and therefore requires additional permissions in the collector namespace:

- `batch/jobs` — create, get, list, delete
- `pods/log` — get (to read Job output)
- `namespaces` — get, create (only if `--collector-namespace` does not already exist)

## Collector workflow

The `collect` subcommand deploys short-lived Kubernetes Jobs to gather data that Rego policies can reference via `input.cluster.collectors`. This is a separate step from `scan`; the scan command itself makes no cluster writes.

Typical two-step workflow:

```bash
# Step 1: collect — writes collector-data.json
./bin/kvirtbp collect --bundle ./policy/baseline --output collector-data.json

# Step 2: scan — injects collected data, makes no cluster writes
./bin/kvirtbp scan --engine rego --policy-bundle ./policy/baseline \
    --collector-data collector-data.json
```

Key `collect` flags:

- `--bundle` — loads collector definitions from a bundle's `metadata.json` automatically
- `--collector-config` — path to a standalone JSON file of `[]CollectorConfig`; merged with bundle collectors (file wins on name collision)
- `--collector-namespace` — Kubernetes namespace for Jobs (default: `kvirtbp-collectors`; created if absent)
- `--collector-timeout` — maximum time to wait for all collectors (default: `5m`)
- `--no-collector-cleanup` — keep completed Jobs after collection (useful for debugging)
- `--output` — path for the collector data JSON file (default: `collector-data.json`)

Collector Jobs are deleted automatically after completion unless `--no-collector-cleanup` is set. A `TTLSecondsAfterFinished` of 300 seconds is also set on each Job as a safety net.

## Runtime behavior

Key runtime flags:

- `--kubeconfig`
- `--context`
- `--namespace`
- `--exclude-namespace`
- `--engine go|rego`
- `--policy-file`
- `--policy-bundle`
- `--waiver-file`
- `--show-runbook`
- `--collector-data` (inject pre-collected node/cluster data into `input.cluster.collectors`)

Output modes:

- `--output table` (human-readable)
- `--output json` (automation)

## Degraded mode semantics

If cluster initialization or discovery fails, findings include:

- `cluster-connectivity` and/or
- `cluster-discovery`

Exit code behavior:

- `0`: no non-waived failures
- `2`: violations
- `3`: partial/degraded scan (connectivity or discovery failures)

## Waiver operations

Waivers allow justified, visible exceptions for findings.

Example waiver file:

```yaml
apiVersion: kvirtbp/v1alpha1
kind: WaiverList
waivers:
  - checkId: sec-baseline-rbac-safety
    justification: "Temporary exception during migration"
    owner: platform-team
    expires: "2026-12-31"
```

Run with:

```bash
./bin/kvirtbp scan --waiver-file ./waivers.yaml
```

Waiver rules:

- `checkId`, `justification`, and `owner` are required.
- `expires` is optional and must be `YYYY-MM-DD` if set.
- Expired waivers are ignored.
- Waived findings remain visible in reports and JSON output.

## Troubleshooting quick reference

- Connectivity failures:
  - Confirm kubeconfig path and context.
  - Confirm API server reachability from execution environment.
- Discovery failures:
  - Confirm API aggregation health.
  - Verify authn/authz permits discovery endpoints.
- KubeVirt API missing:
  - Confirm KubeVirt is installed and CRDs are registered.
- Security coverage failures:
  - Apply PSA enforce labels and baseline NetworkPolicies.
- Namespace guardrail failures:
  - Add ResourceQuota and LimitRange to targeted namespaces.
- Collector failures:
  - Check Job status in the collector namespace: `kubectl get jobs -n kvirtbp-collectors`
  - Use `--no-collector-cleanup` to retain failed Jobs for log inspection.
  - Ensure the scanning identity has `batch/jobs` create/get/delete and `pods/log` get in the collector namespace.

For remediation-specific playbooks, see `docs/runbooks.md`.
