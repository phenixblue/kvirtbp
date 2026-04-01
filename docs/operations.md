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

For remediation-specific playbooks, see `docs/runbooks.md`.
