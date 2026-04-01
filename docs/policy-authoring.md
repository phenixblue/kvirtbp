# Policy Authoring Guide

This guide explains how to extend `kvirtbp` with Rego policies and equivalent Go checks.

## Evaluator model

`kvirtbp` supports two evaluators:

- `go`: built-in checks compiled into the binary.
- `rego`: policies loaded from a Rego file (`--policy-file`) or bundle directory (`--policy-bundle`).

Command examples:

```bash
./bin/kvirtbp scan --engine go
./bin/kvirtbp scan --engine rego --policy-file ./policy/custom.rego
./bin/kvirtbp scan --engine rego --policy-bundle ./policy/baseline
```

## Rego output contract

The Rego evaluator expects `data.kvirtbp.findings` to produce an array of finding objects.

Required fields per finding:

- `checkId`
- `title`
- `category`
- `severity` (`info`, `warning`/`warn`, `error`)
- `message`

Optional recommended fields:

- `reasonCode`
- `evidence` (object map)
- `remediationId`
- `remediation`
- `resourceRef`

## Minimal Rego example

```rego
package kvirtbp

findings contains {
  "checkId": "sec-example-minimal",
  "title": "Example Security Check",
  "category": "security",
  "severity": "warning",
  "message": "Example warning emitted from Rego",
  "reasonCode": "sec.example.warn",
  "remediationId": "RUNBOOK-SEC-RBAC-001",
  "remediation": "Replace example policy with real control logic"
}
```

## Bundle layout

A bundle directory can contain one or more `.rego` files and optional metadata.

Example:

- `policy/baseline/baseline.rego`
- `policy/baseline/metadata.json`

`metadata.json` fields:

- `schemaVersion` (currently `v1alpha1`)
- `policyVersion` (informational)
- `minBinaryVersion` (optional)

## Go check authoring

Built-in checks implement the check contract in `internal/checks`:

- metadata (`ID`, `Title`, `Category`, `Severity`)
- evaluate function returning findings

If you add Go checks:

1. Define metadata and evaluation logic.
2. Register in catalog/registry.
3. Ensure findings include stable `checkId` and actionable remediation guidance.
4. Add unit and fixture tests.

## Authoring conventions

- Keep `checkId` stable and machine-friendly (`domain-control-purpose`).
- Use categories already present in the project (`production-readiness`, `security`, `availability`) unless expanding taxonomy intentionally.
- Emit `reasonCode` for every non-trivial branch.
- Prefer concise, operator-actionable remediation text.
- Map remediations to a runbook ID when possible.

## Validation workflow

```bash
make test
./bin/kvirtbp scan --engine rego --policy-bundle ./policy/baseline --output json
```

For evaluator parity work, use existing equivalence tests under `internal/eval` as reference.
