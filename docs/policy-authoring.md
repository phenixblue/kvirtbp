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

## How the Rego engine works

Every scan runs in **hybrid mode** regardless of `--engine`. The pipeline in `scan.go` is always:

```
1. evaluator.Evaluate()              ← Rego or Go, against the check catalog only
2. kube.BuildPreflightFindingsWithOptions()  ← always runs; appends live cluster findings
3. ApplyBaselineAssessments()
4. ApplyWaivers() (if --waiver-file)
5. FilterFindings()
```

**The Rego engine does not evaluate cluster state.** It has no access to namespaces, nodes, NetworkPolicies, or any other live Kubernetes resources. That evaluation is always performed by the Go kube preflight layer in step 2.

What the Rego engine does instead is evaluate the **check catalog** — the set of controls registered in the binary. Think of it as a policy gate over the catalog: enforce which controls must be present, which categories must have a minimum count, or add custom catalog-level findings before the cluster checks run.

`input.checks` is an array of catalog objects — one per registered check:

```json
[
  { "id": "kubevirt-api-availability",   "title": "KubeVirt API Availability",                   "category": "production-readiness", "severity": "info" },
  { "id": "sec-networkpolicy-coverage",  "title": "Security Namespace NetworkPolicy Coverage",    "category": "security",             "severity": "warning" },
  { "id": "sec-namespace-psa-enforce",   "title": "Security Namespace Pod Security Admission",    "category": "security",             "severity": "warning" },
  { "id": "avail-pdb-coverage",          "title": "Availability PodDisruptionBudget Coverage",    "category": "availability",         "severity": "warning" }
]
```

There is no `input.namespaces`, `input.nodes`, or `input.networkPolicies`. If you want to enforce policy against live cluster resources, write a Go check in `internal/kube/preflight.go` using the Kubernetes client.

Your Rego policy reads from `input.checks` and writes to `data.kvirtbp.findings`. Those findings are merged with the cluster findings from step 2 before being reported.

## Single-check example

The smallest useful policy adds one catalog-level finding: assert that a specific control is registered before the cluster evaluation runs. This can act as a compliance gate — fail the scan if a required check was accidentally removed from the binary.

```rego
package kvirtbp

# Assert that the network-policy coverage check is registered.
# If it is missing, the whole scan should be treated as a violation.

findings := [finding |
    required := "sec-networkpolicy-coverage"
    ids := {c.id | c := input.checks[_]}
    not ids[required]
    finding := {
        "checkId":       "policy.required-control",
        "title":         "Required Control: NetworkPolicy Coverage",
        "category":      "security",
        "severity":      "error",
        "pass":          false,
        "reasonCode":    "policy.required.control.missing",
        "message":       sprintf("required check %q is not present in the catalog", [required]),
        "evidence":      {"missingCheckId": required},
        "remediationId": "RUNBOOK-SEC-NETPOL-001",
        "remediation":   "Register sec-networkpolicy-coverage in the check catalog before scanning.",
    }
]
```

Run it:

```bash
./bin/kvirtbp scan --engine rego --policy-file ./policy/required-controls.rego --output table
```

## Full policy example

The example below is a complete required-control-set policy that mirrors what a platform team would maintain. It enforces catalog invariants that get checked on every scan, before the cluster evaluation runs. It:

1. Asserts that mandatory check IDs are present in the catalog.
2. Enforces a minimum number of checks per category.
3. Emits a pass finding for each requirement that is satisfied.
4. Combines all findings into the required `data.kvirtbp.findings` entrypoint.

```rego
package kvirtbp

# ---------------------------------------------------------------------------
# Required check IDs — these must always be present in the catalog.
# Add any org-mandated controls here.
# ---------------------------------------------------------------------------

required_checks := {
    "kubevirt-api-availability",
    "sec-networkpolicy-coverage",
    "sec-namespace-psa-enforce",
    "avail-pdb-coverage",
}

# Minimum number of registered checks per category.
min_checks_per_category := {
    "production-readiness": 1,
    "security":             2,
    "availability":         1,
}

# ---------------------------------------------------------------------------
# Helper: set of all registered check IDs
# ---------------------------------------------------------------------------

registered_ids := {c.id | c := input.checks[_]}

# ---------------------------------------------------------------------------
# Helper: number of registered checks in a given category
# ---------------------------------------------------------------------------

checks_in_category(cat) := count([c | c := input.checks[_]; c.category == cat])

# ---------------------------------------------------------------------------
# Findings: required check IDs
# ---------------------------------------------------------------------------

required_check_findings := findings {
    findings := [finding |
        req := required_checks[_]
        registered_ids[req]
        finding := {
            "checkId":    sprintf("policy.required-control.%s", [req]),
            "title":      sprintf("Required Control Present: %s", [req]),
            "category":   "production-readiness",
            "severity":   "info",
            "pass":       true,
            "reasonCode": "policy.required.control.present",
            "message":    sprintf("required check %q is registered in the catalog", [req]),
        }
    ]
}

missing_check_findings := findings {
    findings := [finding |
        req := required_checks[_]
        not registered_ids[req]
        finding := {
            "checkId":       sprintf("policy.required-control.%s", [req]),
            "title":         sprintf("Required Control Missing: %s", [req]),
            "category":      "production-readiness",
            "severity":      "error",
            "pass":          false,
            "reasonCode":    "policy.required.control.missing",
            "message":       sprintf("required check %q is not registered in the catalog", [req]),
            "evidence":      {"missingCheckId": req},
            "remediation":   sprintf("Register %q in the check catalog before scanning.", [req]),
        }
    ]
}

# ---------------------------------------------------------------------------
# Findings: minimum checks per category
# ---------------------------------------------------------------------------

category_coverage_pass_findings := findings {
    findings := [finding |
        cat_min := min_checks_per_category[cat]
        count := checks_in_category(cat)
        count >= cat_min
        finding := {
            "checkId":    sprintf("policy.category-coverage.%s", [cat]),
            "title":      sprintf("Category Coverage Met: %s", [cat]),
            "category":   cat,
            "severity":   "info",
            "pass":       true,
            "reasonCode": "policy.category.coverage.pass",
            "message":    sprintf("category %q has %d registered check(s), minimum is %d", [cat, count, cat_min]),
            "evidence":   {"category": cat, "registered": sprintf("%d", [count]), "minimum": sprintf("%d", [cat_min])},
        }
    ]
}

category_coverage_fail_findings := findings {
    findings := [finding |
        cat_min := min_checks_per_category[cat]
        count := checks_in_category(cat)
        count < cat_min
        finding := {
            "checkId":    sprintf("policy.category-coverage.%s", [cat]),
            "title":      sprintf("Category Coverage Insufficient: %s", [cat]),
            "category":   cat,
            "severity":   "warning",
            "pass":       false,
            "reasonCode": "policy.category.coverage.fail",
            "message":    sprintf("category %q has %d registered check(s), minimum required is %d", [cat, count, cat_min]),
            "evidence":   {"category": cat, "registered": sprintf("%d", [count]), "minimum": sprintf("%d", [cat_min])},
            "remediation": sprintf("Add at least %d check(s) for category %q to meet the minimum control requirement.", [cat_min - count, cat]),
        }
    ]
}

# ---------------------------------------------------------------------------
# Combined result — required entrypoint: data.kvirtbp.findings
# ---------------------------------------------------------------------------

findings := array.concat(
    array.concat(required_check_findings, missing_check_findings),
    array.concat(category_coverage_pass_findings, category_coverage_fail_findings),
)
```

### Key patterns

| Pattern | What it does |
|---|---|
| `registered_ids := {c.id \| c := input.checks[_]}` | Builds a set of all registered check IDs in one comprehension |
| `required_checks[_]` | Iterates every element of the required set |
| `not registered_ids[req]` | Fails if `req` is not a member of the registered set |
| `checks_in_category(cat)` | Helper rule returning the count of checks for a category |
| `count < cat_min` | Integer comparison — Rego evaluates this as a condition |
| Named partial arrays (`required_check_findings`, etc.) | Each rule produces an independent slice; `array.concat` merges them into `findings` |
| `findings` entrypoint | Must be `data.kvirtbp.findings`; the engine reads exactly this path |

## Accessing collector data in Rego

Collector output is injected into `input.cluster.collectors` when `--collector-data <file>` is passed to `scan`. The structure mirrors the file produced by `kvirtbp collect`:

```
input.cluster.collectors["<collector-name>"]["<node-name-or-_cluster>"]["<key>"] = "<value>"
```

- **`_cluster`** is the key used for `scope: once` (single cluster-wide Job)
- **node names** are keys for `scope: per-node` (one Job per node)

Example policy reading a sysctl value:

```rego
package kvirtbp

import rego.v1

# Always start from input.cluster (guaranteed defined) — not input.cluster.collectors,
# which may be absent when --collector-data is not provided.
ip_forward := object.get(
    object.get(
        object.get(
            object.get(input.cluster, "collectors", {}),
        "sysctl", {}),
    "_cluster", {}),
"net.ipv4.ip_forward", "0")

findings := [{
    "checkId":  "sec-ip-forward",
    "title":    "IP Forwarding Disabled",
    "category": "security",
    "severity": "warning",
    "pass":     ip_forward == "0",
    "message":  sprintf("net.ipv4.ip_forward = %s (expected 0)", [ip_forward]),
}]
```

> **Important:** `object.get` returns undefined — not the default — when its first argument is itself undefined. Always anchor the chain at a value that is guaranteed to be present in `input` (such as `input.cluster`) so the rule produces a result even when collector data is absent.

For a per-node pattern:

```rego
node_results := object.get(object.get(input.cluster, "collectors", {}), "sysctl", {})

findings := [finding |
    node := input.cluster.nodes[_]
    node_data := object.get(node_results, node.name, {})
    val := object.get(node_data, "net.ipv4.ip_forward", "0")
    val != "0"
    finding := {
        "checkId":  "sec-ip-forward",
        "title":    "IP Forwarding Disabled",
        "category": "security",
        "severity": "warning",
        "pass":     false,
        "message":  sprintf("node %s has net.ipv4.ip_forward=%s", [node.name, val]),
        "evidence": {"node": node.name, "value": val},
    }
]
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
- `collectors` (optional) — array of `CollectorConfig` objects run automatically by `kvirtbp collect --bundle`; their output is injected into `input.cluster.collectors` at scan time

See [docs/collectors.md](docs/collectors.md) for the full `CollectorConfig` schema and collector authoring guide.

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
