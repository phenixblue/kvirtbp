# Check Catalog

This catalog documents checks currently emitted by `kvirtbp scan`.

## Baseline aggregate checks

| Check ID | Category | Default Severity | Purpose | Remediation ID |
| --- | --- | --- | --- | --- |
| prod-baseline-kubevirt-readiness | production-readiness | info | Aggregates production readiness posture across discovery, KubeVirt API/operator health, node inventory, and namespace guardrails. | RUNBOOK-PROD-BASELINE-001 |
| sec-baseline-rbac-safety | security | info | Aggregates security posture across RBAC access, PSA enforcement, and NetworkPolicy coverage. | RUNBOOK-SEC-RBAC-001 |
| avail-baseline-workload-resilience | availability | info | Aggregates availability posture across discovery, node visibility, control-plane HA, and PDB coverage. | RUNBOOK-AVAIL-BASELINE-001 |

## Preflight and capability checks

| Check ID | Category | Typical Severity | Purpose | Remediation ID |
| --- | --- | --- | --- | --- |
| cluster-connectivity | production-readiness | warning on failure | Verifies Kubernetes client connectivity and enters degraded mode on failure. | RUNBOOK-PROD-BASELINE-001 |
| cluster-discovery | production-readiness | warning on failure | Verifies API discovery and capability probing. | RUNBOOK-PROD-BASELINE-001 |
| kubevirt-api-availability | production-readiness | info/warning | Detects whether `kubevirt.io` API group is available. | RUNBOOK-PROD-BASELINE-001 |
| prod-kubevirt-operator-health | production-readiness | info/warning | Assesses KubeVirt operator deployment health in `kubevirt` namespace. | RUNBOOK-PROD-BASELINE-001 |
| prod-node-inventory | production-readiness | info/warning | Checks node listing and minimum node signal coverage. | RUNBOOK-PROD-BASELINE-001 |
| prod-namespace-guardrails-coverage | production-readiness | info/warning | Evaluates ResourceQuota + LimitRange coverage in targeted namespaces. | RUNBOOK-PROD-GUARDRAILS-001 |
| sec-networking-api-availability | security | info/warning | Validates networking API availability for security controls. | RUNBOOK-SEC-RBAC-001 |
| sec-namespace-psa-enforce | security | info/warning | Evaluates PSA `enforce` label coverage (baseline/restricted) in targeted namespaces. | RUNBOOK-SEC-RBAC-001 |
| sec-networkpolicy-coverage | security | info/warning | Evaluates namespace NetworkPolicy coverage across targeted namespaces. | RUNBOOK-SEC-NETPOL-001 |
| avail-control-plane-ha | availability | info/warning | Signals control-plane HA posture from discovered nodes. | RUNBOOK-AVAIL-BASELINE-001 |
| avail-namespace-pdb-coverage | availability | info/warning | Evaluates PodDisruptionBudget coverage across targeted namespaces. | RUNBOOK-AVAIL-BASELINE-001 |

## RBAC permission probes

| Check ID | Category | Typical Severity | Purpose | Remediation ID |
| --- | --- | --- | --- | --- |
| perm-list-nodes | security | info/warning | Verifies scanner identity can list nodes. | RUNBOOK-SEC-RBAC-001 |
| perm-list-namespaces | security | info/warning | Verifies scanner identity can list namespaces. | RUNBOOK-SEC-RBAC-001 |
| perm-list-vms | security | info/warning | Verifies scanner identity can list KubeVirt virtualmachines. | RUNBOOK-SEC-RBAC-001 |

## Notes

- Severity may change at runtime based on evidence and degraded conditions.
- Baseline aggregate checks consume preflight and permission signals and emit `reasonCode` values for machine processing.
- Use `kvirtbp checks` for the current compiled control catalog and `kvirtbp scan --output json` for structured finding output.
- Runbook details are in `docs/runbooks.md`.
