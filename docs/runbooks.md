# Remediation Runbooks

This document maps `remediationId` values emitted by scan findings to operational runbooks.

## RUNBOOK-PROD-BASELINE-001

Title: Production Baseline Discovery Recovery

Description: Restore cluster discovery and KubeVirt API visibility required for production baseline checks.

Steps:
1. Validate active kubeconfig context and API server reachability.
2. Ensure `kubevirt.io` API group is installed and served.
3. Re-run scan with the same identity to confirm pass state.

## RUNBOOK-SEC-RBAC-001

Title: RBAC Read Access Remediation

Description: Grant minimum read permissions required for security baseline evaluation.

Steps:
1. Grant list/get permissions for nodes and namespaces.
2. Grant list/get permissions for KubeVirt virtualmachines.
3. Re-run scan and verify reasonCode is `sec.baseline.pass`.

## RUNBOOK-SEC-NETPOL-001

Title: NetworkPolicy Coverage Remediation

Description: Establish baseline NetworkPolicy coverage across non-system namespaces.

Steps:
1. List non-system namespaces that host workloads and identify namespaces without policies.
2. Apply a default-deny ingress/egress NetworkPolicy per uncovered namespace.
3. Add explicit allow-list policies for required traffic and rerun scan.

## RUNBOOK-AVAIL-BASELINE-001

Title: Availability Baseline Visibility Recovery

Description: Restore node and discovery visibility required for availability baseline checks.

Steps:
1. Confirm API discovery endpoints respond without timeouts.
2. Grant node list permissions to scanning identity.
3. Re-run scan and verify reasonCode is `avail.baseline.pass`.

## RUNBOOK-PROD-GUARDRAILS-001

Title: Namespace Guardrails Remediation

Description: Enforce ResourceQuota and LimitRange defaults for workload namespaces.

Steps:
1. Identify non-system namespaces missing ResourceQuota or LimitRange objects.
2. Apply baseline ResourceQuota and LimitRange templates per uncovered namespace.
3. Rerun scan and verify `prod.guardrails.coverage.pass` for guardrail coverage.
