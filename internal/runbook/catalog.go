package runbook

import "sort"

type Entry struct {
	ID          string
	Title       string
	Description string
	Steps       []string
}

func Catalog() map[string]Entry {
	return map[string]Entry{
		"RUNBOOK-PROD-BASELINE-001": {
			ID:          "RUNBOOK-PROD-BASELINE-001",
			Title:       "Production Baseline Discovery Recovery",
			Description: "Restore cluster discovery and kubevirt API visibility required for production baseline checks.",
			Steps: []string{
				"Validate active kubeconfig context and API server reachability.",
				"Ensure kubevirt.io API group is installed and served.",
				"Re-run scan with the same identity to confirm pass state.",
			},
		},
		"RUNBOOK-SEC-RBAC-001": {
			ID:          "RUNBOOK-SEC-RBAC-001",
			Title:       "RBAC Read Access Remediation",
			Description: "Grant minimum read permissions required for security baseline evaluation.",
			Steps: []string{
				"Grant list/get permissions for nodes and namespaces.",
				"Grant list/get permissions for kubevirt virtualmachines.",
				"Re-run scan and verify security baseline reasonCode is sec.baseline.pass.",
			},
		},
		"RUNBOOK-SEC-NETPOL-001": {
			ID:          "RUNBOOK-SEC-NETPOL-001",
			Title:       "NetworkPolicy Coverage Remediation",
			Description: "Establish baseline NetworkPolicy coverage across non-system namespaces.",
			Steps: []string{
				"List non-system namespaces that host workloads and identify namespaces without policies.",
				"Apply a default-deny ingress/egress NetworkPolicy per uncovered namespace.",
				"Add explicit allow-list policies for required traffic and rerun scan.",
			},
		},
		"RUNBOOK-AVAIL-BASELINE-001": {
			ID:          "RUNBOOK-AVAIL-BASELINE-001",
			Title:       "Availability Baseline Visibility Recovery",
			Description: "Restore node and discovery visibility required for availability baseline checks.",
			Steps: []string{
				"Confirm API discovery endpoints respond without timeouts.",
				"Grant node list permissions to scanning identity.",
				"Re-run scan and verify availability baseline reasonCode is avail.baseline.pass.",
			},
		},
		"RUNBOOK-PROD-GUARDRAILS-001": {
			ID:          "RUNBOOK-PROD-GUARDRAILS-001",
			Title:       "Namespace Guardrails Remediation",
			Description: "Enforce ResourceQuota and LimitRange defaults for workload namespaces.",
			Steps: []string{
				"Identify non-system namespaces missing ResourceQuota or LimitRange objects.",
				"Apply baseline ResourceQuota and LimitRange templates per uncovered namespace.",
				"Rerun scan and verify prod.guardrails.coverage.pass for guardrail coverage.",
			},
		},
	}
}

func Lookup(id string) (Entry, bool) {
	e, ok := Catalog()[id]
	return e, ok
}

func SortedIDs() []string {
	ids := make([]string, 0, len(Catalog()))
	for id := range Catalog() {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
