package checks

func ApplyBaselineAssessments(findings []Finding) []Finding {
	status := make(map[string]Finding, len(findings))
	for _, f := range findings {
		status[f.CheckID] = f
	}

	for i := range findings {
		switch findings[i].CheckID {
		case "prod-baseline-kubevirt-readiness":
			findings[i] = assessProductionReadiness(findings[i], status)
		case "sec-baseline-rbac-safety":
			findings[i] = assessSecurityRBAC(findings[i], status)
		case "avail-baseline-workload-resilience":
			findings[i] = assessAvailabilityResilience(findings[i], status)
		}
	}

	return findings
}

func assessProductionReadiness(base Finding, status map[string]Finding) Finding {
	base.Impact = ImpactMedium
	base.Confidence = ConfidenceHigh
	base.RemediationID = "RUNBOOK-PROD-BASELINE-001"
	base.Evidence = map[string]string{
		"cluster-connectivity": passState(status, "cluster-connectivity"),
		"cluster-discovery":    passState(status, "cluster-discovery"),
		"kubevirt-api":         passState(status, "kubevirt-api-availability"),
		"kubevirt-operator":    passState(status, "prod-kubevirt-operator-health"),
		"node-inventory":       passState(status, "prod-node-inventory"),
		"namespace-guardrails": passState(status, "prod-namespace-guardrails-coverage"),
	}
	if failed(status, "cluster-connectivity") || failed(status, "cluster-discovery") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "prod.discovery.degraded"
		base.Message = "Production baseline degraded: cluster connectivity/discovery issues prevent full readiness validation."
		base.Remediation = "Verify kubeconfig context, API server reachability, and RBAC for discovery endpoints before rerunning scan."
		return base
	}
	if failed(status, "kubevirt-api-availability") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "prod.kubevirt.api.missing"
		base.Message = "Production baseline failed: kubevirt.io API group is unavailable."
		base.Remediation = "Install or enable KubeVirt and confirm the kubevirt.io API group is served by the cluster."
		return base
	}
	if failed(status, "prod-kubevirt-operator-health") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "prod.kubevirt.operator.health.failed"
		base.Message = "Production baseline failed: kubevirt operator health check did not pass."
		base.Remediation = "Stabilize kubevirt operator deployment health before rerunning production checks."
		return base
	}
	if failed(status, "prod-node-inventory") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "prod.nodes.inventory.failed"
		base.Message = "Production baseline failed: node inventory check did not pass."
		base.Remediation = "Verify node visibility and cluster health before rerunning production checks."
		return base
	}
	if failed(status, "prod-namespace-guardrails-coverage") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "prod.namespace.guardrails.insufficient"
		base.Message = "Production baseline failed: namespace quota/limit guardrail coverage is below threshold."
		base.Remediation = "Apply ResourceQuota and LimitRange defaults to non-system namespaces used by workloads."
		return base
	}

	base.Pass = true
	base.Severity = SeverityInfo
	base.ReasonCode = "prod.baseline.pass"
	base.Message = "Production baseline passed: cluster connectivity and KubeVirt API readiness validated."
	base.Remediation = "No action required."
	return base
}

func assessSecurityRBAC(base Finding, status map[string]Finding) Finding {
	base.Impact = ImpactHigh
	base.Confidence = ConfidenceHigh
	base.RemediationID = "RUNBOOK-SEC-RBAC-001"
	base.Evidence = map[string]string{
		"perm-list-nodes":        passState(status, "perm-list-nodes"),
		"perm-list-namespaces":   passState(status, "perm-list-namespaces"),
		"perm-list-vms":          passState(status, "perm-list-vms"),
		"networking-api":         passState(status, "sec-networking-api-availability"),
		"namespace-psa-enforce":  passState(status, "sec-namespace-psa-enforce"),
		"networkpolicy-coverage": passState(status, "sec-networkpolicy-coverage"),
	}
	if failed(status, "sec-namespace-psa-enforce") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "sec.psa.enforce.insufficient"
		base.Message = "Security baseline failed: Pod Security Admission enforce labels are incomplete across targeted namespaces."
		base.Remediation = "Apply pod-security.kubernetes.io/enforce labels with baseline or restricted values on uncovered namespaces."
		return base
	}
	if failed(status, "sec-networkpolicy-coverage") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "sec.networkpolicy.coverage.insufficient"
		base.Message = "Security baseline failed: NetworkPolicy coverage across non-system namespaces is incomplete."
		base.Remediation = "Apply baseline default-deny plus explicit allow-list NetworkPolicy rules across workload namespaces."
		return base
	}
	if failed(status, "perm-list-nodes") || failed(status, "perm-list-namespaces") || failed(status, "perm-list-vms") || failed(status, "sec-networking-api-availability") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "sec.rbac.permissions.missing"
		base.Message = "Security baseline failed: required read RBAC permissions are incomplete for best-practice evaluation."
		base.Remediation = "Grant list/read permissions for nodes, namespaces, and kubevirt virtualmachines to the scanning identity."
		return base
	}

	base.Pass = true
	base.Severity = SeverityInfo
	base.ReasonCode = "sec.baseline.pass"
	base.Message = "Security baseline passed: required RBAC read permissions are present."
	base.Remediation = "No action required."
	return base
}

func assessAvailabilityResilience(base Finding, status map[string]Finding) Finding {
	base.Impact = ImpactMedium
	base.Confidence = ConfidenceMedium
	base.RemediationID = "RUNBOOK-AVAIL-BASELINE-001"
	base.Evidence = map[string]string{
		"cluster-connectivity":   passState(status, "cluster-connectivity"),
		"cluster-discovery":      passState(status, "cluster-discovery"),
		"perm-list-nodes":        passState(status, "perm-list-nodes"),
		"control-plane-ha":       passState(status, "avail-control-plane-ha"),
		"namespace-pdb-coverage": passState(status, "avail-namespace-pdb-coverage"),
	}
	if failed(status, "cluster-connectivity") || failed(status, "cluster-discovery") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "avail.discovery.degraded"
		base.Message = "Availability baseline degraded: cluster discovery/connectivity instability detected."
		base.Remediation = "Stabilize API connectivity and ensure discovery APIs are reachable for resilience verification."
		return base
	}
	if failed(status, "perm-list-nodes") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "avail.nodes.visibility.missing"
		base.Message = "Availability baseline failed: unable to list nodes for resilience checks."
		base.Remediation = "Grant node list/read permissions to the scanning identity and rerun the scan."
		return base
	}
	if failed(status, "avail-control-plane-ha") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "avail.controlplane.ha.degraded"
		base.Message = "Availability baseline failed: control-plane HA check did not meet recommended threshold."
		base.Remediation = "Scale and stabilize control-plane nodes to improve resilience where supported."
		return base
	}
	if failed(status, "avail-namespace-pdb-coverage") {
		base.Pass = false
		base.Severity = SeverityWarning
		base.ReasonCode = "avail.pdb.coverage.insufficient"
		base.Message = "Availability baseline failed: PodDisruptionBudget coverage is incomplete across targeted namespaces."
		base.Remediation = "Add PodDisruptionBudget resources to workload namespaces lacking disruption safeguards."
		return base
	}

	base.Pass = true
	base.Severity = SeverityInfo
	base.ReasonCode = "avail.baseline.pass"
	base.Message = "Availability baseline passed: core discovery and node visibility checks succeeded."
	base.Remediation = "No action required."
	return base
}

func failed(status map[string]Finding, checkID string) bool {
	f, ok := status[checkID]
	return ok && !f.Pass
}

func passState(status map[string]Finding, checkID string) string {
	f, ok := status[checkID]
	if !ok {
		return "unknown"
	}
	if f.Pass {
		return "pass"
	}
	return "fail"
}
