package kvirtbp

# ---------------------------------------------------------------------------
# Helpers — namespace filtering
# Mirrors targetNamespaces() in internal/kube/preflight.go
# ---------------------------------------------------------------------------

system_namespaces := {"kube-system", "kube-public", "kube-node-lease"}

target_namespaces := names {
	include := object.get(input.cluster, "namespaceInclude", [])
	exclude := object.get(input.cluster, "namespaceExclude", [])
	all_ns := [ns | ns := input.cluster.namespaces[_]; ns.phase != "Terminating"; not system_namespaces[ns.name]]
	names := [ns.name |
		ns := all_ns[_]
		namespace_included(ns.name, include)
		not namespace_excluded(ns.name, exclude)
	]
}

namespace_included(name, include) {
	count(include) == 0
}

namespace_included(name, include) {
	count(include) > 0
	some pat
	include[pat]
	glob.match(pat, [], name)
}

namespace_excluded(name, exclude) {
	some pat
	exclude[pat]
	glob.match(pat, [], name)
}

# ---------------------------------------------------------------------------
# Cluster connectivity — degraded mode (no clients)
# ---------------------------------------------------------------------------

degraded_findings := findings {
	input.cluster.degraded == true
	findings := [{
		"checkId":  "cluster-connectivity",
		"title":    "Cluster Connectivity",
		"category": "production-readiness",
		"severity": "warning",
		"pass":     false,
		"message":  input.cluster.discoveryError,
	}]
}

degraded_findings := findings {
	input.cluster.degraded != true
	findings := []
}

# ---------------------------------------------------------------------------
# Discovery error — non-degraded but discovery failed
# ---------------------------------------------------------------------------

# Degraded snapshot already handled above; skip discovery-error for it.
discovery_error_findings := [] {
	input.cluster.degraded == true
}

discovery_error_findings := findings {
	input.cluster.degraded != true
	input.cluster.discoveryError != ""
	findings := [{
		"checkId":  "cluster-discovery",
		"title":    "Cluster API Discovery",
		"category": "production-readiness",
		"severity": "warning",
		"pass":     false,
		"message":  sprintf("API discovery failed: %s", [input.cluster.discoveryError]),
	}]
}

discovery_error_findings := [] {
	input.cluster.degraded != true
	object.get(input.cluster, "discoveryError", "") == ""
}

# ---------------------------------------------------------------------------
# From here on, all checks only produce findings when discovery succeeded
# ---------------------------------------------------------------------------

discovery_ok {
	input.cluster.degraded != true
	object.get(input.cluster, "discoveryError", "") == ""
}

# ---------------------------------------------------------------------------
# KubeVirt API availability
# ---------------------------------------------------------------------------

kubevirt_api_findings := findings {
	discovery_ok
	input.cluster.kubevirtInstalled == true
	findings := [{
		"checkId":  "kubevirt-api-availability",
		"title":    "KubeVirt API Availability",
		"category": "production-readiness",
		"severity": "info",
		"pass":     true,
		"message":  "Detected kubevirt.io API group.",
	}]
}

kubevirt_api_findings := findings {
	discovery_ok
	input.cluster.kubevirtInstalled != true
	findings := [{
		"checkId":  "kubevirt-api-availability",
		"title":    "KubeVirt API Availability",
		"category": "production-readiness",
		"severity": "warning",
		"pass":     false,
		"message":  "kubevirt.io API group was not discovered; KubeVirt-specific checks may be skipped.",
	}]
}

kubevirt_api_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# Networking API availability
# ---------------------------------------------------------------------------

networking_api_findings := findings {
	discovery_ok
	input.cluster.hasNetworkingV1 == true
	findings := [{
		"checkId":    "sec-networking-api-availability",
		"title":      "Security Networking API Availability",
		"category":   "security",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "sec.networking.api.present",
		"message":    "networking.k8s.io/v1 API is available for NetworkPolicy checks.",
	}]
}

networking_api_findings := findings {
	discovery_ok
	input.cluster.hasNetworkingV1 != true
	findings := [{
		"checkId":       "sec-networking-api-availability",
		"title":         "Security Networking API Availability",
		"category":      "security",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "sec.networking.api.missing",
		"message":       "networking.k8s.io/v1 API is unavailable; NetworkPolicy security checks are degraded.",
		"remediationId": "RUNBOOK-SEC-RBAC-001",
		"remediation":   "Ensure networking.k8s.io/v1 is enabled and cluster networking supports NetworkPolicy.",
	}]
}

networking_api_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# KubeVirt operator health
# ---------------------------------------------------------------------------

operator_names := {"virt-operator", "kubevirt-operator"}

kubevirt_operator_findings := findings {
	discovery_ok
	object.get(input.cluster, "deploymentsError", "") != ""
	findings := [{
		"checkId":       "prod-kubevirt-operator-health",
		"title":         "Production KubeVirt Operator Health",
		"category":      "production-readiness",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "prod.kubevirt.operator.enumeration.error",
		"message":       sprintf("unable to evaluate kubevirt operator deployment health: %s", [input.cluster.deploymentsError]),
		"remediationId": "RUNBOOK-PROD-BASELINE-001",
		"remediation":   "Grant deployment read access in kubevirt namespace and verify operator installation.",
	}]
}

kubevirt_operator_findings := findings {
	discovery_ok
	object.get(input.cluster, "deploymentsError", "") == ""
	operator_deps := [d | d := input.cluster.kubevirtDeployments[_]; operator_names[d.name]]
	count(operator_deps) > 0
	healthy_deps := [d | d := operator_deps[_]; d.availableReplicas > 0]
	count(healthy_deps) > 0
	d := healthy_deps[0]
	findings := [{
		"checkId":    "prod-kubevirt-operator-health",
		"title":      "Production KubeVirt Operator Health",
		"category":   "production-readiness",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "prod.kubevirt.operator.healthy",
		"message":    sprintf("KubeVirt operator deployment %s is healthy with %d available replicas.", [d.name, d.availableReplicas]),
		"evidence":   {"deployment": d.name, "availableReplicas": sprintf("%d", [d.availableReplicas])},
	}]
}

kubevirt_operator_findings := findings {
	discovery_ok
	object.get(input.cluster, "deploymentsError", "") == ""
	operator_deps := [d | d := input.cluster.kubevirtDeployments[_]; operator_names[d.name]]
	count(operator_deps) > 0
	unhealthy_deps := [d | d := operator_deps[_]; d.availableReplicas == 0]
	count(unhealthy_deps) > 0
	d := unhealthy_deps[0]
	findings := [{
		"checkId":       "prod-kubevirt-operator-health",
		"title":         "Production KubeVirt Operator Health",
		"category":      "production-readiness",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "prod.kubevirt.operator.unavailable",
		"message":       sprintf("KubeVirt operator deployment %s has no available replicas.", [d.name]),
		"evidence":      {"deployment": d.name, "availableReplicas": "0"},
		"remediationId": "RUNBOOK-PROD-BASELINE-001",
		"remediation":   "Investigate virt-operator rollout and reconcile kubevirt control-plane components.",
	}]
}

kubevirt_operator_findings := findings {
	discovery_ok
	object.get(input.cluster, "deploymentsError", "") == ""
	operator_deps := [d | d := input.cluster.kubevirtDeployments[_]; operator_names[d.name]]
	count(operator_deps) == 0
	findings := [{
		"checkId":       "prod-kubevirt-operator-health",
		"title":         "Production KubeVirt Operator Health",
		"category":      "production-readiness",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "prod.kubevirt.operator.missing",
		"message":       "KubeVirt operator deployment was not found in kubevirt namespace.",
		"remediationId": "RUNBOOK-PROD-BASELINE-001",
		"remediation":   "Install KubeVirt operator and ensure deployment is running in kubevirt namespace.",
	}]
}

kubevirt_operator_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# Node inventory
# ---------------------------------------------------------------------------

node_inventory_findings := findings {
	discovery_ok
	object.get(input.cluster, "nodesError", "") != ""
	findings := [{
		"checkId":       "prod-node-inventory",
		"title":         "Production Node Inventory",
		"category":      "production-readiness",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "prod.nodes.list.error",
		"message":       sprintf("unable to list nodes: %s", [input.cluster.nodesError]),
		"remediationId": "RUNBOOK-PROD-BASELINE-001",
		"remediation":   "Grant node list permissions and verify API server connectivity.",
	}]
}

node_inventory_findings := findings {
	discovery_ok
	object.get(input.cluster, "nodesError", "") == ""
	count(input.cluster.nodes) > 0
	findings := [{
		"checkId":    "prod-node-inventory",
		"title":      "Production Node Inventory",
		"category":   "production-readiness",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "prod.nodes.present",
		"message":    sprintf("cluster node inventory detected: %d nodes", [count(input.cluster.nodes)]),
		"evidence":   {"nodeCount": sprintf("%d", [count(input.cluster.nodes)])},
	}]
}

node_inventory_findings := findings {
	discovery_ok
	object.get(input.cluster, "nodesError", "") == ""
	count(input.cluster.nodes) == 0
	findings := [{
		"checkId":       "prod-node-inventory",
		"title":         "Production Node Inventory",
		"category":      "production-readiness",
		"severity":      "error",
		"pass":          false,
		"reasonCode":    "prod.nodes.none",
		"message":       "no nodes were returned by the cluster API.",
		"remediationId": "RUNBOOK-PROD-BASELINE-001",
		"remediation":   "Verify cluster health and API permissions for node visibility.",
	}]
}

node_inventory_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# Control-plane HA
# ---------------------------------------------------------------------------

control_plane_count := count([n | n := input.cluster.nodes[_]; n.controlPlane == true])

control_plane_ha_findings := findings {
	discovery_ok
	object.get(input.cluster, "nodesError", "") == ""
	control_plane_count >= 3
	findings := [{
		"checkId":    "avail-control-plane-ha",
		"title":      "Availability Control Plane HA",
		"category":   "availability",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "avail.controlplane.ha.pass",
		"message":    sprintf("control-plane high availability looks healthy: %d control-plane nodes", [control_plane_count]),
		"evidence":   {"controlPlaneNodes": sprintf("%d", [control_plane_count])},
	}]
}

control_plane_ha_findings := findings {
	discovery_ok
	object.get(input.cluster, "nodesError", "") == ""
	control_plane_count < 3
	findings := [{
		"checkId":       "avail-control-plane-ha",
		"title":         "Availability Control Plane HA",
		"category":      "availability",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "avail.controlplane.ha.insufficient",
		"message":       sprintf("control-plane HA below recommended threshold: %d control-plane nodes", [control_plane_count]),
		"evidence":      {"controlPlaneNodes": sprintf("%d", [control_plane_count])},
		"remediationId": "RUNBOOK-AVAIL-BASELINE-001",
		"remediation":   "Scale control-plane nodes toward a highly available quorum where supported.",
	}]
}

control_plane_ha_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# Namespace PSA enforce
# ---------------------------------------------------------------------------

psa_ns_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") != ""
	findings := [{
		"checkId":       "sec-namespace-psa-enforce",
		"title":         "Security Namespace Pod Security Admission Enforce",
		"category":      "security",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "sec.psa.enumeration.error",
		"message":       sprintf("unable to evaluate namespace PSA labels: %s", [input.cluster.namespacesError]),
		"remediationId": "RUNBOOK-SEC-RBAC-001",
		"remediation":   "Grant namespace read permissions so PSA enforce labels can be evaluated.",
	}]
}

psa_ns_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) == 0
	findings := [{
		"checkId":    "sec-namespace-psa-enforce",
		"title":      "Security Namespace Pod Security Admission Enforce",
		"category":   "security",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "sec.psa.target.none",
		"message":    "No non-system namespaces detected for PSA enforcement checks.",
	}]
}

psa_ns_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) > 0
	ns_map := {ns.name: ns | ns := input.cluster.namespaces[_]}
	compliant := [name | name := target_namespaces[_]; enforce := object.get(ns_map[name].labels, "pod-security.kubernetes.io/enforce", ""); enforce == "baseline"]
	compliant2 := [name | name := target_namespaces[_]; enforce := object.get(ns_map[name].labels, "pod-security.kubernetes.io/enforce", ""); enforce == "restricted"]
	all_compliant := array.concat(compliant, compliant2)
	count(all_compliant) == count(target_namespaces)
	coverage := sprintf("%.1f", [count(all_compliant) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":    "sec-namespace-psa-enforce",
		"title":      "Security Namespace Pod Security Admission Enforce",
		"category":   "security",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "sec.psa.enforce.pass",
		"message":    "PSA enforce labels are configured across targeted namespaces.",
		"evidence":   {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"compliantNamespaces": sprintf("%d", [count(all_compliant)]),
			"coveragePercent": coverage,
		},
	}]
}

psa_ns_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) > 0
	ns_map := {ns.name: ns | ns := input.cluster.namespaces[_]}
	compliant := [name | name := target_namespaces[_]; enforce := object.get(ns_map[name].labels, "pod-security.kubernetes.io/enforce", ""); enforce == "baseline"]
	compliant2 := [name | name := target_namespaces[_]; enforce := object.get(ns_map[name].labels, "pod-security.kubernetes.io/enforce", ""); enforce == "restricted"]
	all_compliant := array.concat(compliant, compliant2)
	count(all_compliant) < count(target_namespaces)
	coverage := sprintf("%.1f", [count(all_compliant) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":       "sec-namespace-psa-enforce",
		"title":         "Security Namespace Pod Security Admission Enforce",
		"category":      "security",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "sec.psa.enforce.missing",
		"message":       sprintf("PSA enforce coverage is %s%% across targeted namespaces.", [coverage]),
		"evidence":      {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"compliantNamespaces": sprintf("%d", [count(all_compliant)]),
			"coveragePercent": coverage,
		},
		"remediationId": "RUNBOOK-SEC-RBAC-001",
		"remediation":   "Set pod-security.kubernetes.io/enforce to baseline or restricted on uncovered namespaces.",
	}]
}

psa_ns_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# NetworkPolicy coverage
# ---------------------------------------------------------------------------

netpol_findings := findings {
	discovery_ok
	object.get(input.cluster, "networkPoliciesError", "") != ""
	findings := [{
		"checkId":       "sec-networkpolicy-coverage",
		"title":         "Security Namespace NetworkPolicy Coverage",
		"category":      "security",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "sec.networkpolicy.enumeration.error",
		"message":       sprintf("unable to evaluate NetworkPolicy coverage: %s", [input.cluster.networkPoliciesError]),
		"remediationId": "RUNBOOK-SEC-NETPOL-001",
		"remediation":   "Grant namespace and networkpolicy read permissions to the scanning identity.",
	}]
}

netpol_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") != ""
	object.get(input.cluster, "networkPoliciesError", "") == ""
	findings := [{
		"checkId":       "sec-networkpolicy-coverage",
		"title":         "Security Namespace NetworkPolicy Coverage",
		"category":      "security",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "sec.networkpolicy.enumeration.error",
		"message":       sprintf("unable to evaluate NetworkPolicy coverage: %s", [input.cluster.namespacesError]),
		"remediationId": "RUNBOOK-SEC-NETPOL-001",
		"remediation":   "Grant namespace and networkpolicy read permissions to the scanning identity.",
	}]
}

netpol_findings := findings {
	discovery_ok
	object.get(input.cluster, "networkPoliciesError", "") == ""
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) == 0
	findings := [{
		"checkId":    "sec-networkpolicy-coverage",
		"title":      "Security Namespace NetworkPolicy Coverage",
		"category":   "security",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "sec.networkpolicy.target.none",
		"message":    "No non-system namespaces detected for NetworkPolicy coverage checks.",
	}]
}

netpol_findings := findings {
	discovery_ok
	object.get(input.cluster, "networkPoliciesError", "") == ""
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) > 0
	protected := {np.namespace | np := input.cluster.networkPolicies[_]}
	covered := [name | name := target_namespaces[_]; protected[name]]
	count(covered) == count(target_namespaces)
	coverage := sprintf("%.1f", [count(covered) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":    "sec-networkpolicy-coverage",
		"title":      "Security Namespace NetworkPolicy Coverage",
		"category":   "security",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "sec.networkpolicy.coverage.pass",
		"message":    sprintf("NetworkPolicy coverage is complete across %d non-system namespaces.", [count(target_namespaces)]),
		"evidence":   {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"coveredNamespaces": sprintf("%d", [count(covered)]),
			"coveragePercent": coverage,
		},
	}]
}

netpol_findings := findings {
	discovery_ok
	object.get(input.cluster, "networkPoliciesError", "") == ""
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) > 0
	protected := {np.namespace | np := input.cluster.networkPolicies[_]}
	covered := [name | name := target_namespaces[_]; protected[name]]
	count(covered) < count(target_namespaces)
	coverage := sprintf("%.1f", [count(covered) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":       "sec-networkpolicy-coverage",
		"title":         "Security Namespace NetworkPolicy Coverage",
		"category":      "security",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "sec.networkpolicy.coverage.partial",
		"message":       sprintf("NetworkPolicy coverage is %s%% across non-system namespaces.", [coverage]),
		"evidence":      {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"coveredNamespaces": sprintf("%d", [count(covered)]),
			"coveragePercent": coverage,
		},
		"remediationId": "RUNBOOK-SEC-NETPOL-001",
		"remediation":   "Add baseline default-deny plus required allow-list NetworkPolicy rules for uncovered namespaces.",
	}]
}

netpol_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# Namespace guardrails coverage (ResourceQuota + LimitRange)
# ---------------------------------------------------------------------------

guardrails_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") != ""
	findings := [{
		"checkId":       "prod-namespace-guardrails-coverage",
		"title":         "Production Namespace Guardrails Coverage",
		"category":      "production-readiness",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "prod.guardrails.enumeration.error",
		"message":       sprintf("unable to evaluate namespace guardrails: %s", [input.cluster.namespacesError]),
		"remediationId": "RUNBOOK-PROD-GUARDRAILS-001",
		"remediation":   "Grant read permissions for namespaces, resourcequotas, and limitranges.",
	}]
}

guardrails_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) == 0
	findings := [{
		"checkId":    "prod-namespace-guardrails-coverage",
		"title":      "Production Namespace Guardrails Coverage",
		"category":   "production-readiness",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "prod.guardrails.target.none",
		"message":    "No non-system namespaces detected for quota/limit guardrail checks.",
	}]
}

guardrails_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) > 0
	quota_ns := {rq.namespace | rq := input.cluster.resourceQuotas[_]}
	limit_ns := {lr.namespace | lr := input.cluster.limitRanges[_]}
	compliant := [name | name := target_namespaces[_]; quota_ns[name]; limit_ns[name]]
	count(compliant) * 100 >= count(target_namespaces) * 80
	coverage := sprintf("%.1f", [count(compliant) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":    "prod-namespace-guardrails-coverage",
		"title":      "Production Namespace Guardrails Coverage",
		"category":   "production-readiness",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "prod.guardrails.coverage.pass",
		"message":    sprintf("Namespace guardrails coverage is %s%% across non-system namespaces.", [coverage]),
		"evidence":   {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"compliantNamespaces": sprintf("%d", [count(compliant)]),
			"coveragePercent": coverage,
		},
	}]
}

guardrails_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	count(target_namespaces) > 0
	quota_ns := {rq.namespace | rq := input.cluster.resourceQuotas[_]}
	limit_ns := {lr.namespace | lr := input.cluster.limitRanges[_]}
	compliant := [name | name := target_namespaces[_]; quota_ns[name]; limit_ns[name]]
	count(compliant) * 100 < count(target_namespaces) * 80
	coverage := sprintf("%.1f", [count(compliant) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":       "prod-namespace-guardrails-coverage",
		"title":         "Production Namespace Guardrails Coverage",
		"category":      "production-readiness",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "prod.guardrails.coverage.partial",
		"message":       sprintf("Namespace guardrails coverage is %s%% and below recommended threshold.", [coverage]),
		"evidence":      {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"compliantNamespaces": sprintf("%d", [count(compliant)]),
			"coveragePercent": coverage,
		},
		"remediationId": "RUNBOOK-PROD-GUARDRAILS-001",
		"remediation":   "Add ResourceQuota and LimitRange defaults to uncovered namespaces.",
	}]
}

guardrails_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# PodDisruptionBudget coverage
# ---------------------------------------------------------------------------

pdb_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") != ""
	findings := [{
		"checkId":       "avail-namespace-pdb-coverage",
		"title":         "Availability Namespace PDB Coverage",
		"category":      "availability",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "avail.pdb.enumeration.error",
		"message":       sprintf("unable to evaluate PodDisruptionBudget coverage: %s", [input.cluster.namespacesError]),
		"remediationId": "RUNBOOK-AVAIL-BASELINE-001",
		"remediation":   "Grant PodDisruptionBudget read permissions to the scanning identity.",
	}]
}

pdb_findings := findings {
	discovery_ok
	object.get(input.cluster, "podDisruptionBudgetsError", "") != ""
	object.get(input.cluster, "namespacesError", "") == ""
	findings := [{
		"checkId":       "avail-namespace-pdb-coverage",
		"title":         "Availability Namespace PDB Coverage",
		"category":      "availability",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "avail.pdb.enumeration.error",
		"message":       sprintf("unable to evaluate PodDisruptionBudget coverage: %s", [input.cluster.podDisruptionBudgetsError]),
		"remediationId": "RUNBOOK-AVAIL-BASELINE-001",
		"remediation":   "Grant PodDisruptionBudget read permissions to the scanning identity.",
	}]
}

pdb_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	object.get(input.cluster, "podDisruptionBudgetsError", "") == ""
	count(target_namespaces) == 0
	findings := [{
		"checkId":    "avail-namespace-pdb-coverage",
		"title":      "Availability Namespace PDB Coverage",
		"category":   "availability",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "avail.pdb.target.none",
		"message":    "No non-system namespaces detected for PDB coverage checks.",
	}]
}

pdb_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	object.get(input.cluster, "podDisruptionBudgetsError", "") == ""
	count(target_namespaces) > 0
	pdb_ns := {p.namespace | p := input.cluster.podDisruptionBudgets[_]}
	covered := [name | name := target_namespaces[_]; pdb_ns[name]]
	count(covered) == count(target_namespaces)
	coverage := sprintf("%.1f", [count(covered) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":    "avail-namespace-pdb-coverage",
		"title":      "Availability Namespace PDB Coverage",
		"category":   "availability",
		"severity":   "info",
		"pass":       true,
		"reasonCode": "avail.pdb.coverage.pass",
		"message":    "PodDisruptionBudget coverage is complete across targeted namespaces.",
		"evidence":   {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"coveredNamespaces": sprintf("%d", [count(covered)]),
			"coveragePercent": coverage,
		},
	}]
}

pdb_findings := findings {
	discovery_ok
	object.get(input.cluster, "namespacesError", "") == ""
	object.get(input.cluster, "podDisruptionBudgetsError", "") == ""
	count(target_namespaces) > 0
	pdb_ns := {p.namespace | p := input.cluster.podDisruptionBudgets[_]}
	covered := [name | name := target_namespaces[_]; pdb_ns[name]]
	count(covered) < count(target_namespaces)
	coverage := sprintf("%.1f", [count(covered) * 100.0 / count(target_namespaces)])
	findings := [{
		"checkId":       "avail-namespace-pdb-coverage",
		"title":         "Availability Namespace PDB Coverage",
		"category":      "availability",
		"severity":      "warning",
		"pass":          false,
		"reasonCode":    "avail.pdb.coverage.partial",
		"message":       sprintf("PodDisruptionBudget coverage is %s%% across targeted namespaces.", [coverage]),
		"evidence":      {
			"targetNamespaces": sprintf("%d", [count(target_namespaces)]),
			"coveredNamespaces": sprintf("%d", [count(covered)]),
			"coveragePercent": coverage,
		},
		"remediationId": "RUNBOOK-AVAIL-BASELINE-001",
		"remediation":   "Add PodDisruptionBudget resources to uncovered workload namespaces.",
	}]
}

pdb_findings := [] { not discovery_ok }

# ---------------------------------------------------------------------------
# Permission (RBAC) findings
# ---------------------------------------------------------------------------

permission_findings := [finding |
	p := input.cluster.permissions[_]
	p.error != ""
	finding := {
		"checkId":  p.id,
		"title":    "RBAC Preflight",
		"category": "security",
		"severity": "warning",
		"pass":     false,
		"message":  sprintf("permission probe failed for %s.%s: %s", [p.resource, p.group, p.error]),
	}
]

permission_allowed_findings := [finding |
	p := input.cluster.permissions[_]
	object.get(p, "error", "") == ""
	p.allowed == true
	finding := {
		"checkId":  p.id,
		"title":    "RBAC Preflight",
		"category": "security",
		"severity": "info",
		"pass":     true,
		"message":  sprintf("allowed to %s %s.%s", [p.verb, p.resource, p.group]),
	}
]

permission_denied_findings := [finding |
	p := input.cluster.permissions[_]
	object.get(p, "error", "") == ""
	p.allowed != true
	finding := {
		"checkId":  p.id,
		"title":    "RBAC Preflight",
		"category": "security",
		"severity": "warning",
		"pass":     false,
		"message":  sprintf("not allowed to %s %s.%s (%s)", [p.verb, p.resource, p.group, object.get(p, "reason", "")]),
	}
]

all_permission_findings := array.concat(
	array.concat(permission_findings, permission_allowed_findings),
	permission_denied_findings,
)

# ---------------------------------------------------------------------------
# Required entrypoint: data.kvirtbp.findings
# ---------------------------------------------------------------------------

# cluster_findings is the exported entrypoint for this module.
# When no snapshot is present (unit tests, dry-run), return empty.
cluster_findings := [] { not input.cluster }

# When a snapshot is present, assemble all cluster checks.
cluster_findings := v {
	input.cluster
	v := _assembled_cluster_findings
}

_assembled_cluster_findings := array.concat(
	array.concat(
		array.concat(
			array.concat(degraded_findings, discovery_error_findings),
			array.concat(kubevirt_api_findings, networking_api_findings),
		),
		array.concat(
			array.concat(kubevirt_operator_findings, node_inventory_findings),
			array.concat(control_plane_ha_findings, psa_ns_findings),
		),
	),
	array.concat(
		array.concat(netpol_findings, guardrails_findings),
		array.concat(pdb_findings, all_permission_findings),
	),
)
