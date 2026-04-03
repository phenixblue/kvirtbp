package kvirtbp

# ---------------------------------------------------------------------------
# cluster_test.rego — OPA unit tests for cluster.rego
# Run with: opa test ./policy/ -v
# ---------------------------------------------------------------------------

# Base cluster snapshot used across tests. Three control-plane nodes, no
# target namespaces, discovery healthy. Produces only "no target" pass
# findings for namespace-level checks so tests can query per-check results.
_base_cluster := {
	"degraded":                  false,
	"discoveryError":            "",
	"kubevirtInstalled":         true,
	"hasNetworkingV1":           true,
	"deploymentsError":          "",
	"nodesError":                "",
	"namespacesError":           "",
	"networkPoliciesError":      "",
	"podDisruptionBudgetsError": "",
	"nodes": [
		{"name": "cp-1", "controlPlane": true,  "ready": true},
		{"name": "cp-2", "controlPlane": true,  "ready": true},
		{"name": "cp-3", "controlPlane": true,  "ready": true},
		{"name": "worker-1", "controlPlane": false, "ready": true},
	],
	"namespaces":           [],
	"kubevirtDeployments":  [],
	"networkPolicies":      [],
	"resourceQuotas":       [],
	"limitRanges":          [],
	"podDisruptionBudgets": [],
	"permissions":          [],
}

# No "cluster" key in input → empty cluster findings.
test_cluster_no_input {
	cluster_findings == [] with input as {"checks": []}
}

# Degraded snapshot → single cluster-connectivity failing finding.
test_cluster_degraded_connectivity {
	f := cluster_findings with input as {
		"cluster": {"degraded": true, "discoveryError": "cannot reach API server"},
	}
	count(f) == 1
	f[0].checkId == "cluster-connectivity"
	f[0].pass == false
}

# Non-degraded snapshot with a discovery error → cluster-discovery failing finding.
test_cluster_discovery_error {
	f := cluster_findings with input as {
		"cluster": {"degraded": false, "discoveryError": "CRD list failed"},
	}
	some i
	f[i].checkId == "cluster-discovery"
	f[i].pass == false
}

# KubeVirt installed → kubevirt-api-availability passes.
test_cluster_kubevirt_installed_pass {
	f := cluster_findings with input as {"cluster": _base_cluster}
	some i
	f[i].checkId == "kubevirt-api-availability"
	f[i].pass == true
}

# KubeVirt not installed → kubevirt-api-availability fails.
test_cluster_kubevirt_not_installed_fail {
	cluster := {
		"degraded":                  false,
		"discoveryError":            "",
		"kubevirtInstalled":         false,
		"hasNetworkingV1":           true,
		"deploymentsError":          "",
		"nodesError":                "",
		"namespacesError":           "",
		"networkPoliciesError":      "",
		"podDisruptionBudgetsError": "",
		"nodes": [
			{"name": "cp-1", "controlPlane": true, "ready": true},
			{"name": "cp-2", "controlPlane": true, "ready": true},
			{"name": "cp-3", "controlPlane": true, "ready": true},
		],
		"namespaces":           [],
		"kubevirtDeployments":  [],
		"networkPolicies":      [],
		"resourceQuotas":       [],
		"limitRanges":          [],
		"podDisruptionBudgets": [],
		"permissions":          [],
	}
	f := cluster_findings with input as {"cluster": cluster}
	some i
	f[i].checkId == "kubevirt-api-availability"
	f[i].pass == false
}

# Three control-plane nodes → HA check passes.
test_cluster_control_plane_ha_pass {
	f := cluster_findings with input as {"cluster": _base_cluster}
	some i
	f[i].checkId == "avail-control-plane-ha"
	f[i].pass == true
}

# Only one control-plane node → HA check fails.
test_cluster_control_plane_ha_insufficient {
	cluster := {
		"degraded":                  false,
		"discoveryError":            "",
		"kubevirtInstalled":         true,
		"hasNetworkingV1":           true,
		"deploymentsError":          "",
		"nodesError":                "",
		"namespacesError":           "",
		"networkPoliciesError":      "",
		"podDisruptionBudgetsError": "",
		"nodes": [{"name": "cp-1", "controlPlane": true, "ready": true}],
		"namespaces":           [],
		"kubevirtDeployments":  [],
		"networkPolicies":      [],
		"resourceQuotas":       [],
		"limitRanges":          [],
		"podDisruptionBudgets": [],
		"permissions":          [],
	}
	f := cluster_findings with input as {"cluster": cluster}
	some i
	f[i].checkId == "avail-control-plane-ha"
	f[i].pass == false
}

# No nodes returned → node inventory check fails.
test_cluster_node_inventory_empty {
	cluster := {
		"degraded":                  false,
		"discoveryError":            "",
		"kubevirtInstalled":         true,
		"hasNetworkingV1":           true,
		"deploymentsError":          "",
		"nodesError":                "",
		"namespacesError":           "",
		"networkPoliciesError":      "",
		"podDisruptionBudgetsError": "",
		"nodes":                [],
		"namespaces":           [],
		"kubevirtDeployments":  [],
		"networkPolicies":      [],
		"resourceQuotas":       [],
		"limitRanges":          [],
		"podDisruptionBudgets": [],
		"permissions":          [],
	}
	f := cluster_findings with input as {"cluster": cluster}
	some i
	f[i].checkId == "prod-node-inventory"
	f[i].pass == false
	f[i].reasonCode == "prod.nodes.none"
}

# Non-empty nodes → node inventory check passes.
test_cluster_node_inventory_present {
	f := cluster_findings with input as {"cluster": _base_cluster}
	some i
	f[i].checkId == "prod-node-inventory"
	f[i].pass == true
}

# No target namespaces → PSA check returns a pass ("no target" variant).
test_cluster_psa_no_target_namespaces {
	f := cluster_findings with input as {"cluster": _base_cluster}
	some i
	f[i].checkId == "sec-namespace-psa-enforce"
	f[i].pass == true
	f[i].reasonCode == "sec.psa.target.none"
}

# Degraded snapshot → no permission findings (all sub-checks short-circuit).
test_cluster_degraded_produces_no_permission_findings {
	f := cluster_findings with input as {
		"cluster": {"degraded": true, "discoveryError": "unreachable"},
	}
	count([x | x := f[_]; x.checkId == "perm-list-nodes"]) == 0
}
