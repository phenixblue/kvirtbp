package kvirtbp_test

import rego.v1

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# Minimal input with collector data present (two nodes, same arch).
input_with_data := {
	"cluster": {
		"nodes": [
			{"name": "worker-1"},
			{"name": "worker-2"},
		],
		"collectors": {
			"node-info": {
				"worker-1": {"kernel": "5.15.0-122-generic", "arch": "x86_64"},
				"worker-2": {"kernel": "5.15.0-118-generic", "arch": "x86_64"},
			},
		},
	},
}

# Input with mixed architectures.
input_mixed_arch := {
	"cluster": {
		"nodes": [
			{"name": "worker-1"},
			{"name": "worker-2"},
		],
		"collectors": {
			"node-info": {
				"worker-1": {"kernel": "5.15.0-122-generic", "arch": "x86_64"},
				"worker-2": {"kernel": "6.1.0-28-arm64",    "arch": "aarch64"},
			},
		},
	},
}

# Input with no collector data injected.
input_no_collectors := {
	"cluster": {
		"nodes": [{"name": "worker-1"}],
	},
}

# No cluster at all (dry-run / unit test mode).
input_no_cluster := {}

# ---------------------------------------------------------------------------
# findings are empty when no cluster
# ---------------------------------------------------------------------------

test_no_cluster_findings_empty if {
	findings := data.kvirtbp.findings with input as input_no_cluster
	count(findings) == 0
}

# ---------------------------------------------------------------------------
# Collector data present — check 1
# ---------------------------------------------------------------------------

test_collector_present_pass if {
	findings := data.kvirtbp.findings with input as input_with_data
	present_findings := [f | f := findings[_]; f.checkId == "prod-node-info-collector-present"]
	count(present_findings) == 1
	present_findings[0].pass == true
	present_findings[0].reasonCode == "prod.collector.node-info.present"
}

test_collector_absent_fail if {
	findings := data.kvirtbp.findings with input as input_no_collectors
	present_findings := [f | f := findings[_]; f.checkId == "prod-node-info-collector-present"]
	count(present_findings) == 1
	present_findings[0].pass == false
	present_findings[0].reasonCode == "prod.collector.node-info.absent"
}

# ---------------------------------------------------------------------------
# Architecture consistency — check 2
# ---------------------------------------------------------------------------

test_arch_consistent_pass if {
	findings := data.kvirtbp.findings with input as input_with_data
	arch_findings := [f | f := findings[_]; f.checkId == "prod-node-arch-consistent"]
	count(arch_findings) == 1
	arch_findings[0].pass == true
	arch_findings[0].reasonCode == "prod.node.arch.consistent"
	arch_findings[0].evidence.architecture == "x86_64"
}

test_arch_mixed_fail if {
	findings := data.kvirtbp.findings with input as input_mixed_arch
	arch_findings := [f | f := findings[_]; f.checkId == "prod-node-arch-consistent"]
	count(arch_findings) == 1
	arch_findings[0].pass == false
	arch_findings[0].reasonCode == "prod.node.arch.mixed"
}

# ---------------------------------------------------------------------------
# No collector data → arch check is skipped (only collector-present emitted)
# ---------------------------------------------------------------------------

test_no_collector_arch_check_skipped if {
	findings := data.kvirtbp.findings with input as input_no_collectors
	arch_findings := [f | f := findings[_]; f.checkId == "prod-node-arch-consistent"]
	count(arch_findings) == 0
}
