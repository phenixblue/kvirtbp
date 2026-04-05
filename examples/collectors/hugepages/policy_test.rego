package kvirtbp_test

import rego.v1

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# All nodes have hugepages configured.
input_all_configured := {
	"cluster": {
		"nodes": [
			{"name": "worker-1"},
			{"name": "worker-2"},
		],
		"collectors": {
			"hugepages": {
				"worker-1": {"total": 512, "free": 480, "size_kb": 2048},
				"worker-2": {"total": 256, "free": 256, "size_kb": 2048},
			},
		},
	},
}

# Only one of two nodes has hugepages configured.
input_partial := {
	"cluster": {
		"nodes": [
			{"name": "worker-1"},
			{"name": "worker-2"},
		],
		"collectors": {
			"hugepages": {
				"worker-1": {"total": 512, "free": 480, "size_kb": 2048},
				"worker-2": {"total": 0,   "free": 0,   "size_kb": 2048},
			},
		},
	},
}

# No nodes have hugepages configured.
input_none_configured := {
	"cluster": {
		"nodes": [
			{"name": "worker-1"},
			{"name": "worker-2"},
		],
		"collectors": {
			"hugepages": {
				"worker-1": {"total": 0, "free": 0, "size_kb": 2048},
				"worker-2": {"total": 0, "free": 0, "size_kb": 2048},
			},
		},
	},
}

# No collector data at all.
input_no_collectors := {
	"cluster": {
		"nodes": [{"name": "worker-1"}],
	},
}

# No cluster (dry-run / unit-test mode).
input_no_cluster := {}

# ---------------------------------------------------------------------------
# findings are empty when there is no cluster
# ---------------------------------------------------------------------------

test_no_cluster_findings_empty if {
	findings := data.kvirtbp.findings with input as input_no_cluster
	count(findings) == 0
}

# ---------------------------------------------------------------------------
# Check 1: collector data present / absent
# ---------------------------------------------------------------------------

test_collector_present_pass if {
	findings := data.kvirtbp.findings with input as input_all_configured
	present := [f | f := findings[_]; f.checkId == "prod-hugepages-collector-present"]
	count(present) == 1
	present[0].pass == true
	present[0].reasonCode == "prod.collector.hugepages.present"
}

test_collector_absent_fail if {
	findings := data.kvirtbp.findings with input as input_no_collectors
	present := [f | f := findings[_]; f.checkId == "prod-hugepages-collector-present"]
	count(present) == 1
	present[0].pass == false
	present[0].reasonCode == "prod.collector.hugepages.absent"
}

# ---------------------------------------------------------------------------
# Check 2: hugepages configuration coverage
# ---------------------------------------------------------------------------

test_all_configured_pass if {
	findings := data.kvirtbp.findings with input as input_all_configured
	hp := [f | f := findings[_]; f.checkId == "prod-hugepages-configured"]
	count(hp) == 1
	hp[0].pass == true
	hp[0].reasonCode == "prod.hugepages.all_configured"
}

test_partial_configured_fail if {
	findings := data.kvirtbp.findings with input as input_partial
	hp := [f | f := findings[_]; f.checkId == "prod-hugepages-configured"]
	count(hp) == 1
	hp[0].pass == false
	hp[0].reasonCode == "prod.hugepages.partial"
}

test_none_configured_fail if {
	findings := data.kvirtbp.findings with input as input_none_configured
	hp := [f | f := findings[_]; f.checkId == "prod-hugepages-configured"]
	count(hp) == 1
	hp[0].pass == false
	hp[0].reasonCode == "prod.hugepages.none_configured"
}

# ---------------------------------------------------------------------------
# No collector data → hugepages check is skipped
# ---------------------------------------------------------------------------

test_no_collector_hugepages_check_skipped if {
	findings := data.kvirtbp.findings with input as input_no_collectors
	hp := [f | f := findings[_]; f.checkId == "prod-hugepages-configured"]
	count(hp) == 0
}
