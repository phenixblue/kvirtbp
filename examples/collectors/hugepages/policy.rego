# ============================================================================
# hugepages reference collector bundle
# ============================================================================
#
# Collector: "hugepages" (scope: per-node)
#   Runs one Job per node using alpine:3.21. Each Job reads /proc/meminfo
#   (which is not namespaced in Linux — it reflects the host's values) and
#   emits a small JSON object with the node's hugepages configuration.
#
#   No special privileges or host namespace mounts are required because
#   /proc/meminfo is visible from any container without elevated access.
#
#   Collected data shape (input.cluster.collectors["hugepages"]):
#     {
#       "worker-1": { "total": 512, "free": 480, "size_kb": 2048 },
#       "worker-2": { "total":   0, "free":   0, "size_kb": 2048 }
#     }
#
#   Fields:
#     total    — HugePages_Total: system-wide number of hugepages configured
#     free     — HugePages_Free:  hugepages not yet allocated
#     size_kb  — Hugepagesize (in kB): typically 2048 (2 Mi) or 1048576 (1 Gi)
#
# Policies:
#   prod-hugepages-collector-present — gates subsequent checks; warns if data absent
#   prod-hugepages-configured        — at least one node has hugepages enabled
#   prod-hugepages-all-configured    — every node has hugepages enabled (info)
#
# Usage:
#   # Step 1: collect
#   kvirtbp collect --bundle ./examples/collectors/hugepages --output collector-data.json
#
#   # Step 2: scan
#   kvirtbp scan --engine rego \
#       --policy-bundle ./examples/collectors/hugepages \
#       --collector-data collector-data.json
#
#   # Combine with node-info in a single collect run — scan remains separate per bundle:
#   kvirtbp collect \
#       --bundle ./examples/collectors/node-info \
#       --bundle ./examples/collectors/hugepages \
#       --output collector-data.json
# ============================================================================

package kvirtbp

# ---------------------------------------------------------------------------
# Short-circuit: no cluster snapshot present (unit tests / dry-run).
# ---------------------------------------------------------------------------

findings := [] { not input.cluster }
findings := cluster_findings { input.cluster }

# ---------------------------------------------------------------------------
# Safe access helpers.
# ---------------------------------------------------------------------------

hugepages_data := object.get(
	object.get(input.cluster, "collectors", {}),
	"hugepages",
	{}
)

# Nodes that reported at least one configured hugepage (total > 0).
nodes_with_hugepages := {name |
	some name
	hugepages_data[name]
	object.get(hugepages_data[name], "total", 0) > 0
}

# All node names that sent back data (excludes _error sentinels).
nodes_reporting := {name |
	some name
	hugepages_data[name]
	not startswith(name, "_")
	not hugepages_data[name]._error
}

# ---------------------------------------------------------------------------
# Guards.
# ---------------------------------------------------------------------------

collector_data_present {
	count(hugepages_data) > 0
}

some_hugepages_configured {
	collector_data_present
	count(nodes_with_hugepages) > 0
}

all_hugepages_configured {
	collector_data_present
	count(nodes_reporting) > 0
	count(nodes_with_hugepages) == count(nodes_reporting)
}

no_hugepages_configured {
	collector_data_present
	count(nodes_with_hugepages) == 0
}

partial_hugepages_configured {
	some_hugepages_configured
	not all_hugepages_configured
}

# ---------------------------------------------------------------------------
# Check 1: collector data is present
# ---------------------------------------------------------------------------

collector_findings := [{
	"checkId":    "prod-hugepages-collector-present",
	"title":      "Hugepages Collector Data Present",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":       true,
	"reasonCode": "prod.collector.hugepages.present",
	"message":    sprintf("hugepages collector data present for %d node(s)", [count(nodes_reporting)]),
	"evidence":   {"nodeCount": sprintf("%d", [count(nodes_reporting)])},
}] {
	collector_data_present
}

collector_findings := [{
	"checkId":    "prod-hugepages-collector-present",
	"title":      "Hugepages Collector Data Present",
	"category":   "production-readiness",
	"severity":   "warning",
	"pass":       false,
	"reasonCode": "prod.collector.hugepages.absent",
	"message":    "hugepages collector data is absent; run 'kvirtbp collect' before scanning",
	"remediation": "kvirtbp collect --bundle ./examples/collectors/hugepages --output collector-data.json",
}] {
	not collector_data_present
}

# ---------------------------------------------------------------------------
# Check 2: hugepages configured on all nodes
#
# KubeVirt VMs can use 2Mi or 1Gi hugepages to reduce TLB pressure and
# improve memory throughput for latency-sensitive workloads. Configuring
# hugepages on every node ensures VMs can be scheduled anywhere without
# capacity errors.
# ---------------------------------------------------------------------------

hugepages_findings := [{
	"checkId":    "prod-hugepages-configured",
	"title":      "Hugepages Configured on All Nodes",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":       true,
	"reasonCode": "prod.hugepages.all_configured",
	"message":    sprintf("hugepages configured on all %d reporting node(s)", [count(nodes_reporting)]),
	"evidence":   {"configuredNodes": sprintf("%d", [count(nodes_with_hugepages)])},
}] {
	all_hugepages_configured
}

hugepages_findings := [{
	"checkId":      "prod-hugepages-configured",
	"title":        "Hugepages Configured on All Nodes",
	"category":     "production-readiness",
	"severity":     "info",
	"pass":         false,
	"reasonCode":   "prod.hugepages.partial",
	"message":      sprintf("%d of %d node(s) have hugepages configured", [count(nodes_with_hugepages), count(nodes_reporting)]),
	"evidence":     {
		"configuredNodes":  sprintf("%d", [count(nodes_with_hugepages)]),
		"reportingNodes":   sprintf("%d", [count(nodes_reporting)]),
	},
	"remediation":  "Configure hugepages on all nodes for consistent KubeVirt VM scheduling. See: https://kubernetes.io/docs/tasks/manage-hugepages/scheduling-hugepages/",
}] {
	partial_hugepages_configured
}

hugepages_findings := [{
	"checkId":      "prod-hugepages-configured",
	"title":        "Hugepages Configured on All Nodes",
	"category":     "production-readiness",
	"severity":     "info",
	"pass":         false,
	"reasonCode":   "prod.hugepages.none_configured",
	"message":      "no nodes have hugepages configured; KubeVirt VMs requesting hugepages will fail to schedule",
	"remediation":  "Configure 2Mi or 1Gi hugepages on cluster nodes to support KubeVirt VMs with hugepages memory. See: https://kubernetes.io/docs/tasks/manage-hugepages/scheduling-hugepages/",
}] {
	no_hugepages_configured
}

hugepages_findings := [] {
	not all_hugepages_configured
	not partial_hugepages_configured
	not no_hugepages_configured
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

cluster_findings := array.concat(collector_findings, hugepages_findings)
