# ============================================================================
# node-info reference collector bundle
# ============================================================================
#
# Collector: "node-info" (scope: per-node)
#   Runs one Job per node using alpine:3.21.  Each Job writes the node's
#   kernel version and CPU architecture to /kvirtbp/output.json with a
#   single printf command — no extra packages required.
#
#   Collected data shape (input.cluster.collectors["node-info"]):
#     {
#       "worker-1": { "kernel": "5.15.0-122-generic", "arch": "x86_64" },
#       "worker-2": { "kernel": "5.15.0-122-generic", "arch": "aarch64" }
#     }
#
# Usage:
#   # Step 1: collect
#   kvirtbp collect --bundle ./examples/collectors/node-info --output collector-data.json
#
#   # Step 2: scan
#   kvirtbp scan --engine rego \
#       --policy-bundle ./examples/collectors/node-info \
#       --collector-data collector-data.json
#
#   # Or from a tagged GitHub release in a single step:
#   BUNDLE=https://github.com/myorg/policies/archive/refs/tags/v1.0.0.tar.gz
#   kvirtbp collect --bundle $BUNDLE --bundle-subdir examples/collectors/node-info \
#       --output collector-data.json
#   kvirtbp scan --engine rego --policy-bundle $BUNDLE \
#       --bundle-subdir examples/collectors/node-info \
#       --collector-data collector-data.json
# ============================================================================

package kvirtbp

# ---------------------------------------------------------------------------
# Short-circuit: no cluster snapshot present (unit tests / dry-run).
# ---------------------------------------------------------------------------

findings := [] { not input.cluster }
findings := cluster_findings { input.cluster }

# ---------------------------------------------------------------------------
# Safe access helpers.
#
# Always anchor object.get chains at input.cluster (which is guaranteed to be
# defined when input.cluster is present) rather than at
# input.cluster.collectors, which may be absent when --collector-data is not
# provided.  Passing an undefined first argument to object.get returns
# undefined, not the default value.
# ---------------------------------------------------------------------------

node_info_data := object.get(
	object.get(input.cluster, "collectors", {}),
	"node-info",
	{}
)

# Set of distinct CPU architectures seen across all nodes that reported back.
node_architectures := {arch |
	some node_name
	node_info_data[node_name]
	arch := object.get(node_info_data[node_name], "arch", "")
	arch != ""
}

# ---------------------------------------------------------------------------
# Guards — used to select which rule body fires below.
# ---------------------------------------------------------------------------

collector_data_present {
	count(node_info_data) > 0
}

arch_consistent {
	collector_data_present
	count(node_architectures) == 1
}

arch_mixed {
	collector_data_present
	count(node_architectures) > 1
}

# ---------------------------------------------------------------------------
# Check 1: collector data is present
#
# This check acts as a pre-condition gate: if the user forgot to run
# 'kvirtbp collect' it fails loudly so subsequent checks can be skipped
# rather than silently producing vacuous pass results.
# ---------------------------------------------------------------------------

collector_findings := [{
	"checkId":    "prod-node-info-collector-present",
	"title":      "Node Info Collector Data Present",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":       true,
	"reasonCode": "prod.collector.node-info.present",
	"message":    sprintf("node-info collector data present for %d node(s)", [count(node_info_data)]),
	"evidence":   {"nodeCount": sprintf("%d", [count(node_info_data)])},
}] {
	collector_data_present
}

collector_findings := [{
	"checkId":    "prod-node-info-collector-present",
	"title":      "Node Info Collector Data Present",
	"category":   "production-readiness",
	"severity":   "warning",
	"pass":       false,
	"reasonCode": "prod.collector.node-info.absent",
	"message":    "node-info collector data is absent; run 'kvirtbp collect' before scanning",
	"remediation": "kvirtbp collect --bundle ./examples/collectors/node-info --output collector-data.json",
}] {
	not collector_data_present
}

# ---------------------------------------------------------------------------
# Check 2: all nodes report the same CPU architecture
#
# Mixed architectures in a KubeVirt cluster can cause VM scheduling failures
# when the guest image is incompatible with the host CPU architecture.
# ---------------------------------------------------------------------------

arch_findings := [{
	"checkId":    "prod-node-arch-consistent",
	"title":      "Node CPU Architecture Consistency",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":       true,
	"reasonCode": "prod.node.arch.consistent",
	"message":    sprintf("all nodes report a consistent CPU architecture: %s", [concat(", ", node_architectures)]),
	"evidence":   {"architecture": concat(", ", node_architectures)},
}] {
	arch_consistent
}

arch_findings := [{
	"checkId":       "prod-node-arch-consistent",
	"title":         "Node CPU Architecture Consistency",
	"category":      "production-readiness",
	"severity":      "warning",
	"pass":          false,
	"reasonCode":    "prod.node.arch.mixed",
	"message":       sprintf("mixed CPU architectures detected across nodes: %s", [concat(", ", node_architectures)]),
	"evidence":      {"architectures": concat(", ", node_architectures)},
	"remediation":   "KubeVirt VM scheduling may fail if the guest image is incompatible with the host CPU architecture. Ensure nodes share a common architecture for KubeVirt workloads.",
}] {
	arch_mixed
}

arch_findings := [] {
	not arch_consistent
	not arch_mixed
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

cluster_findings := array.concat(collector_findings, arch_findings)
