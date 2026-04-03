package kvirtbp

# Custom e2e policy bundle: checks that a specific ConfigMap exists in the cluster.
# The "resources" field in metadata.json tells the scanner to fetch v1/configmaps
# via the dynamic client before evaluating this policy, making ConfigMap objects
# available at input.cluster.resources["v1/configmaps"].
#
# NOTE: resource type strings must use the plural API resource name as it appears
# in the Kubernetes REST path (e.g. "configmaps", "deployments", "virtualmachines").

required_name := "kvirtbp-e2e-marker"

# No cluster snapshot (unit-test / catalog-only mode) → no cluster findings.
findings = [] {
	not input.cluster
}

# ConfigMap present → pass.
findings = f {
	input.cluster
	cms = object.get(object.get(input.cluster, "resources", {}), "v1/configmaps", [])
	found = [cm | cm = cms[_]; cm.name == required_name]
	count(found) > 0
	f = [{
		"checkId":  "custom-configmap-marker",
		"title":    "Custom ConfigMap Marker",
		"category": "production-readiness",
		"severity": "info",
		"pass":     true,
		"message":  "Required ConfigMap 'kvirtbp-e2e-marker' found in cluster.",
	}]
}

# ConfigMap absent → fail.
findings = f {
	input.cluster
	cms = object.get(object.get(input.cluster, "resources", {}), "v1/configmaps", [])
	found = [cm | cm = cms[_]; cm.name == required_name]
	count(found) == 0
	f = [{
		"checkId":     "custom-configmap-marker",
		"title":       "Custom ConfigMap Marker",
		"category":    "production-readiness",
		"severity":    "warning",
		"pass":        false,
		"message":     "Required ConfigMap 'kvirtbp-e2e-marker' not found in cluster.",
		"remediation": "Create a ConfigMap named 'kvirtbp-e2e-marker' in any namespace.",
	}]
}
