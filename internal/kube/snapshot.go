package kube

// ClusterSnapshot holds a point-in-time snapshot of the cluster resources
// needed for preflight checks. It is serializable to JSON and is the sole
// input to the Rego preflight engine.
type ClusterSnapshot struct {
	// Degraded is true when no Kubernetes client was available.
	Degraded bool `json:"degraded"`
	// API discovery
	KubeVirtInstalled bool   `json:"kubevirtInstalled"`
	HasNetworkingV1   bool   `json:"hasNetworkingV1"`
	HasPolicyV1       bool   `json:"hasPolicyV1"`
	ServerVersion     string `json:"serverVersion"`
	DiscoveryError    string `json:"discoveryError,omitempty"`

	// Nodes
	Nodes      []NodeSnapshot `json:"nodes"`
	NodesError string         `json:"nodesError,omitempty"`

	// Namespaces
	Namespaces      []NamespaceSnapshot `json:"namespaces"`
	NamespacesError string              `json:"namespacesError,omitempty"`

	// Deployments in the kubevirt namespace
	KubeVirtDeployments []DeploymentSnapshot `json:"kubevirtDeployments"`
	DeploymentsError    string               `json:"deploymentsError,omitempty"`

	// NetworkPolicies (all namespaces)
	NetworkPolicies      []NetworkPolicySnapshot `json:"networkPolicies"`
	NetworkPoliciesError string                  `json:"networkPoliciesError,omitempty"`

	// ResourceQuotas (all namespaces)
	ResourceQuotas      []ResourceQuotaSnapshot `json:"resourceQuotas"`
	ResourceQuotasError string                  `json:"resourceQuotasError,omitempty"`

	// LimitRanges (all namespaces)
	LimitRanges      []LimitRangeSnapshot `json:"limitRanges"`
	LimitRangesError string               `json:"limitRangesError,omitempty"`

	// PodDisruptionBudgets (all namespaces)
	PodDisruptionBudgets      []PDBSnapshot `json:"podDisruptionBudgets"`
	PodDisruptionBudgetsError string        `json:"podDisruptionBudgetsError,omitempty"`

	// Permission probes
	Permissions []PermissionSnapshot `json:"permissions"`

	// Namespace filter options — serialized so Rego can apply the same filtering
	NamespaceInclude []string `json:"namespaceInclude,omitempty"`
	NamespaceExclude []string `json:"namespaceExclude,omitempty"`

	// Resources holds dynamically fetched resources keyed by "GROUP/VERSION/RESOURCE"
	// (core API resources use "v1/RESOURCE", e.g. "v1/configmaps").
	// Values are lists of ResourceSnapshot objects. Populated only when
	// ResourceTypes are declared in bundle metadata or via --resource flag.
	Resources map[string][]ResourceSnapshot `json:"resources,omitempty"`

	// Collectors holds data injected from external collectors, keyed by
	// collector name. For per-node collectors the value is
	// map[nodeName]map[string]any; for once-collectors it is
	// map["_cluster"]map[string]any. Populated via --collector-data or the
	// collect subcommand.
	Collectors map[string]any `json:"collectors,omitempty"`
}

// ResourceSnapshot is a generic, serializable representation of a single
// Kubernetes object. Only metadata is captured; spec/status are omitted
// intentionally so that Rego policies receive a consistent, stable shape.
type ResourceSnapshot struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// NodeSnapshot captures the node fields used by preflight checks.
type NodeSnapshot struct {
	Name         string `json:"name"`
	ControlPlane bool   `json:"controlPlane"`
	Ready        bool   `json:"ready"`
}

// NamespaceSnapshot captures the namespace fields used by preflight checks.
type NamespaceSnapshot struct {
	Name   string            `json:"name"`
	Phase  string            `json:"phase"`
	Labels map[string]string `json:"labels,omitempty"`
}

// DeploymentSnapshot captures the deployment fields used by preflight checks.
type DeploymentSnapshot struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	AvailableReplicas int32  `json:"availableReplicas"`
}

// NetworkPolicySnapshot captures the NetworkPolicy fields used by preflight checks.
type NetworkPolicySnapshot struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ResourceQuotaSnapshot captures the ResourceQuota fields used by preflight checks.
type ResourceQuotaSnapshot struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// LimitRangeSnapshot captures the LimitRange fields used by preflight checks.
type LimitRangeSnapshot struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// PDBSnapshot captures the PodDisruptionBudget fields used by preflight checks.
type PDBSnapshot struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// PermissionSnapshot captures the result of a single RBAC permission probe.
type PermissionSnapshot struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Group    string `json:"group"`
	Verb     string `json:"verb"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason,omitempty"`
	Error    string `json:"error,omitempty"`
}
