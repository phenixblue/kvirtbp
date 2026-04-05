package collector

// CollectorScope controls how many Jobs are deployed for a collector.
type CollectorScope string

const (
	// ScopeOnce deploys a single cluster-wide Job. Output is stored under the
	// sentinel key "_cluster" in the collector data map.
	ScopeOnce CollectorScope = "once"

	// ScopePerNode deploys one Job per node (using nodeName node selector).
	// Output is stored keyed by node name in the collector data map.
	ScopePerNode CollectorScope = "per-node"
)

// defaultOutputPath is the path inside the collector pod container where
// commands write their output. The CLI appends "cat <outputPath>" as the
// final container command so pod logs contain only the clean JSON payload.
const defaultOutputPath = "/kvirtbp/output.json"

// CollectorConfig declares a custom pod collector, either in a bundle's
// metadata.json or in a standalone --collector-config file.
type CollectorConfig struct {
	// Name is the unique key used in the collector data file and in
	// input.cluster.collectors["<name>"] in Rego.
	Name string `json:"name"`

	// Image is the container image to run.
	Image string `json:"image"`

	// Commands are shell commands executed in order inside the container.
	// They may write freely to stdout/stderr; their canonical output must be
	// written to OutputPath as valid JSON. The CLI appends
	// "cat <OutputPath>" as the last command so pod logs equal the JSON file.
	Commands []string `json:"commands"`

	// Scope controls deployment shape: "once" (single Job) or "per-node"
	// (one Job per node). Defaults to "once".
	Scope CollectorScope `json:"scope"`

	// OutputPath is the in-pod file path where commands write JSON output.
	// Defaults to /kvirtbp/output.json.
	OutputPath string `json:"outputPath,omitempty"`

	// TimeoutSeconds is the per-collector deadline in seconds. 0 means use
	// the global cap set by --collector-timeout.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`

	// Privileged runs the container with SecurityContext.Privileged = true.
	// Must be explicitly opted into; never defaulted.
	Privileged bool `json:"privileged,omitempty"`

	// HostPID mounts the host PID namespace into the container.
	HostPID bool `json:"hostPID,omitempty"`

	// HostNetwork attaches the container to the host network namespace.
	HostNetwork bool `json:"hostNetwork,omitempty"`

	// Env is an optional set of environment variables injected into the
	// container. Values should not contain secrets; use Kubernetes Secrets
	// or a mounted volume for sensitive data.
	Env map[string]string `json:"env,omitempty"`

	// Tolerations are applied to the Job pod template so the collector can
	// be scheduled on nodes with matching taints (e.g. control-plane nodes).
	// Use {"operator": "Exists"} to tolerate all taints on a node.
	Tolerations []CollectorToleration `json:"tolerations,omitempty"`
}

// CollectorToleration is a simplified representation of a Kubernetes
// pod toleration, mirroring corev1.Toleration without importing k8s types
// into the config schema.
type CollectorToleration struct {
	// Key is the taint key the toleration applies to. Empty string matches
	// all taint keys (only valid when Operator is "Exists").
	Key string `json:"key,omitempty"`

	// Operator is "Exists" or "Equal" (default: "Equal").
	Operator string `json:"operator,omitempty"`

	// Value is the taint value to match (only used when Operator is "Equal").
	Value string `json:"value,omitempty"`

	// Effect is the taint effect to match: "NoSchedule", "NoExecute",
	// "PreferNoSchedule", or empty string to match all effects.
	Effect string `json:"effect,omitempty"`
}

// ResolvedOutputPath returns OutputPath if set, otherwise the package default.
func (c CollectorConfig) ResolvedOutputPath() string {
	if c.OutputPath != "" {
		return c.OutputPath
	}
	return defaultOutputPath
}

// CollectorDataScope is the sentinel key used for ScopeOnce results in the
// collector data map (input.cluster.collectors["name"]["_cluster"]).
const CollectorDataScope = "_cluster"
