package collector

import (
	"context"
	"time"

	"github.com/phenixblue/kvirtbp/internal/kube"
)

// RunOptions are passed to each Collector at execution time.
type RunOptions struct {
	// Namespace is the Kubernetes namespace where Jobs are created.
	Namespace string

	// GlobalTimeout is the maximum total time to wait for a collector to
	// finish, regardless of its per-CollectorConfig TimeoutSeconds value.
	// A zero value means no global cap.
	GlobalTimeout time.Duration

	// SkipCleanup prevents the Collector from deleting the Job (and its Pods)
	// after completion. Useful for debugging.
	SkipCleanup bool
}

// Collector runs a single CollectorConfig against the cluster and returns the
// collected data keyed by node name (ScopePerNode) or by CollectorDataScope
// (ScopeOnce).
type Collector interface {
	// Name returns the collector name, matching CollectorConfig.Name.
	Name() string

	// Collect executes the collector and returns its output.
	// The returned map is map[nodeNameOrCluster]map[string]any.
	// On partial failures (e.g. one node out of many fails) the node entry
	// contains {"_error": "<message>"} rather than returning a top-level error.
	Collect(ctx context.Context, clients *kube.Clients, opts RunOptions) (map[string]any, error)
}
