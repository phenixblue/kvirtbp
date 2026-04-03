package eval_test

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/eval"
	regoengine "github.com/phenixblue/kvirtbp/internal/eval/rego"
	"github.com/phenixblue/kvirtbp/internal/kube"
)

func preflightPolicyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "policy", "preflight", "preflight.rego")
}

func runPreflightRego(t *testing.T, snap kube.ClusterSnapshot) []checks.Finding {
	t.Helper()
	ctx := context.Background()
	result, err := regoengine.New().Evaluate(ctx, eval.RunRequest{
		Registry:        []checks.Check{},
		PolicyFile:      preflightPolicyPath(t),
		ClusterSnapshot: &snap,
	})
	if err != nil {
		t.Fatalf("rego engine error: %v", err)
	}
	return result.Findings
}

func findingsByID(findings []checks.Finding) map[string]checks.Finding {
	m := make(map[string]checks.Finding, len(findings))
	for _, f := range findings {
		m[f.CheckID] = f
	}
	return m
}

func sortedIDs(findings []checks.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.CheckID)
	}
	sort.Strings(ids)
	return ids
}

func startsWithPerm(id string) bool {
	return len(id) >= 5 && id[:5] == "perm-"
}

func healthyClusterSnapshot() kube.ClusterSnapshot {
	return kube.ClusterSnapshot{
		Degraded:          false,
		KubeVirtInstalled: true,
		HasNetworkingV1:   true,
		HasPolicyV1:       true,
		ServerVersion:     "v1.29.0",
		Nodes: []kube.NodeSnapshot{
			{Name: "cp-1", ControlPlane: true, Ready: true},
			{Name: "cp-2", ControlPlane: true, Ready: true},
			{Name: "cp-3", ControlPlane: true, Ready: true},
			{Name: "worker-1", ControlPlane: false, Ready: true},
			{Name: "worker-2", ControlPlane: false, Ready: true},
		},
		Namespaces: []kube.NamespaceSnapshot{
			{Name: "app-ns-1", Phase: "Active", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}},
			{Name: "app-ns-2", Phase: "Active", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}},
		},
		KubeVirtDeployments: []kube.DeploymentSnapshot{
			{Name: "virt-operator", Namespace: "kubevirt", AvailableReplicas: 2},
		},
		NetworkPolicies: []kube.NetworkPolicySnapshot{
			{Name: "default-deny", Namespace: "app-ns-1"},
			{Name: "default-deny", Namespace: "app-ns-2"},
		},
		ResourceQuotas: []kube.ResourceQuotaSnapshot{
			{Name: "default", Namespace: "app-ns-1"},
			{Name: "default", Namespace: "app-ns-2"},
		},
		LimitRanges: []kube.LimitRangeSnapshot{
			{Name: "default", Namespace: "app-ns-1"},
			{Name: "default", Namespace: "app-ns-2"},
		},
		PodDisruptionBudgets: []kube.PDBSnapshot{
			{Name: "app-pdb", Namespace: "app-ns-1"},
			{Name: "app-pdb", Namespace: "app-ns-2"},
		},
		Permissions: []kube.PermissionSnapshot{
			{ID: "perm-list-nodes", Resource: "nodes", Group: "", Verb: "list", Allowed: true},
			{ID: "perm-list-namespaces", Resource: "namespaces", Group: "", Verb: "list", Allowed: true},
			{ID: "perm-list-vms", Resource: "virtualmachines", Group: "kubevirt.io", Verb: "list", Allowed: true},
		},
	}
}

// --- Degraded ---

func TestRegoPreflightDegradedSnapshot(t *testing.T) {
	snap := kube.DegradedSnapshot(kube.PreflightOptions{})
	findings := runPreflightRego(t, snap)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding for degraded snapshot, got %d: %v", len(findings), sortedIDs(findings))
	}
	byID := findingsByID(findings)
	conn, ok := byID["cluster-connectivity"]
	if !ok {
		t.Fatalf("expected cluster-connectivity finding; got %v", sortedIDs(findings))
	}
	if conn.Pass {
		t.Errorf("cluster-connectivity should fail for degraded snapshot")
	}
}

// --- Discovery error ---

func TestRegoPreflightDiscoveryError(t *testing.T) {
	snap := kube.ClusterSnapshot{
		Degraded:       false,
		DiscoveryError: "API server not responding: connection timeout",
	}
	findings := runPreflightRego(t, snap)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding for discovery error, got %d: %v", len(findings), sortedIDs(findings))
	}
	byID := findingsByID(findings)
	disc, ok := byID["cluster-discovery"]
	if !ok {
		t.Fatalf("expected cluster-discovery finding; got %v", sortedIDs(findings))
	}
	if disc.Pass {
		t.Errorf("cluster-discovery should fail")
	}
}

// --- Healthy cluster ---

func TestRegoPreflightHealthyCluster(t *testing.T) {
	snap := healthyClusterSnapshot()
	findings := runPreflightRego(t, snap)
	byID := findingsByID(findings)

	mustPass := []string{
		"kubevirt-api-availability",
		"sec-networking-api-availability",
		"prod-kubevirt-operator-health",
		"prod-node-inventory",
		"avail-control-plane-ha",
		"sec-namespace-psa-enforce",
		"sec-networkpolicy-coverage",
		"prod-namespace-guardrails-coverage",
		"avail-namespace-pdb-coverage",
	}
	for _, id := range mustPass {
		f, ok := byID[id]
		if !ok {
			t.Errorf("missing expected finding %q (got %v)", id, sortedIDs(findings))
			continue
		}
		if !f.Pass {
			t.Errorf("expected %q to pass, got fail: %s", id, f.Message)
		}
	}
	for id, f := range byID {
		if startsWithPerm(id) && !f.Pass {
			t.Errorf("permission probe %q should pass on healthy snapshot: %s", id, f.Message)
		}
	}
}

// --- Missing PSA label ---

func TestRegoPreflightMissingPSALabel(t *testing.T) {
	snap := healthyClusterSnapshot()
	ns := snap.Namespaces
	for i, n := range ns {
		if n.Name == "app-ns-1" {
			ns[i].Labels = map[string]string{}
		}
	}
	snap.Namespaces = ns

	findings := runPreflightRego(t, snap)
	byID := findingsByID(findings)
	f, ok := byID["sec-namespace-psa-enforce"]
	if !ok {
		t.Fatal("expected sec-namespace-psa-enforce finding")
	}
	if f.Pass {
		t.Errorf("sec-namespace-psa-enforce should fail when a namespace is missing PSA label")
	}
}

// --- Missing NetworkPolicy ---

func TestRegoPreflightMissingNetworkPolicy(t *testing.T) {
	snap := healthyClusterSnapshot()
	filtered := snap.NetworkPolicies[:0]
	for _, np := range snap.NetworkPolicies {
		if np.Namespace != "app-ns-2" {
			filtered = append(filtered, np)
		}
	}
	snap.NetworkPolicies = filtered

	findings := runPreflightRego(t, snap)
	byID := findingsByID(findings)
	f, ok := byID["sec-networkpolicy-coverage"]
	if !ok {
		t.Fatal("expected sec-networkpolicy-coverage finding")
	}
	if f.Pass {
		t.Errorf("sec-networkpolicy-coverage should fail when a namespace has no NetworkPolicy")
	}
}

// --- Insufficient control-plane nodes ---

func TestRegoPreflightInsufficientControlPlane(t *testing.T) {
	snap := healthyClusterSnapshot()
	snap.Nodes = []kube.NodeSnapshot{
		{Name: "cp-1", ControlPlane: true, Ready: true},
		{Name: "worker-1", ControlPlane: false, Ready: true},
		{Name: "worker-2", ControlPlane: false, Ready: true},
	}

	findings := runPreflightRego(t, snap)
	byID := findingsByID(findings)
	f, ok := byID["avail-control-plane-ha"]
	if !ok {
		t.Fatal("expected avail-control-plane-ha finding")
	}
	if f.Pass {
		t.Errorf("avail-control-plane-ha should fail when <3 control-plane nodes")
	}
}

// --- Missing PDB ---

func TestRegoPreflightMissingPDB(t *testing.T) {
	snap := healthyClusterSnapshot()
	filtered := snap.PodDisruptionBudgets[:0]
	for _, p := range snap.PodDisruptionBudgets {
		if p.Namespace != "app-ns-1" {
			filtered = append(filtered, p)
		}
	}
	snap.PodDisruptionBudgets = filtered

	findings := runPreflightRego(t, snap)
	byID := findingsByID(findings)
	f, ok := byID["avail-namespace-pdb-coverage"]
	if !ok {
		t.Fatal("expected avail-namespace-pdb-coverage finding")
	}
	if f.Pass {
		t.Errorf("avail-namespace-pdb-coverage should fail when a namespace has no PDB")
	}
}

// --- Permission denied ---

func TestRegoPreflightPermissionDenied(t *testing.T) {
	snap := healthyClusterSnapshot()
	snap.Permissions = []kube.PermissionSnapshot{
		{ID: "perm-list-nodes", Resource: "nodes", Group: "", Verb: "list", Allowed: false, Reason: "forbidden"},
		{ID: "perm-list-namespaces", Resource: "namespaces", Group: "", Verb: "list", Allowed: true},
		{ID: "perm-list-vms", Resource: "virtualmachines", Group: "kubevirt.io", Verb: "list", Allowed: true},
	}

	findings := runPreflightRego(t, snap)
	byID := findingsByID(findings)

	f, ok := byID["perm-list-nodes"]
	if !ok {
		t.Fatal("expected perm-list-nodes finding")
	}
	if f.Pass {
		t.Errorf("perm-list-nodes should fail when denied")
	}
	if f2, ok := byID["perm-list-namespaces"]; ok && !f2.Pass {
		t.Errorf("perm-list-namespaces should pass, got fail")
	}
}

// --- Equivalence: Rego vs Go on healthy cluster ---

func TestRegoPreflightEquivalentToGoOnHealthyCluster(t *testing.T) {
	snap := healthyClusterSnapshot()

	goFindings := kube.BuildPreflightFindingsFromSnapshot(snap)
	regoFindings := runPreflightRego(t, snap)

	goByID := findingsByID(goFindings)
	regoByID := findingsByID(regoFindings)

	for id, goF := range goByID {
		regoF, ok := regoByID[id]
		if !ok {
			t.Errorf("Rego missing finding %q (present in Go result)", id)
			continue
		}
		if goF.Pass != regoF.Pass {
			t.Errorf("finding %q: Go pass=%v, Rego pass=%v (Go: %q, Rego: %q)", id, goF.Pass, regoF.Pass, goF.Message, regoF.Message)
		}
	}
	for id, regoF := range regoByID {
		goF, ok := goByID[id]
		if !ok {
			continue // Rego may emit extra findings not in Go; that's acceptable
		}
		if goF.Pass != regoF.Pass {
			t.Errorf("finding %q: Rego pass=%v, Go pass=%v", id, regoF.Pass, goF.Pass)
		}
	}
}
