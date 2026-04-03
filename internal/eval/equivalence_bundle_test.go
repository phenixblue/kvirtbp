package eval_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/eval"
	"github.com/phenixblue/kvirtbp/internal/eval/goeval"
	regoengine "github.com/phenixblue/kvirtbp/internal/eval/rego"
)

type bundleEquivalenceCheck struct {
	meta checks.Metadata
}

func (s bundleEquivalenceCheck) Metadata() checks.Metadata {
	return s.meta
}

func (s bundleEquivalenceCheck) Evaluate(ctx context.Context) ([]checks.Finding, error) {
	_ = ctx
	return []checks.Finding{buildFinding(s.meta)}, nil
}

func TestGoAndCheckedInRegoBundleEquivalentForBaselineCategories(t *testing.T) {
	registry := []checks.Check{
		bundleEquivalenceCheck{meta: checks.Metadata{ID: "prod-baseline-kubevirt-readiness", Title: "Production Baseline", Category: "production-readiness", Severity: checks.SeverityInfo}},
		bundleEquivalenceCheck{meta: checks.Metadata{ID: "sec-baseline-rbac-safety", Title: "Security Baseline", Category: "security", Severity: checks.SeverityInfo}},
		bundleEquivalenceCheck{meta: checks.Metadata{ID: "avail-baseline-workload-resilience", Title: "Availability Baseline", Category: "availability", Severity: checks.SeverityInfo}},
	}

	bundlePath := filepath.Join("..", "..", "policy", "baseline")
	ctx := context.Background()
	goResult, err := goeval.New().Evaluate(ctx, eval.RunRequest{Registry: registry})
	if err != nil {
		t.Fatalf("go evaluator failed: %v", err)
	}
	regoResult, err := regoengine.New().Evaluate(ctx, eval.RunRequest{Registry: registry, PolicyBundle: bundlePath})
	if err != nil {
		t.Fatalf("rego evaluator failed: %v", err)
	}

	if !eval.Equivalent(goResult, regoResult) {
		t.Fatalf("expected equivalent normalized findings\ngo=%+v\nrego=%+v", eval.NormalizeForComparison(goResult), eval.NormalizeForComparison(regoResult))
	}
}

func TestCheckedInBundleMatchesDefaultPolicyForCategoryIDMismatch(t *testing.T) {
	registry := []checks.Check{
		bundleEquivalenceCheck{meta: checks.Metadata{ID: "prod-wrong-prefix", Title: "Wrong Prefix", Category: "security", Severity: checks.SeverityInfo}},
	}

	bundlePath := filepath.Join("..", "..", "policy", "baseline")
	ctx := context.Background()
	defaultResult, err := regoengine.New().Evaluate(ctx, eval.RunRequest{Registry: registry})
	if err != nil {
		t.Fatalf("default rego evaluator failed: %v", err)
	}
	bundleResult, err := regoengine.New().Evaluate(ctx, eval.RunRequest{Registry: registry, PolicyBundle: bundlePath})
	if err != nil {
		t.Fatalf("bundle rego evaluator failed: %v", err)
	}

	if len(defaultResult.Findings) != 1 || len(bundleResult.Findings) != 1 {
		t.Fatalf("expected exactly one finding from each evaluator, got default=%d bundle=%d", len(defaultResult.Findings), len(bundleResult.Findings))
	}

	if defaultResult.Findings[0].ReasonCode != "rego.id.category.mismatch" {
		t.Fatalf("expected default reasonCode rego.id.category.mismatch, got %s", defaultResult.Findings[0].ReasonCode)
	}
	if bundleResult.Findings[0].ReasonCode != "rego.id.category.mismatch" {
		t.Fatalf("expected bundle reasonCode rego.id.category.mismatch, got %s", bundleResult.Findings[0].ReasonCode)
	}

	if !eval.Equivalent(defaultResult, bundleResult) {
		t.Fatalf("expected equivalent normalized findings\ndefault=%+v\nbundle=%+v", eval.NormalizeForComparison(defaultResult), eval.NormalizeForComparison(bundleResult))
	}
}

func TestFullBundleProducesCatalogAndClusterFindings(t *testing.T) {
	registry := []checks.Check{
		bundleEquivalenceCheck{meta: checks.Metadata{ID: "prod-baseline-kubevirt-readiness", Title: "Production Baseline", Category: "production-readiness", Severity: checks.SeverityInfo}},
		bundleEquivalenceCheck{meta: checks.Metadata{ID: "sec-baseline-rbac-safety", Title: "Security Baseline", Category: "security", Severity: checks.SeverityInfo}},
		bundleEquivalenceCheck{meta: checks.Metadata{ID: "avail-baseline-workload-resilience", Title: "Availability Baseline", Category: "availability", Severity: checks.SeverityInfo}},
	}

	snap := healthyClusterSnapshot()
	bundlePath := filepath.Join("..", "..", "policy")
	ctx := context.Background()

	result, err := regoengine.New().Evaluate(ctx, eval.RunRequest{
		Registry:        registry,
		PolicyBundle:    bundlePath,
		ClusterSnapshot: &snap,
	})
	if err != nil {
		t.Fatalf("full bundle evaluator failed: %v", err)
	}

	byID := make(map[string]checks.Finding, len(result.Findings))
	for _, f := range result.Findings {
		byID[f.CheckID] = f
	}

	// Catalog findings must be present.
	catalogIDs := []string{"prod-baseline-kubevirt-readiness", "sec-baseline-rbac-safety", "avail-baseline-workload-resilience"}
	for _, id := range catalogIDs {
		if _, ok := byID[id]; !ok {
			t.Errorf("full bundle missing catalog finding %q", id)
		}
	}

	// Key cluster findings must be present and passing.
	clusterPassIDs := []string{
		"kubevirt-api-availability",
		"prod-node-inventory",
		"avail-control-plane-ha",
		"sec-namespace-psa-enforce",
		"sec-networkpolicy-coverage",
		"prod-namespace-guardrails-coverage",
		"avail-namespace-pdb-coverage",
	}
	for _, id := range clusterPassIDs {
		f, ok := byID[id]
		if !ok {
			t.Errorf("full bundle missing cluster finding %q", id)
			continue
		}
		if !f.Pass {
			t.Errorf("full bundle cluster finding %q should pass on healthy snapshot, got fail: %s", id, f.Message)
		}
	}
}
