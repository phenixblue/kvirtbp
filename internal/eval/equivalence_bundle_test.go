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
