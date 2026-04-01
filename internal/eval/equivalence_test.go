package eval_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/eval"
	"github.com/phenixblue/kvirtbp/internal/eval/goeval"
	regoengine "github.com/phenixblue/kvirtbp/internal/eval/rego"
)

type equivalenceCheck struct {
	meta checks.Metadata
}

func (s equivalenceCheck) Metadata() checks.Metadata {
	return s.meta
}

func (s equivalenceCheck) Evaluate(ctx context.Context) ([]checks.Finding, error) {
	_ = ctx
	return []checks.Finding{buildFinding(s.meta)}, nil
}

func TestGoAndRegoEquivalentFindings(t *testing.T) {
	registry := []checks.Check{
		equivalenceCheck{meta: checks.Metadata{ID: "prod-baseline-kubevirt-readiness", Title: "Production Baseline: KubeVirt Readiness", Category: "production-readiness", Severity: checks.SeverityInfo}},
		equivalenceCheck{meta: checks.Metadata{ID: "sec-baseline-rbac-safety", Title: "Security Baseline: RBAC Safety", Category: "security", Severity: checks.SeverityInfo}},
		equivalenceCheck{meta: checks.Metadata{ID: "avail-baseline-workload-resilience", Title: "Availability Baseline: Workload Resilience", Category: "availability", Severity: checks.SeverityInfo}},
	}

	regoPolicy := `package kvirtbp

findings := [finding |
	check := input.checks[_]
	finding := {
		"checkId": check.id,
		"title": check.title,
		"category": check.category,
		"severity": check.severity,
		"pass": true,
		"message": sprintf("control %s passed", [check.id])
	}
]
`

	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "equivalence.rego")
	if err := os.WriteFile(policyPath, []byte(regoPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	ctx := context.Background()
	goResult, err := goeval.New().Evaluate(ctx, eval.RunRequest{Registry: registry})
	if err != nil {
		t.Fatalf("go evaluator failed: %v", err)
	}
	regoResult, err := regoengine.New().Evaluate(ctx, eval.RunRequest{Registry: registry, PolicyFile: policyPath})
	if err != nil {
		t.Fatalf("rego evaluator failed: %v", err)
	}

	if !eval.Equivalent(goResult, regoResult) {
		t.Fatalf("expected equivalent normalized findings\ngo=%+v\nrego=%+v", eval.NormalizeForComparison(goResult), eval.NormalizeForComparison(regoResult))
	}
}

func TestEquivalentDetectsDifferences(t *testing.T) {
	a := checks.RunResult{Findings: []checks.Finding{{CheckID: "a", Title: "A", Category: "security", Severity: checks.SeverityInfo, Pass: true}}}
	b := checks.RunResult{Findings: []checks.Finding{{CheckID: "a", Title: "A", Category: "security", Severity: checks.SeverityError, Pass: true}}}

	if eval.Equivalent(a, b) {
		t.Fatal("expected non-equivalent results")
	}
}

func buildFinding(m checks.Metadata) checks.Finding {
	return checks.Finding{
		CheckID:  m.ID,
		Title:    m.Title,
		Category: m.Category,
		Severity: m.Severity,
		Pass:     true,
		Message:  "control passed",
	}
}
