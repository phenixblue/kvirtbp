package rego

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/eval"
)

type stubCheck struct {
	meta checks.Metadata
}

func (s stubCheck) Metadata() checks.Metadata {
	return s.meta
}

func (s stubCheck) Evaluate(ctx context.Context) ([]checks.Finding, error) {
	_ = ctx
	return nil, nil
}

func TestEvaluateWithDefaultPolicy(t *testing.T) {
	engine := New()

	result, err := engine.Evaluate(context.Background(), eval.RunRequest{
		Registry: []checks.Check{stubCheck{meta: checks.Metadata{
			ID:       "id-1",
			Title:    "Title 1",
			Category: "security",
			Severity: checks.SeverityInfo,
		}}},
	})
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(result.Findings))
	}
	if result.Findings[0].CheckID != "id-1" {
		t.Fatalf("expected finding check id id-1, got %s", result.Findings[0].CheckID)
	}
}

func TestEvaluateWithUnsupportedCategory(t *testing.T) {
	engine := New()

	result, err := engine.Evaluate(context.Background(), eval.RunRequest{
		Registry: []checks.Check{stubCheck{meta: checks.Metadata{
			ID:       "id-unsupported",
			Title:    "Unsupported",
			Category: "unknown",
			Severity: checks.SeverityInfo,
		}}},
	})
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Pass {
		t.Fatal("expected unsupported category to fail policy validation")
	}
	if result.Findings[0].ReasonCode != "rego.category.unsupported" {
		t.Fatalf("expected reasonCode rego.category.unsupported, got %s", result.Findings[0].ReasonCode)
	}
}

func TestEvaluateWithCategoryIDMismatch(t *testing.T) {
	engine := New()

	result, err := engine.Evaluate(context.Background(), eval.RunRequest{
		Registry: []checks.Check{stubCheck{meta: checks.Metadata{
			ID:       "prod-wrong-prefix",
			Title:    "Wrong Prefix",
			Category: "security",
			Severity: checks.SeverityInfo,
		}}},
	})
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Pass {
		t.Fatal("expected category/id mismatch to fail policy validation")
	}
	if result.Findings[0].ReasonCode != "rego.id.category.mismatch" {
		t.Fatalf("expected reasonCode rego.id.category.mismatch, got %s", result.Findings[0].ReasonCode)
	}
}

func TestEvaluateWithMissingPolicyFile(t *testing.T) {
	engine := New()
	_, err := engine.Evaluate(context.Background(), eval.RunRequest{PolicyFile: "missing-file.rego"})
	if err == nil {
		t.Fatal("expected error for missing policy file")
	}
}

func TestEvaluateWithPolicyBundle(t *testing.T) {
	engine := New()
	tmp := t.TempDir()

	policy := `package kvirtbp

findings := [{
  "checkId": "bundle-check",
  "title": "Bundle Check",
  "category": "security",
  "severity": "info",
  "pass": true,
  "message": "bundle ok"
}]`
	if err := os.WriteFile(filepath.Join(tmp, "bundle.rego"), []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "metadata.json"), []byte(`{"schemaVersion":"v1alpha1"}`), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	result, err := engine.Evaluate(context.Background(), eval.RunRequest{PolicyBundle: tmp})
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].CheckID != "bundle-check" {
		t.Fatalf("unexpected findings: %+v", result.Findings)
	}
}

func TestEvaluateWithInvalidFindingSeverity(t *testing.T) {
	engine := New()
	tmp := t.TempDir()

	policy := `package kvirtbp

findings := [{
  "checkId": "bad",
  "title": "Bad",
  "category": "security",
  "severity": "critical",
  "pass": true,
  "message": "bad severity"
}]`
	path := filepath.Join(tmp, "bad.rego")
	if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, err := engine.Evaluate(context.Background(), eval.RunRequest{PolicyFile: path})
	if err == nil {
		t.Fatal("expected validation error")
	}
}
