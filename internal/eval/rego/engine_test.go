package rego

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/collector"
	"github.com/phenixblue/kvirtbp/internal/eval"
	"github.com/phenixblue/kvirtbp/internal/kube"
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

func TestResourceTypesFromBundle_WithResources(t *testing.T) {
	tmp := t.TempDir()
	meta := `{"schemaVersion":"v1alpha1","resources":["apps/v1/Deployment","v1/ConfigMap"]}`
	if err := os.WriteFile(filepath.Join(tmp, "metadata.json"), []byte(meta), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	got, err := ResourceTypesFromBundle(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "apps/v1/Deployment" || got[1] != "v1/ConfigMap" {
		t.Errorf("unexpected resources: %v", got)
	}
}

func TestResourceTypesFromBundle_NoResourcesField(t *testing.T) {
	tmp := t.TempDir()
	meta := `{"schemaVersion":"v1alpha1"}`
	if err := os.WriteFile(filepath.Join(tmp, "metadata.json"), []byte(meta), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	got, err := ResourceTypesFromBundle(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected nil/empty resources, got %v", got)
	}
}

func TestResourceTypesFromBundle_MissingMetadata(t *testing.T) {
	tmp := t.TempDir()
	// no metadata.json written
	got, err := ResourceTypesFromBundle(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty resources for missing metadata, got %v", got)
	}
}

func TestResourceTypesFromBundle_NonExistentBundle(t *testing.T) {
	// A non-existent path means metadata.json also doesn't exist, which the
	// implementation treats the same as a missing file — no error, no resources.
	got, err := ResourceTypesFromBundle("/does/not/exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty resources, got %v", got)
	}
}

// ---- CollectorsFromBundle ----

func TestCollectorsFromBundle_WithCollectors(t *testing.T) {
	tmp := t.TempDir()
	meta := `{
		"schemaVersion": "v1alpha1",
		"collectors": [
			{"name": "sysctl", "image": "alpine", "scope": "per-node", "commands": ["sysctl -a > /kvirtbp/output.json"]}
		]
	}`
	if err := os.WriteFile(filepath.Join(tmp, "metadata.json"), []byte(meta), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	got, err := CollectorsFromBundle(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 collector, got %d", len(got))
	}
	if got[0].Name != "sysctl" || got[0].Image != "alpine" || got[0].Scope != collector.ScopePerNode {
		t.Errorf("unexpected collector: %+v", got[0])
	}
}

func TestCollectorsFromBundle_NoCollectorsField(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "metadata.json"), []byte(`{"schemaVersion":"v1alpha1"}`), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	got, err := CollectorsFromBundle(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected nil/empty collectors, got %v", got)
	}
}

func TestCollectorsFromBundle_MissingMetadata(t *testing.T) {
	tmp := t.TempDir()
	got, err := CollectorsFromBundle(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty collectors for missing metadata, got %v", got)
	}
}

// ---- Rego evaluation with collector data ----

func TestEvaluateWithCollectorData(t *testing.T) {
	tmp := t.TempDir()

	// Policy that inspects input.cluster.collectors and emits a passing finding
	// when a specific sysctl value is present.
	policy := `package kvirtbp

import rego.v1

ip_forward := object.get(
    object.get(
        object.get(
            object.get(input.cluster, "collectors", {}),
        "sysctl", {}),
    "_cluster", {}),
"net.ipv4.ip_forward", "0")

findings := [{
  "checkId": "collector-check",
  "title": "IP Forwarding Check",
  "category": "security",
  "severity": "info",
  "pass": ip_forward == "1",
  "message": "net.ipv4.ip_forward should be 1"
}]`
	if err := os.WriteFile(filepath.Join(tmp, "policy.rego"), []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "metadata.json"), []byte(`{"schemaVersion":"v1alpha1"}`), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	snap := &kube.ClusterSnapshot{
		Collectors: map[string]any{
			"sysctl": map[string]any{
				"_cluster": map[string]any{
					"net.ipv4.ip_forward": "1",
				},
			},
		},
	}

	engine := New()
	result, err := engine.Evaluate(context.Background(), eval.RunRequest{
		PolicyBundle:    tmp,
		ClusterSnapshot: snap,
	})
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if !result.Findings[0].Pass {
		t.Errorf("expected finding to pass when collector value is '1'")
	}
}

func TestEvaluateWithCollectorData_MissingData(t *testing.T) {
	tmp := t.TempDir()

	// Policy that gracefully handles absent collector data by defaulting to "0".
	// When no collector data is injected the pass condition must be false.
	policy := `package kvirtbp

import rego.v1

# Start from input.cluster (always present) to safely handle absent collectors.
ip_forward := object.get(
    object.get(
        object.get(
            object.get(input.cluster, "collectors", {}),
        "sysctl", {}),
    "_cluster", {}),
"net.ipv4.ip_forward", "0")

findings := [{
  "checkId": "collector-check",
  "title": "IP Forwarding Check",
  "category": "security",
  "severity": "info",
  "pass": ip_forward == "1",
  "message": "net.ipv4.ip_forward should be 1"
}]`
	if err := os.WriteFile(filepath.Join(tmp, "policy.rego"), []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "metadata.json"), []byte(`{"schemaVersion":"v1alpha1"}`), 0o644); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	// No collector data injected — ClusterSnapshot.Collectors is nil.
	snap := &kube.ClusterSnapshot{}

	engine := New()
	result, err := engine.Evaluate(context.Background(), eval.RunRequest{
		PolicyBundle:    tmp,
		ClusterSnapshot: snap,
	})
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Pass {
		t.Errorf("expected finding to fail when collector data is absent")
	}
}
