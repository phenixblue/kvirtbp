package checks

import "testing"

func TestParseCheckFlags(t *testing.T) {
	inc, exc := ParseCheckFlags([]string{"check-a", "check-b-", "check-c", ""})
	if len(inc) != 2 || inc[0] != "check-a" || inc[1] != "check-c" {
		t.Fatalf("unexpected include: %v", inc)
	}
	if len(exc) != 1 || exc[0] != "check-b" {
		t.Fatalf("unexpected exclude: %v", exc)
	}

	// All excludes, no includes.
	inc, exc = ParseCheckFlags([]string{"x-", "y-"})
	if len(inc) != 0 {
		t.Fatalf("expected empty include, got %v", inc)
	}
	if len(exc) != 2 {
		t.Fatalf("expected 2 excludes, got %v", exc)
	}
}

func TestFilterRegistryByCategoryAndSeverity(t *testing.T) {
	registry := []Check{BaselineControl{meta: Metadata{ID: "prod-baseline-kubevirt-readiness", Title: "Production Baseline", Category: "production-readiness", Severity: SeverityInfo}}}

	filtered := FilterRegistry(registry, Filter{
		Categories: []string{"production-readiness"},
		Severities: []Severity{SeverityInfo},
	})
	if len(filtered) != 1 {
		t.Fatalf("expected 1 check after filter, got %d", len(filtered))
	}

	filtered = FilterRegistry(registry, Filter{Categories: []string{"security"}})
	if len(filtered) != 0 {
		t.Fatalf("expected 0 checks after category mismatch, got %d", len(filtered))
	}
}

func TestFilterFindingsByIncludeExclude(t *testing.T) {
	findings := []Finding{
		{CheckID: "a", Category: "x", Severity: SeverityInfo},
		{CheckID: "b", Category: "y", Severity: SeverityWarning},
	}

	filtered := FilterFindings(findings, Filter{IncludeIDs: []string{"a"}})
	if len(filtered) != 1 || filtered[0].CheckID != "a" {
		t.Fatalf("unexpected include filter result: %+v", filtered)
	}

	filtered = FilterFindings(findings, Filter{ExcludeIDs: []string{"a"}})
	if len(filtered) != 1 || filtered[0].CheckID != "b" {
		t.Fatalf("unexpected exclude filter result: %+v", filtered)
	}
}

func TestParseSeverity(t *testing.T) {
	if _, err := ParseSeverity("warning"); err != nil {
		t.Fatalf("expected warning severity to parse: %v", err)
	}
	if _, err := ParseSeverity("invalid"); err == nil {
		t.Fatal("expected invalid severity to fail")
	}
}
