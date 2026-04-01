package checks

import (
	"context"
	"testing"
)

func TestRunAllReturnsFindings(t *testing.T) {
	result, err := RunAll(context.Background(), DefaultChecks())
	if err != nil {
		t.Fatalf("RunAll() returned error: %v", err)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 baseline findings, got %d", len(result.Findings))
	}
	if result.SchemaVersion != ReportSchemaVersion {
		t.Fatalf("expected schema version %s, got %s", ReportSchemaVersion, result.SchemaVersion)
	}
}

func TestDefaultCatalogDomainCoverage(t *testing.T) {
	checks := DefaultChecks()
	if len(checks) != 3 {
		t.Fatalf("expected 3 default checks, got %d", len(checks))
	}

	seen := map[string]bool{}
	for _, c := range checks {
		seen[c.Metadata().Category] = true
	}

	for _, cat := range []string{"production-readiness", "security", "availability"} {
		if !seen[cat] {
			t.Fatalf("expected category %s in default catalog", cat)
		}
	}
}
