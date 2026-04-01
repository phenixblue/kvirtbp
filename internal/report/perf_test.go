package report

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

// syntheticResult builds a RunResult with n findings spread across three
// categories and severities, alternating pass/fail.
func syntheticResult(n int) checks.RunResult {
	categories := []string{"production-readiness", "security", "availability"}
	severities := []checks.Severity{checks.SeverityInfo, checks.SeverityWarning, checks.SeverityError}

	findings := make([]checks.Finding, n)
	for i := range findings {
		pass := i%3 != 0
		findings[i] = checks.Finding{
			CheckID:       fmt.Sprintf("check-%04d", i),
			Title:         fmt.Sprintf("Check %d", i),
			Category:      categories[i%len(categories)],
			Severity:      severities[i%len(severities)],
			Pass:          pass,
			Message:       fmt.Sprintf("result for check %d", i),
			ReasonCode:    fmt.Sprintf("reason.%d", i%10),
			RemediationID: fmt.Sprintf("RUNBOOK-%04d", i%20),
		}
	}

	return checks.RunResult{
		SchemaVersion: checks.ReportSchemaVersion,
		Metadata: &checks.MetadataRun{
			Engine:         "go",
			EvaluationMode: "hybrid",
			DurationMillis: 150,
		},
		Summary:  checks.Summarize(findings),
		Findings: findings,
	}
}

// ---- Latency budget tests ------------------------------------------------

func TestWriteJSON_LatencyBudget1000Findings(t *testing.T) {
	result := syntheticResult(1000)
	budget := 100 * time.Millisecond

	var buf bytes.Buffer
	start := time.Now()
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	elapsed := time.Since(start)

	if buf.Len() == 0 {
		t.Fatal("expected non-empty JSON output")
	}
	if elapsed > budget {
		t.Errorf("WriteJSON/1000findings took %v, budget is %v", elapsed, budget)
	}
}

func TestWriteJSON_LatencyBudget5000Findings(t *testing.T) {
	result := syntheticResult(5000)
	budget := 500 * time.Millisecond

	var buf bytes.Buffer
	start := time.Now()
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	elapsed := time.Since(start)

	if buf.Len() == 0 {
		t.Fatal("expected non-empty JSON output")
	}
	if elapsed > budget {
		t.Errorf("WriteJSON/5000findings took %v, budget is %v", elapsed, budget)
	}
}

func TestWriteTable_LatencyBudget500Findings(t *testing.T) {
	result := syntheticResult(500)
	budget := 2 * time.Second // lipgloss table rendering is terminal-bound; generous budget

	var buf bytes.Buffer
	start := time.Now()
	if err := WriteTable(&buf, result); err != nil {
		t.Fatalf("WriteTable failed: %v", err)
	}
	elapsed := time.Since(start)

	if buf.Len() == 0 {
		t.Fatal("expected non-empty table output")
	}
	if elapsed > budget {
		t.Errorf("WriteTable/500findings took %v, budget is %v", elapsed, budget)
	}
}

// ---- Benchmarks ----------------------------------------------------------

func BenchmarkWriteJSON(b *testing.B) {
	result := syntheticResult(1000)
	b.ResetTimer()
	for range b.N {
		var buf bytes.Buffer
		_ = WriteJSON(&buf, result)
	}
}

func BenchmarkWriteTable(b *testing.B) {
	result := syntheticResult(100)
	b.ResetTimer()
	for range b.N {
		var buf bytes.Buffer
		_ = WriteTable(&buf, result)
	}
}
