package checks

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// latencyBudgets defines the maximum allowed wall-clock time per operation at
// the given synthetic scale. These are intentionally conservative to avoid
// flakiness on slow CI runners while still catching O(N²) regressions.
var latencyBudgets = map[string]time.Duration{
	"FilterRegistry/500checks":        10 * time.Millisecond,
	"FilterFindings/1000findings":      10 * time.Millisecond,
	"FilterFindings/5000findings":      50 * time.Millisecond,
	"ApplyWaivers/1000findings":        10 * time.Millisecond,
	"ApplyWaivers/5000findings":        50 * time.Millisecond,
	"ApplyBaselineAssessments/1000findings": 10 * time.Millisecond,
	"Summarize/5000findings":           10 * time.Millisecond,
}

// syntheticRegistry builds N checks evenly spread across 3 categories.
func syntheticRegistry(n int) []Check {
	categories := []string{"production-readiness", "security", "availability"}
	severities := []Severity{SeverityInfo, SeverityWarning, SeverityError}
	checks := make([]Check, n)
	for i := range checks {
		checks[i] = BaselineControl{meta: Metadata{
			ID:       fmt.Sprintf("check-%04d", i),
			Title:    fmt.Sprintf("Check %d", i),
			Category: categories[i%len(categories)],
			Severity: severities[i%len(severities)],
		}}
	}
	return checks
}

// syntheticFindings builds N findings evenly spread across 3 categories.
func syntheticFindings(n int) []Finding {
	categories := []string{"production-readiness", "security", "availability"}
	severities := []Severity{SeverityInfo, SeverityWarning, SeverityError}
	findings := make([]Finding, n)
	for i := range findings {
		findings[i] = Finding{
			CheckID:       fmt.Sprintf("check-%04d", i),
			Title:         fmt.Sprintf("Check %d", i),
			Category:      categories[i%len(categories)],
			Severity:      severities[i%len(severities)],
			Pass:          i%3 != 0,
			Message:       fmt.Sprintf("result for check %d", i),
			ReasonCode:    fmt.Sprintf("reason.%d", i%10),
			RemediationID: fmt.Sprintf("RUNBOOK-%04d", i%20),
		}
	}
	return findings
}

// syntheticWaivers builds n waivers matching every other check ID.
func syntheticWaivers(n int) []Waiver {
	waivers := make([]Waiver, n)
	for i := range waivers {
		waivers[i] = Waiver{
			CheckID:       fmt.Sprintf("check-%04d", i*2),
			Justification: fmt.Sprintf("waiver justification %d", i),
			Owner:         "perf-test-owner",
		}
	}
	return waivers
}

// ---- Latency budget tests ------------------------------------------------

func TestFilterRegistry_LatencyBudget500(t *testing.T) {
	registry := syntheticRegistry(500)
	filter := Filter{Categories: []string{"security"}}
	budget := latencyBudgets["FilterRegistry/500checks"]

	start := time.Now()
	result := FilterRegistry(registry, filter)
	elapsed := time.Since(start)

	if len(result) == 0 {
		t.Fatal("expected non-empty filtered result")
	}
	if elapsed > budget {
		t.Errorf("FilterRegistry/500 took %v, budget is %v", elapsed, budget)
	}
}

func TestFilterFindings_LatencyBudget1000(t *testing.T) {
	findings := syntheticFindings(1000)
	filter := Filter{Categories: []string{"security"}}
	budget := latencyBudgets["FilterFindings/1000findings"]

	start := time.Now()
	result := FilterFindings(findings, filter)
	elapsed := time.Since(start)

	if len(result) == 0 {
		t.Fatal("expected non-empty filtered result")
	}
	if elapsed > budget {
		t.Errorf("FilterFindings/1000 took %v, budget is %v", elapsed, budget)
	}
}

func TestFilterFindings_LatencyBudget5000(t *testing.T) {
	findings := syntheticFindings(5000)
	filter := Filter{Categories: []string{"security"}}
	budget := latencyBudgets["FilterFindings/5000findings"]

	start := time.Now()
	result := FilterFindings(findings, filter)
	elapsed := time.Since(start)

	if len(result) == 0 {
		t.Fatal("expected non-empty filtered result")
	}
	if elapsed > budget {
		t.Errorf("FilterFindings/5000 took %v, budget is %v", elapsed, budget)
	}
}

func TestApplyWaivers_LatencyBudget1000(t *testing.T) {
	findings := syntheticFindings(1000)
	waivers := syntheticWaivers(100)
	budget := latencyBudgets["ApplyWaivers/1000findings"]

	start := time.Now()
	result := ApplyWaivers(findings, waivers)
	elapsed := time.Since(start)

	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
	if elapsed > budget {
		t.Errorf("ApplyWaivers/1000 took %v, budget is %v", elapsed, budget)
	}
}

func TestApplyWaivers_LatencyBudget5000(t *testing.T) {
	findings := syntheticFindings(5000)
	waivers := syntheticWaivers(200)
	budget := latencyBudgets["ApplyWaivers/5000findings"]

	start := time.Now()
	result := ApplyWaivers(findings, waivers)
	elapsed := time.Since(start)

	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
	if elapsed > budget {
		t.Errorf("ApplyWaivers/5000 took %v, budget is %v", elapsed, budget)
	}
}

func TestSummarize_LatencyBudget5000(t *testing.T) {
	findings := syntheticFindings(5000)
	budget := latencyBudgets["Summarize/5000findings"]

	start := time.Now()
	s := Summarize(findings)
	elapsed := time.Since(start)

	if s.Total != 5000 {
		t.Fatalf("expected Total=5000, got %d", s.Total)
	}
	if elapsed > budget {
		t.Errorf("Summarize/5000 took %v, budget is %v", elapsed, budget)
	}
}

func TestApplyBaselineAssessments_LatencyBudget1000(t *testing.T) {
	// ApplyBaselineAssessments works on a fixed check set; the scale test
	// validates that it handles a large slice without degrading on the index pass.
	findings := syntheticFindings(1000)
	budget := latencyBudgets["ApplyBaselineAssessments/1000findings"]

	start := time.Now()
	result := ApplyBaselineAssessments(findings)
	elapsed := time.Since(start)

	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
	if elapsed > budget {
		t.Errorf("ApplyBaselineAssessments/1000 took %v, budget is %v", elapsed, budget)
	}
}

// ---- Go evaluator end-to-end scale test ---------------------------------

func TestRunFiltered_Scale500Checks(t *testing.T) {
	registry := syntheticRegistry(500)
	filter := Filter{}
	budget := 200 * time.Millisecond

	start := time.Now()
	result, err := RunFiltered(context.Background(), registry, filter)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("RunFiltered failed: %v", err)
	}
	if result.Summary.Total == 0 {
		t.Fatal("expected non-zero findings from 500 checks")
	}
	if elapsed > budget {
		t.Errorf("RunFiltered/500checks took %v, budget is %v", elapsed, budget)
	}
}

// ---- Benchmarks ----------------------------------------------------------

func BenchmarkFilterRegistry(b *testing.B) {
	registry := syntheticRegistry(500)
	filter := Filter{Categories: []string{"security"}}
	b.ResetTimer()
	for range b.N {
		_ = FilterRegistry(registry, filter)
	}
}

func BenchmarkFilterFindings(b *testing.B) {
	findings := syntheticFindings(1000)
	filter := Filter{Categories: []string{"security"}}
	b.ResetTimer()
	for range b.N {
		_ = FilterFindings(findings, filter)
	}
}

func BenchmarkApplyWaivers(b *testing.B) {
	findings := syntheticFindings(1000)
	waivers := syntheticWaivers(100)
	b.ResetTimer()
	for range b.N {
		fc := make([]Finding, len(findings))
		copy(fc, findings)
		_ = ApplyWaivers(fc, waivers)
	}
}

func BenchmarkSummarize(b *testing.B) {
	findings := syntheticFindings(5000)
	b.ResetTimer()
	for range b.N {
		_ = Summarize(findings)
	}
}

func BenchmarkRunFiltered(b *testing.B) {
	registry := syntheticRegistry(500)
	filter := Filter{}
	ctx := context.Background()
	b.ResetTimer()
	for range b.N {
		_, _ = RunFiltered(ctx, registry, filter)
	}
}
