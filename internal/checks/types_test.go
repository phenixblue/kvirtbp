package checks

import "testing"

func TestSummarize(t *testing.T) {
	findings := []Finding{
		{Pass: true, Severity: SeverityInfo},
		{Pass: false, Severity: SeverityWarning},
		{Pass: false, Severity: SeverityError},
	}

	s := Summarize(findings)
	if s.Total != 3 || s.Passed != 1 || s.Failed != 2 {
		t.Fatalf("unexpected summary counts: %+v", s)
	}
	if s.Info != 1 || s.Warning != 1 || s.Error != 1 {
		t.Fatalf("unexpected severity counts: %+v", s)
	}
}

func TestExitCode(t *testing.T) {
	ok := RunResult{Findings: []Finding{{Pass: true, CheckID: "x"}}}
	if code := ExitCode(ok); code != ExitCodeSuccess {
		t.Fatalf("expected success exit code, got %d", code)
	}

	violation := RunResult{Findings: []Finding{{Pass: false, CheckID: "sec-rbac"}}}
	if code := ExitCode(violation); code != ExitCodeViolation {
		t.Fatalf("expected violation exit code, got %d", code)
	}

	partial := RunResult{Findings: []Finding{{Pass: false, CheckID: "cluster-connectivity"}}}
	if code := ExitCode(partial); code != ExitCodePartial {
		t.Fatalf("expected partial exit code, got %d", code)
	}
}
