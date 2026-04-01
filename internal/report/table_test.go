package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

func TestWriteTableIncludesSummaryAndTriage(t *testing.T) {
	result := checks.RunResult{
		Summary: checks.Summary{Total: 2, Passed: 1, Failed: 1, Info: 1, Warning: 1, Error: 0},
		Findings: []checks.Finding{
			{
				CheckID:  "ok-check",
				Category: "security",
				Severity: checks.SeverityInfo,
				Pass:     true,
				Message:  "ok",
			},
			{
				CheckID:       "bad-check",
				Category:      "security",
				Severity:      checks.SeverityWarning,
				Pass:          false,
				ReasonCode:    "sec.rbac.permissions.missing",
				RemediationID: "RUNBOOK-SEC-RBAC-001",
				Message:       "bad",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteTable(&buf, result); err != nil {
		t.Fatalf("WriteTable failed: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Summary: total=2 passed=1 failed=1 info=1 warning=1 error=0",
		"Failing reason codes:",
		"sec.rbac.permissions.missing: 1",
		"Remediation IDs:",
		"RUNBOOK-SEC-RBAC-001",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q\nOutput:\n%s", want, out)
		}
	}
}
