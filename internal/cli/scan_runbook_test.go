package cli

import (
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

func TestAnnotateRunbookHints(t *testing.T) {
	input := []checks.Finding{
		{
			CheckID:       "sec-baseline-rbac-safety",
			Pass:          false,
			Message:       "Security baseline failed",
			RemediationID: "RUNBOOK-SEC-RBAC-001",
			Remediation:   "Grant permissions",
			ReasonCode:    "sec.rbac.permissions.missing",
			Category:      "security",
			Severity:      checks.SeverityWarning,
		},
		{
			CheckID:  "perm-list-nodes",
			Pass:     true,
			Message:  "allowed",
			Category: "security",
			Severity: checks.SeverityInfo,
		},
	}

	got := annotateRunbookHints(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
	if got[0].Message == input[0].Message {
		t.Fatal("expected first finding message to include runbook hint")
	}
	if got[1].Message != input[1].Message {
		t.Fatal("expected passing finding message to remain unchanged")
	}
}
