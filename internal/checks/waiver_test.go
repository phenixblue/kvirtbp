package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWaivers_valid(t *testing.T) {
	content := `
apiVersion: kvirtbp/v1alpha1
kind: WaiverList
waivers:
  - checkId: sec-baseline-rbac-safety
    justification: "Temporarily waived pending RBAC audit"
    owner: platform-team
    expires: "2099-12-31"
  - checkId: avail-baseline-workload-resilience
    justification: "Dev namespace excluded from resilience checks"
    owner: dev-team
`
	path := writeTempWaiver(t, content)
	waivers, err := LoadWaivers(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(waivers) != 2 {
		t.Fatalf("expected 2 waivers, got %d", len(waivers))
	}
	if waivers[0].CheckID != "sec-baseline-rbac-safety" {
		t.Errorf("unexpected checkId: %q", waivers[0].CheckID)
	}
	if waivers[0].Owner != "platform-team" {
		t.Errorf("unexpected owner: %q", waivers[0].Owner)
	}
	if waivers[0].Expires != "2099-12-31" {
		t.Errorf("unexpected expires: %q", waivers[0].Expires)
	}
}

func TestLoadWaivers_missingCheckID(t *testing.T) {
	content := `
waivers:
  - justification: "no check id"
    owner: someone
`
	path := writeTempWaiver(t, content)
	if _, err := LoadWaivers(path); err == nil {
		t.Fatal("expected error for missing checkId")
	}
}

func TestLoadWaivers_missingJustification(t *testing.T) {
	content := `
waivers:
  - checkId: prod-baseline-kubevirt-readiness
    owner: ops-team
`
	path := writeTempWaiver(t, content)
	if _, err := LoadWaivers(path); err == nil {
		t.Fatal("expected error for missing justification")
	}
}

func TestLoadWaivers_missingOwner(t *testing.T) {
	content := `
waivers:
  - checkId: prod-baseline-kubevirt-readiness
    justification: "some reason"
`
	path := writeTempWaiver(t, content)
	if _, err := LoadWaivers(path); err == nil {
		t.Fatal("expected error for missing owner")
	}
}

func TestLoadWaivers_invalidExpiresDate(t *testing.T) {
	content := `
waivers:
  - checkId: prod-baseline-kubevirt-readiness
    justification: "some reason"
    owner: ops-team
    expires: "not-a-date"
`
	path := writeTempWaiver(t, content)
	if _, err := LoadWaivers(path); err == nil {
		t.Fatal("expected error for invalid expires date")
	}
}

func TestLoadWaivers_fileNotFound(t *testing.T) {
	if _, err := LoadWaivers("/nonexistent/path/waivers.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestApplyWaivers_matchByCheckID(t *testing.T) {
	findings := []Finding{
		{CheckID: "sec-baseline-rbac-safety", Pass: false},
		{CheckID: "prod-baseline-kubevirt-readiness", Pass: false},
	}
	waivers := []Waiver{
		{CheckID: "sec-baseline-rbac-safety", Justification: "pending fix", Owner: "ops", Expires: "2099-12-31"},
	}

	result := ApplyWaivers(findings, waivers)

	if !result[0].Waived {
		t.Error("expected first finding to be waived")
	}
	if result[0].WaiverJustification != "pending fix" {
		t.Errorf("unexpected justification: %q", result[0].WaiverJustification)
	}
	if result[0].WaiverOwner != "ops" {
		t.Errorf("unexpected owner: %q", result[0].WaiverOwner)
	}
	if result[1].Waived {
		t.Error("expected second finding to not be waived")
	}
}

func TestApplyWaivers_expiredWaiverNotApplied(t *testing.T) {
	findings := []Finding{
		{CheckID: "sec-baseline-rbac-safety", Pass: false},
	}
	waivers := []Waiver{
		{CheckID: "sec-baseline-rbac-safety", Justification: "old waiver", Owner: "ops", Expires: "2000-01-01"},
	}

	result := ApplyWaivers(findings, waivers)
	if result[0].Waived {
		t.Error("expired waiver should not be applied")
	}
}

func TestApplyWaivers_noExpiryAppliedIndefinitely(t *testing.T) {
	findings := []Finding{
		{CheckID: "avail-baseline-workload-resilience", Pass: false},
	}
	waivers := []Waiver{
		{CheckID: "avail-baseline-workload-resilience", Justification: "dev env", Owner: "dev-team"},
	}

	result := ApplyWaivers(findings, waivers)
	if !result[0].Waived {
		t.Error("waiver with no expiry should be applied")
	}
	if result[0].WaiverExpires != "" {
		t.Errorf("expected empty WaiverExpires, got %q", result[0].WaiverExpires)
	}
}

func TestApplyWaivers_resourceRefScopedMatch(t *testing.T) {
	findings := []Finding{
		{CheckID: "sec-baseline-rbac-safety", ResourceRef: "ns/default", Pass: false},
		{CheckID: "sec-baseline-rbac-safety", ResourceRef: "ns/prod", Pass: false},
	}
	waivers := []Waiver{
		{CheckID: "sec-baseline-rbac-safety", ResourceRef: "ns/default", Justification: "default only", Owner: "ops"},
	}

	result := ApplyWaivers(findings, waivers)
	if !result[0].Waived {
		t.Error("ns/default finding should be waived")
	}
	if result[1].Waived {
		t.Error("ns/prod finding should not be waived")
	}
}

func TestApplyWaivers_emptyWaivers(t *testing.T) {
	findings := []Finding{
		{CheckID: "sec-baseline-rbac-safety", Pass: false},
	}
	result := ApplyWaivers(findings, nil)
	if result[0].Waived {
		t.Error("no waivers should produce no waived findings")
	}
}

func TestSummarize_includesWaived(t *testing.T) {
	findings := []Finding{
		{Pass: true, Severity: SeverityInfo},
		{Pass: false, Waived: true, Severity: SeverityWarning},
		{Pass: false, Severity: SeverityError},
	}
	s := Summarize(findings)
	if s.Total != 3 {
		t.Errorf("expected Total=3, got %d", s.Total)
	}
	if s.Passed != 1 {
		t.Errorf("expected Passed=1, got %d", s.Passed)
	}
	if s.Waived != 1 {
		t.Errorf("expected Waived=1, got %d", s.Waived)
	}
	if s.Failed != 1 {
		t.Errorf("expected Failed=1, got %d", s.Failed)
	}
}

func TestExitCode_waivedNotViolation(t *testing.T) {
	result := RunResult{
		Findings: []Finding{
			{CheckID: "sec-baseline-rbac-safety", Pass: false, Waived: true},
		},
	}
	if code := ExitCode(result); code != ExitCodeSuccess {
		t.Errorf("waived findings should not produce violation exit code, got %d", code)
	}
}

// writeTempWaiver writes content to a temp file and returns its path.
func writeTempWaiver(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "waivers.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp waiver file: %v", err)
	}
	return path
}
