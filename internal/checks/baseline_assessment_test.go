package checks

import "testing"

func TestApplyBaselineAssessmentsAllPass(t *testing.T) {
	findings := []Finding{
		{CheckID: "prod-baseline-kubevirt-readiness", Pass: true, Severity: SeverityInfo},
		{CheckID: "sec-baseline-rbac-safety", Pass: true, Severity: SeverityInfo},
		{CheckID: "avail-baseline-workload-resilience", Pass: true, Severity: SeverityInfo},
		{CheckID: "kubevirt-api-availability", Pass: true},
		{CheckID: "prod-kubevirt-operator-health", Pass: true},
		{CheckID: "prod-node-inventory", Pass: true},
		{CheckID: "prod-namespace-guardrails-coverage", Pass: true},
		{CheckID: "sec-networking-api-availability", Pass: true},
		{CheckID: "sec-namespace-psa-enforce", Pass: true},
		{CheckID: "sec-networkpolicy-coverage", Pass: true},
		{CheckID: "avail-control-plane-ha", Pass: true},
		{CheckID: "avail-namespace-pdb-coverage", Pass: true},
		{CheckID: "perm-list-nodes", Pass: true},
		{CheckID: "perm-list-namespaces", Pass: true},
		{CheckID: "perm-list-vms", Pass: true},
	}

	got := ApplyBaselineAssessments(findings)
	for _, id := range []string{"prod-baseline-kubevirt-readiness", "sec-baseline-rbac-safety", "avail-baseline-workload-resilience"} {
		f := mustFind(t, got, id)
		if !f.Pass {
			t.Fatalf("expected %s to pass", id)
		}
		if f.ReasonCode == "" {
			t.Fatalf("expected %s reason code", id)
		}
		if f.Remediation == "" {
			t.Fatalf("expected %s remediation", id)
		}
		if len(f.Evidence) == 0 {
			t.Fatalf("expected %s evidence", id)
		}
		if f.Impact == "" || f.Confidence == "" {
			t.Fatalf("expected %s impact/confidence", id)
		}
		if f.RemediationID == "" {
			t.Fatalf("expected %s remediation ID", id)
		}
	}
}

func TestApplyBaselineAssessmentsFailures(t *testing.T) {
	findings := []Finding{
		{CheckID: "prod-baseline-kubevirt-readiness", Pass: true, Severity: SeverityInfo},
		{CheckID: "sec-baseline-rbac-safety", Pass: true, Severity: SeverityInfo},
		{CheckID: "avail-baseline-workload-resilience", Pass: true, Severity: SeverityInfo},
		{CheckID: "kubevirt-api-availability", Pass: false},
		{CheckID: "perm-list-vms", Pass: false},
		{CheckID: "perm-list-nodes", Pass: false},
		{CheckID: "prod-namespace-guardrails-coverage", Pass: false},
		{CheckID: "prod-kubevirt-operator-health", Pass: false},
		{CheckID: "sec-namespace-psa-enforce", Pass: false},
		{CheckID: "sec-networkpolicy-coverage", Pass: false},
		{CheckID: "avail-namespace-pdb-coverage", Pass: false},
	}

	got := ApplyBaselineAssessments(findings)
	prod := mustFind(t, got, "prod-baseline-kubevirt-readiness")
	if prod.Pass {
		t.Fatal("expected production baseline to fail")
	}
	if prod.ReasonCode == "" || prod.Remediation == "" {
		t.Fatal("expected production baseline reason and remediation")
	}
	if prod.ReasonCode != "prod.kubevirt.api.missing" {
		t.Fatalf("expected production reason prod.kubevirt.api.missing, got %s", prod.ReasonCode)
	}
	if prod.RemediationID == "" {
		t.Fatal("expected production remediation ID")
	}

	sec := mustFind(t, got, "sec-baseline-rbac-safety")
	if sec.Pass {
		t.Fatal("expected security baseline to fail")
	}
	if sec.ReasonCode != "sec.psa.enforce.insufficient" {
		t.Fatalf("expected security reason sec.psa.enforce.insufficient, got %s", sec.ReasonCode)
	}
	if sec.Evidence["namespace-psa-enforce"] != "fail" {
		t.Fatal("expected security evidence to include failed psa coverage")
	}

	avail := mustFind(t, got, "avail-baseline-workload-resilience")
	if avail.Pass {
		t.Fatal("expected availability baseline to fail")
	}
	if avail.ReasonCode == "" {
		t.Fatal("expected availability reason code")
	}
	if avail.Impact == "" || avail.Confidence == "" {
		t.Fatal("expected availability impact/confidence")
	}
}

func TestApplyBaselineAssessmentsNewSignalReasons(t *testing.T) {
	prod := mustFind(t, ApplyBaselineAssessments([]Finding{
		{CheckID: "prod-baseline-kubevirt-readiness", Pass: true, Severity: SeverityInfo},
		{CheckID: "kubevirt-api-availability", Pass: true},
		{CheckID: "prod-kubevirt-operator-health", Pass: false},
	}), "prod-baseline-kubevirt-readiness")
	if prod.ReasonCode != "prod.kubevirt.operator.health.failed" {
		t.Fatalf("expected production operator-health reason, got %s", prod.ReasonCode)
	}

	sec := mustFind(t, ApplyBaselineAssessments([]Finding{
		{CheckID: "sec-baseline-rbac-safety", Pass: true, Severity: SeverityInfo},
		{CheckID: "sec-namespace-psa-enforce", Pass: false},
		{CheckID: "sec-networkpolicy-coverage", Pass: true},
		{CheckID: "perm-list-nodes", Pass: true},
		{CheckID: "perm-list-namespaces", Pass: true},
		{CheckID: "perm-list-vms", Pass: true},
		{CheckID: "sec-networking-api-availability", Pass: true},
	}), "sec-baseline-rbac-safety")
	if sec.ReasonCode != "sec.psa.enforce.insufficient" {
		t.Fatalf("expected security psa reason, got %s", sec.ReasonCode)
	}

	avail := mustFind(t, ApplyBaselineAssessments([]Finding{
		{CheckID: "avail-baseline-workload-resilience", Pass: true, Severity: SeverityInfo},
		{CheckID: "cluster-connectivity", Pass: true},
		{CheckID: "cluster-discovery", Pass: true},
		{CheckID: "perm-list-nodes", Pass: true},
		{CheckID: "avail-control-plane-ha", Pass: true},
		{CheckID: "avail-namespace-pdb-coverage", Pass: false},
	}), "avail-baseline-workload-resilience")
	if avail.ReasonCode != "avail.pdb.coverage.insufficient" {
		t.Fatalf("expected availability pdb reason, got %s", avail.ReasonCode)
	}
}

func mustFind(t *testing.T, findings []Finding, id string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.CheckID == id {
			return f
		}
	}
	t.Fatalf("missing finding %s", id)
	return Finding{}
}
