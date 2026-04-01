package runbook

import "testing"

func TestLookupKnownID(t *testing.T) {
	e, ok := Lookup("RUNBOOK-SEC-RBAC-001")
	if !ok {
		t.Fatal("expected known runbook to be found")
	}
	if e.ID != "RUNBOOK-SEC-RBAC-001" {
		t.Fatalf("unexpected runbook id %s", e.ID)
	}
	if len(e.Steps) == 0 {
		t.Fatal("expected runbook steps")
	}
}

func TestSortedIDsCount(t *testing.T) {
	ids := SortedIDs()
	if len(ids) != 5 {
		t.Fatalf("expected 5 runbook IDs, got %d", len(ids))
	}
}
