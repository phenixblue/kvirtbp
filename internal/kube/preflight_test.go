package kube

import (
	"context"
	"testing"
)

func TestBuildPreflightFindingsNilClient(t *testing.T) {
	findings := BuildPreflightFindings(context.Background(), nil)
	if len(findings) == 0 {
		t.Fatal("expected degraded-mode finding when clients are nil")
	}
	if findings[0].CheckID != "cluster-connectivity" {
		t.Fatalf("expected cluster-connectivity check id, got %s", findings[0].CheckID)
	}
}
