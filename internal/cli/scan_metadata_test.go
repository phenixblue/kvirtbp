package cli

import "testing"

func TestBuildRunMetadata(t *testing.T) {
	meta := buildRunMetadata(runMetadataInput{
		Engine:                    "rego",
		NamespaceInclude:          []string{"tenant-*"},
		NamespaceExclude:          []string{"tenant-b"},
		ClusterContextHash:        "abc123",
		ClusterContextHashVersion: "v1",
		DurationMillis:            42,
		PolicyFile:                "./policy.rego",
		PolicyBundle:              "",
		KubeContext:               "dev",
		KubeconfigProvided:        true,
	})

	if meta == nil {
		t.Fatal("expected metadata")
	}
	if meta.Engine != "rego" {
		t.Fatalf("expected engine rego, got %s", meta.Engine)
	}
	if meta.EvaluationMode != "hybrid" {
		t.Fatalf("expected evaluation mode hybrid, got %s", meta.EvaluationMode)
	}
	if meta.DurationMillis != 42 {
		t.Fatalf("expected duration 42, got %d", meta.DurationMillis)
	}
	if meta.ClusterContextHash != "abc123" {
		t.Fatalf("expected cluster context hash abc123, got %s", meta.ClusterContextHash)
	}
	if meta.ClusterContextHashVersion != "v1" {
		t.Fatalf("expected cluster context hash version v1, got %s", meta.ClusterContextHashVersion)
	}
	if len(meta.NamespaceInclude) != 1 || meta.NamespaceInclude[0] != "tenant-*" {
		t.Fatalf("unexpected include namespaces: %+v", meta.NamespaceInclude)
	}
	if len(meta.NamespaceExclude) != 1 || meta.NamespaceExclude[0] != "tenant-b" {
		t.Fatalf("unexpected exclude namespaces: %+v", meta.NamespaceExclude)
	}
	if !meta.KubeconfigProvided {
		t.Fatal("expected kubeconfigProvided=true")
	}
}

func TestClusterContextHashDeterministic(t *testing.T) {
	a := clusterContextHash("dev", true)
	b := clusterContextHash("dev", true)
	if a != b {
		t.Fatalf("expected deterministic hash, got %s and %s", a, b)
	}
	if len(a) != 12 {
		t.Fatalf("expected 12-char hash, got %q (len=%d)", a, len(a))
	}

	c := clusterContextHash("dev", false)
	if c == a {
		t.Fatalf("expected different hash for different kubeconfigProvided value, got %s", c)
	}
}
