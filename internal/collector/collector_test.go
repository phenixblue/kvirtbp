package collector_test

import (
	"testing"

	"github.com/phenixblue/kvirtbp/internal/collector"
)

// ---- MergeCollectorConfigs ----

func TestMergeCollectorConfigs_EmptySlices(t *testing.T) {
	got := collector.MergeCollectorConfigs(nil, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

func TestMergeCollectorConfigs_OnlyA(t *testing.T) {
	a := []collector.CollectorConfig{
		{Name: "sysctl", Image: "alpine"},
	}
	got := collector.MergeCollectorConfigs(a, nil)
	if len(got) != 1 || got[0].Name != "sysctl" {
		t.Fatalf("unexpected result: %v", got)
	}
}

func TestMergeCollectorConfigs_OnlyB(t *testing.T) {
	b := []collector.CollectorConfig{
		{Name: "sysctl", Image: "alpine"},
	}
	got := collector.MergeCollectorConfigs(nil, b)
	if len(got) != 1 || got[0].Name != "sysctl" {
		t.Fatalf("unexpected result: %v", got)
	}
}

func TestMergeCollectorConfigs_NoOverlap(t *testing.T) {
	a := []collector.CollectorConfig{{Name: "sysctl", Image: "alpine"}}
	b := []collector.CollectorConfig{{Name: "kernel", Image: "ubuntu"}}
	got := collector.MergeCollectorConfigs(a, b)
	if len(got) != 2 {
		t.Fatalf("expected 2 elements, got %d: %v", len(got), got)
	}
	if got[0].Name != "sysctl" || got[1].Name != "kernel" {
		t.Fatalf("unexpected order: %v", got)
	}
}

func TestMergeCollectorConfigs_BOverridesA(t *testing.T) {
	a := []collector.CollectorConfig{{Name: "sysctl", Image: "alpine:3.18"}}
	b := []collector.CollectorConfig{{Name: "sysctl", Image: "alpine:latest"}}
	got := collector.MergeCollectorConfigs(a, b)
	if len(got) != 1 {
		t.Fatalf("expected 1 element after dedup, got %d", len(got))
	}
	if got[0].Image != "alpine:latest" {
		t.Fatalf("expected b to win on collision, got image %q", got[0].Image)
	}
}

func TestMergeCollectorConfigs_PartialOverlap(t *testing.T) {
	a := []collector.CollectorConfig{
		{Name: "sysctl", Image: "alpine:old"},
		{Name: "disk", Image: "busybox"},
	}
	b := []collector.CollectorConfig{
		{Name: "sysctl", Image: "alpine:new"},
		{Name: "net", Image: "nettools"},
	}
	got := collector.MergeCollectorConfigs(a, b)
	if len(got) != 3 {
		t.Fatalf("expected 3 elements, got %d: %v", len(got), got)
	}
	// Order: sysctl (overridden by b), disk, net
	if got[0].Name != "sysctl" || got[0].Image != "alpine:new" {
		t.Errorf("got[0] wrong: %+v", got[0])
	}
	if got[1].Name != "disk" {
		t.Errorf("got[1] wrong: %+v", got[1])
	}
	if got[2].Name != "net" {
		t.Errorf("got[2] wrong: %+v", got[2])
	}
}

// ---- CollectorConfig.ResolvedOutputPath ----

func TestResolvedOutputPath_Default(t *testing.T) {
	cfg := collector.CollectorConfig{}
	got := cfg.ResolvedOutputPath()
	want := "/kvirtbp/output.json"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestResolvedOutputPath_Custom(t *testing.T) {
	cfg := collector.CollectorConfig{OutputPath: "/tmp/out.json"}
	got := cfg.ResolvedOutputPath()
	if got != "/tmp/out.json" {
		t.Fatalf("want /tmp/out.json, got %q", got)
	}
}

// ---- CollectorScope constants ----

func TestCollectorScopeConstants(t *testing.T) {
	if collector.ScopeOnce != "once" {
		t.Errorf("ScopeOnce = %q, want %q", collector.ScopeOnce, "once")
	}
	if collector.ScopePerNode != "per-node" {
		t.Errorf("ScopePerNode = %q, want %q", collector.ScopePerNode, "per-node")
	}
}

// ---- NewJobCollector ----

func TestNewJobCollector_ReturnsCollector(t *testing.T) {
	cfg := collector.CollectorConfig{
		Name:  "test-collector",
		Image: "alpine",
		Scope: collector.ScopeOnce,
	}
	c := collector.NewJobCollector(cfg)
	if c == nil {
		t.Fatal("NewJobCollector returned nil")
	}
	if c.Name() != "test-collector" {
		t.Fatalf("Name() = %q, want %q", c.Name(), "test-collector")
	}
}
