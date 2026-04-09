package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Output != "table" {
		t.Fatalf("expected default output table, got %s", cfg.Output)
	}
}
