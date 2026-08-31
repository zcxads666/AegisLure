package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppliesSecureRuntimeDefaultsAndEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"instance_id":"instance","instance_key":"key","admin_port":28443,"admin_path":"/entry/"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_REQUIRE_TLS", "true")
	t.Setenv("HP_ADMIN_HOSTS", "admin.example,127.0.0.1")
	t.Setenv("HP_EVENT_RETENTION_DAYS", "45")
	t.Setenv("HP_EVENT_MAX_ENTRIES", "12000")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RequireAdminTLS || cfg.EventRetentionDays != 45 || cfg.EventMaxEntries != 12000 {
		t.Fatalf("runtime defaults/overrides not applied: %#v", cfg)
	}
	if len(cfg.AdminHostAllowlist) != 2 || cfg.AdminHostAllowlist[0] != "admin.example" || cfg.AdminHostAllowlist[1] != "127.0.0.1" {
		t.Fatalf("host allowlist not applied: %#v", cfg.AdminHostAllowlist)
	}
}

func TestLoadRejectsInvalidRetentionEnvironmentWithoutDroppingDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"instance_id":"instance","instance_key":"key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_EVENT_RETENTION_DAYS", "0")
	t.Setenv("HP_EVENT_MAX_ENTRIES", "999")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EventRetentionDays != 30 || cfg.EventMaxEntries != 100000 {
		t.Fatalf("invalid retention environment changed defaults: %#v", cfg)
	}
}

func TestNormalizePortPoolsKeepsBaseAndRejectsOutOfRangeCandidates(t *testing.T) {
	cfg := &Config{ProfilePorts: map[string]int{"ollama": 11434}, PortPools: map[string][]int{"ollama": {0, 11435, 11435, 70000}}}
	NormalizePortPools(cfg)
	if !PortInPool(cfg, "ollama", 11434) || !PortInPool(cfg, "ollama", 11435) || PortInPool(cfg, "ollama", 11436) {
		t.Fatalf("unexpected normalized port pool: %#v", cfg.PortPools)
	}
	if len(cfg.PortPools["ollama"]) != 2 {
		t.Fatalf("unexpected normalized candidate count: %#v", cfg.PortPools["ollama"])
	}
}
