package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if cfg.GeoIPProvider != GeoIPProviderMaxMind {
		t.Fatalf("GeoIP provider default = %q, want %q", cfg.GeoIPProvider, GeoIPProviderMaxMind)
	}
	cityPath, asnPath := cfg.GeoIPDatabasePaths()
	if cityPath != filepath.Join(filepath.Dir(path), "geoip", DefaultMaxMindCityDB) || asnPath != filepath.Join(filepath.Dir(path), "geoip", DefaultMaxMindASNDB) {
		t.Fatalf("unexpected default GeoIP database paths: %q %q", cityPath, asnPath)
	}
}

func TestLoadNormalizesGeoIPProviderAndRuntimeDatabasePaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"instance_id":"instance","instance_key":"key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_GEOIP_PROVIDER", "ipinfo-lite")
	t.Setenv("HP_MAXMIND_CITY_DB", "/srv/geoip/city.mmdb")
	t.Setenv("HP_MAXMIND_ASN_DB", "/srv/geoip/asn.mmdb")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GeoIPProvider != GeoIPProviderIPInfoLite {
		t.Fatalf("GeoIP provider normalization = %q", cfg.GeoIPProvider)
	}
	cityPath, asnPath := cfg.GeoIPDatabasePaths()
	if cityPath != "/srv/geoip/city.mmdb" || asnPath != "/srv/geoip/asn.mmdb" {
		t.Fatalf("runtime database paths = %q %q", cityPath, asnPath)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "city.mmdb") || strings.Contains(string(encoded), "asn.mmdb") {
		t.Fatalf("runtime database paths leaked into config JSON: %s", encoded)
	}
}

func TestLoadSupportsIPInfoMMDBPathsAndTokenEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"instance_id":"instance","instance_key":"key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_GEOIP_PROVIDER", "ipinfo-database")
	t.Setenv("HP_IPINFO_LOCATION_DB", "/srv/geoip/ipinfo_location.mmdb")
	t.Setenv("HP_IPINFO_ASN_DB", "/srv/geoip/ipinfo_asn.mmdb")
	t.Setenv("HP_IPINFO_LITE_TOKEN", "test-token")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GeoIPProvider != GeoIPProviderIPInfoMMDB || cfg.IPInfoLiteToken != "test-token" {
		t.Fatalf("IPinfo settings normalization = %#v", cfg)
	}
	locationPath, asnPath := cfg.IPInfoDatabasePaths()
	if locationPath != "/srv/geoip/ipinfo_location.mmdb" || asnPath != "/srv/geoip/ipinfo_asn.mmdb" {
		t.Fatalf("IPinfo database paths = %q %q", locationPath, asnPath)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "ipinfo_location.mmdb") || strings.Contains(string(encoded), "ipinfo_asn.mmdb") {
		t.Fatalf("IPinfo runtime database paths leaked into config JSON: %s", encoded)
	}
}

func TestLoadReadsIPInfoTokenFromProtectedRuntimeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"instance_id":"instance","instance_key":"key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "ipinfo_token")
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_GEOIP_PROVIDER", "ipinfo-api")
	t.Setenv("HP_IPINFO_LITE_TOKEN_FILE", tokenPath)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GeoIPProvider != GeoIPProviderIPInfoAPI || cfg.IPInfoLiteToken != "test-token" || cfg.IPInfoLiteTokenFile != tokenPath {
		t.Fatalf("IPinfo token file settings = %#v", cfg)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), tokenPath) {
		t.Fatalf("IPinfo token file path leaked into config JSON: %s", encoded)
	}
}

func TestNormalizeGeoIPRejectsUnknownProvider(t *testing.T) {
	if err := NormalizeGeoIP(&Config{GeoIPProvider: "unknown"}); err == nil {
		t.Fatal("unknown GeoIP provider was accepted")
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

func TestLoadNormalizesPostgresComponentsWithoutSerializingCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"instance_id":"instance","instance_key":"key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(t.TempDir(), "postgres-password")
	if err := os.WriteFile(passwordPath, []byte("p@ss word\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_DB_DRIVER", "postgres")
	t.Setenv("HP_DB_HOST", "db.internal")
	t.Setenv("HP_DB_PORT", "5433")
	t.Setenv("HP_DB_NAME", "honey")
	t.Setenv("HP_DB_USER", "sensor")
	t.Setenv("HP_DB_PASSWORD_FILE", passwordPath)
	t.Setenv("HP_DB_SSLMODE", "require")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseDriver != "postgres" || !strings.Contains(cfg.DatabaseURL, "db.internal:5433/honey") || !strings.Contains(cfg.DatabaseURL, "sslmode=require") {
		t.Fatalf("unexpected normalized postgres config: %#v", cfg)
	}
	if !strings.Contains(cfg.DatabaseURL, "p%40ss%20word") {
		t.Fatalf("database password was not URL encoded: %q", cfg.DatabaseURL)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "p@ss") || strings.Contains(string(encoded), "db.internal") {
		t.Fatalf("runtime postgres credentials leaked into config JSON: %s", encoded)
	}
}

func TestNormalizeDatabaseRejectsMissingPasswordAndInvalidSSLMode(t *testing.T) {
	missingPassword := &Config{DatabaseDriver: "postgres", DatabaseHost: "db"}
	if err := NormalizeDatabase(missingPassword); err == nil {
		t.Fatal("missing PostgreSQL password was accepted")
	}
	invalidSSL := &Config{DatabaseDriver: "postgres", DatabaseURL: "postgres://user:pass@db/name?sslmode=bogus"}
	if err := NormalizeDatabase(invalidSSL); err == nil {
		t.Fatal("invalid PostgreSQL sslmode was accepted")
	}
}

func TestLoadReadsPostgresURLFileWithPriority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"instance_id":"instance","instance_key":"key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	urlPath := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(urlPath, []byte("postgresql://file-user:file-pass@db.internal:5432/aegislure?sslmode=require\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_DB_DRIVER", "postgres")
	t.Setenv("HP_DATABASE_URL", "postgres://direct-user:direct-pass@wrong.example/aegislure")
	t.Setenv("HP_DATABASE_URL_FILE", urlPath)
	t.Setenv("HP_DB_PASSWORD_FILE", "")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "postgresql://file-user:file-pass@db.internal:5432/aegislure?sslmode=require" {
		t.Fatalf("database URL file did not take priority: %q", cfg.DatabaseURL)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "file-pass") || strings.Contains(string(encoded), "db.internal") {
		t.Fatalf("database URL file contents leaked into config JSON: %s", encoded)
	}
}
