package app

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
	"github.com/zcxads666/AegisLure/internal/store"
)

func TestPostgresStartsWithCompleteBuiltinRulePack(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("AEGISLURE_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("AEGISLURE_TEST_POSTGRES_URL is not configured")
	}
	dataDir := t.TempDir()
	configPath := dataDir + "/config.json"
	if _, err := config.Init(configPath, dataDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HP_DB_DRIVER", "postgres")
	t.Setenv("HP_DATABASE_URL", databaseURL)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWithOptions(dataDir, cfg.InstanceKey, store.Options{Driver: store.DriverPostgres, DatabaseURL: cfg.DatabaseURL, ConnectRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service := New(cfg, st)
	_ = service
	pack, ok := st.GetPack(model.PackKindDetector, "builtin-rules-v3")
	if !ok {
		t.Fatal("PostgreSQL did not receive builtin-rules-v3")
	}
	var document packs.DetectorRulePack
	if err := json.Unmarshal(pack.Definition, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Rules) < 48 {
		t.Fatalf("PostgreSQL builtin rule count = %d, want at least 48", len(document.Rules))
	}
	if policies := st.ListOAuthChannelPolicies(); len(policies) != len(model.OAuthChannelProviders()) {
		t.Fatalf("PostgreSQL default OAuth identity policies = %d", len(policies))
	}
}
