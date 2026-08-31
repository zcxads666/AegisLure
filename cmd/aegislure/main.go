package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zcxads666/AegisLure/internal/app"
	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/oauth"
	"github.com/zcxads666/AegisLure/internal/store"
)

func main() {
	configPath := flag.String("config", "./config.json", "path to root-owned runtime config")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v (run hpctl init first)", err)
	}
	_ = os.Setenv("HP_CONFIG", *configPath)
	st, err := store.OpenWithOptions(cfg.DataDir, cfg.InstanceKey, store.Options{
		MaxEvents:      cfg.EventMaxEntries,
		EventRetention: time.Duration(cfg.EventRetentionDays) * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	broker, err := loadOptionalOAuthBroker(*configPath, cfg.InstanceKey)
	if err != nil {
		_ = st.Close()
		log.Fatalf("load OAuth broker: %v", err)
	}
	service := app.New(cfg, st)
	if broker != nil {
		service.SetOAuthBroker(broker)
	}
	if err := service.Start(); err != nil {
		log.Fatalf("start service: %v", err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown: %v\n", err)
	}
}

func loadOptionalOAuthBroker(configPath, instanceKey string) (*oauth.Broker, error) {
	path := strings.TrimSpace(os.Getenv("HP_OAUTH_CONFIG"))
	explicit := path != ""
	if path == "" {
		path = filepath.Join(filepath.Dir(configPath), "secrets", "oauth.json")
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return nil, nil
		}
		return nil, err
	}
	return oauth.LoadFile(path, instanceKey)
}
