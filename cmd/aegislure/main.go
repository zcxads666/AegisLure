package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zcxads666/AegisLure/internal/app"
	"github.com/zcxads666/AegisLure/internal/config"
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
	st, err := store.Open(cfg.DataDir, cfg.InstanceKey)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	service := app.New(cfg, st)
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
