package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
)

const (
	coreN2Address = "192.168.40.6:38412"
	gnbN2Address  = "192.168.40.6:38414"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	configFilePtr := flag.String("config", "", "The config file to be provided for Ella Core Tester")
	flag.Parse()

	if *configFilePtr == "" {
		log.Fatal("No config file provided. Use `-config` to provide a config file")
	}

	cfg, err := config.Validate(*configFilePtr)
	if err != nil {
		log.Fatalf("couldn't validate config: %v", err)
	}

	err = logger.ConfigureLogging(cfg.LogLevel)
	if err != nil {
		logger.EllaCoreTesterLog.Fatalf("Error configuring logging: %v", err)
	}

	logger.EllaCoreTesterLog.Info("Starting Ella Core Tester")

	err = gnb.Start(coreN2Address, gnbN2Address)
	if err != nil {
		logger.EllaCoreTesterLog.Fatalf("Error starting gNB: %v", err)
	}

	<-ctx.Done()
	logger.EllaCoreTesterLog.Info("Shutdown signal received, exiting.")
}
