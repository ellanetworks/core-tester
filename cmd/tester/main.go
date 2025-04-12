package main

import (
	"flag"
	"log"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/gnb"
)

func main() {
	configFilePath := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()
	if *configFilePath == "" {
		log.Fatalf("No config file provided. Use `-config` to provide a config file")
	}
	cfg, err := config.Load(*configFilePath)
	if err != nil {
		log.Fatalf("Failed to load config file: %v", err)
	}
	_, err = gnb.InitGnb(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize gNB: %v", err)
	}
	log.Println("gNB initialized successfully")
	select {}
}
