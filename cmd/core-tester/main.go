package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/tests"
)

func main() {
	configPath := flag.String("config", "", "Path to config file (mandatory)")
	outputFilePtr := flag.String("write", "", "The output file to write test results to (in JSON format)")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("No config file provided. Use `-config` to provide a config file")
	}

	cfg, err := config.Validate(*configPath)
	if err != nil {
		log.Fatalf("Couldn't validate config: %v\n", err)
	}

	err = tests.RegisterAll()
	if err != nil {
		log.Fatalf("Could not register tests: %v\n", err)
	}

	testEnv := engine.Env{
		CoreN2Address: cfg.EllaCore.N2Address,
		GnbN2Address:  cfg.Gnb.N2Address,
	}

	allPassed, testResults := engine.Run(context.Background(), testEnv)

	err = writeResultsToFile(*outputFilePtr, testResults)
	if err != nil {
		log.Fatalf("Could not write test results to file: %v\n", err)
	}

	if !allPassed {
		os.Exit(1)
	}
}

func writeResultsToFile(filePath string, testResults []engine.TestResult) error {
	if filePath == "" {
		return nil
	}

	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("could not create output file: %v", err)
	}
	defer f.Close()

	b, err := json.Marshal(testResults)
	if err != nil {
		return fmt.Errorf("could not marshal test results to json: %v", err)
	}

	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("could not write test results to file: %v", err)
	}

	return nil
}
