package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/register"
	"github.com/ellanetworks/core-tester/tests"
	"github.com/ellanetworks/core/client"
	"github.com/spf13/cobra"
)

var (
	configFile string
	outputFile string
)

var rootCmd = &cobra.Command{
	Use:   "ella-core-tester [command]",
	Short: "A tool for testing Ella Core",
	Long:  `Ella Core Tester is a tool for testing Ella Core. It can validate functionality, connectivity, and performance.`,
	Args:  cobra.ArbitraryArgs,
}

var runCmd = &cobra.Command{
	Use:   "test",
	Short: "Run the complete test suite",
	Long:  "Run all registered tests against the Ella Core instance specified in the config file.",
	Args:  cobra.NoArgs,
	Run:   Test,
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a subscriber in Ella Core and create a GTP tunnel",
	Long:  "Register a subscriber in Ella Core and create a GTP tunnel.",
	Args:  cobra.NoArgs,
	Run:   Register,
}

func main() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(registerCmd)

	runCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to config file (required)")
	runCmd.Flags().StringVarP(&outputFile, "write", "w", "", "Write test results (JSON) to file")
	runCmd.MarkFlagRequired("config")

	registerCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to config file (required)")
	registerCmd.MarkFlagRequired("config")

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func Test(cmd *cobra.Command, args []string) {
	cfg, err := config.Validate(configFile)
	if err != nil {
		log.Fatalf("Couldn't validate config: %v\n", err)
	}

	err = tests.RegisterAll()
	if err != nil {
		log.Fatalf("Could not register tests: %v\n", err)
	}

	clientConfig := &client.Config{
		BaseURL:  cfg.EllaCore.API.Address,
		APIToken: cfg.EllaCore.API.Token,
	}

	ellaClient, err := client.New(clientConfig)
	if err != nil {
		log.Fatalf("failed to create ella client: %v", err)
	}

	testEnv := engine.Env{
		CoreConfig: engine.CoreConfig{
			N2Address: cfg.EllaCore.N2Address,
			MCC:       cfg.EllaCore.MCC,
			MNC:       cfg.EllaCore.MNC,
			SST:       cfg.EllaCore.SST,
			SD:        cfg.EllaCore.SD,
			TAC:       cfg.EllaCore.TAC,
			DNN:       cfg.EllaCore.DNN,
		},
		GnbN2Address:   cfg.Gnb.N2Address,
		GnbN3Address:   cfg.Gnb.N3Address,
		EllaCoreClient: ellaClient,
	}

	allPassed, testResults := engine.Run(context.Background(), testEnv)

	err = writeResultsToFile(outputFile, testResults)
	if err != nil {
		log.Fatalf("Could not write test results to file: %v\n", err)
	}

	if !allPassed {
		log.Fatalf("Some tests failed\n")
	}
}

func Register(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	cfg, err := config.Validate(configFile)
	if err != nil {
		log.Fatalf("Couldn't validate config: %v\n", err)
	}

	err = register.Register(ctx, cfg)
	if err != nil {
		log.Fatalf("Could not register: %v\n", err)
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
