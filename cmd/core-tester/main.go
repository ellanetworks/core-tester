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
	configFile        string
	outputFile        string
	imsi              string
	key               string
	opc               string
	sqn               string
	policyName        string
	mcc               string
	mnc               string
	sst               int32
	sd                string
	tac               string
	dnn               string
	gnbN2Address      string
	gnbN3Address      string
	ellaCoreN2Address string
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
	Long:  "Run all registered tests against the Ella Core instance specified in the config file. This procedure is intrusive and will create and delete resources in Ella Core.",
	Args:  cobra.NoArgs,
	Run:   Test,
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a subscriber in Ella Core and create a GTP tunnel",
	Long:  "Register a subscriber in Ella Core and create a GTP tunnel. The subscriber needs to already be created in Ella Core. This procedure will not try to create and delete resources in Ela Core.",
	Args:  cobra.NoArgs,
	Run:   Register,
}

func main() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(registerCmd)

	runCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to config file (required)")
	runCmd.Flags().StringVarP(&outputFile, "write", "w", "", "Write test results (JSON) to file")
	_ = runCmd.MarkFlagRequired("config")

	registerCmd.Flags().StringVar(&imsi, "imsi", "imsi", "IMSI of the subscriber")
	registerCmd.Flags().StringVar(&key, "key", "key", "Key of the subscriber")
	registerCmd.Flags().StringVar(&opc, "opc", "opc", "OPC of the subscriber")
	registerCmd.Flags().StringVar(&sqn, "sqn", "sqn", "SQN of the subscriber")
	registerCmd.Flags().StringVar(&policyName, "policy-name", "policy-name", "Policy name of the subscriber")
	registerCmd.Flags().StringVar(&mcc, "mcc", "mcc", "MCC of the subscriber")
	registerCmd.Flags().StringVar(&mnc, "mnc", "mnc", "MNC of the subscriber")
	registerCmd.Flags().Int32Var(&sst, "sst", 0, "SST of the subscriber")
	registerCmd.Flags().StringVar(&sd, "sd", "sd", "SD of the subscriber")
	registerCmd.Flags().StringVar(&tac, "tac", "tac", "TAC of the subscriber")
	registerCmd.Flags().StringVar(&dnn, "dnn", "dnn", "DNN of the subscriber")
	registerCmd.Flags().StringVar(&gnbN2Address, "gnb-n2-address", "gnb-n2-address", "gNB N2 address")
	registerCmd.Flags().StringVar(&gnbN3Address, "gnb-n3-address", "gnb-n3-address", "gNB N3 address")
	registerCmd.Flags().StringVar(&ellaCoreN2Address, "ella-core-n2-address", "ella-core-n2-address", "Ella Core N2 address")
	_ = registerCmd.MarkFlagRequired("imsi")
	_ = registerCmd.MarkFlagRequired("key")
	_ = registerCmd.MarkFlagRequired("opc")
	_ = registerCmd.MarkFlagRequired("sqn")
	_ = registerCmd.MarkFlagRequired("policy-name")
	_ = registerCmd.MarkFlagRequired("mcc")
	_ = registerCmd.MarkFlagRequired("mnc")
	_ = registerCmd.MarkFlagRequired("sst")
	_ = registerCmd.MarkFlagRequired("tac")
	_ = registerCmd.MarkFlagRequired("dnn")
	_ = registerCmd.MarkFlagRequired("gnb-n2-address")
	_ = registerCmd.MarkFlagRequired("gnb-n3-address")
	_ = registerCmd.MarkFlagRequired("ella-core-n2-address")

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
		Config:         cfg,
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

// type EllaCoreConfig struct {
// 	API       EllaCoreAPIConfig
// 	N2Address string
// 	MCC       string
// 	MNC       string
// 	SST       int32
// 	SD        string
// 	TAC       string
// 	DNN       string
// }

func Register(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	registerConfig := register.RegisterConfig{
		IMSI:              imsi,
		Key:               key,
		OPC:               opc,
		SequenceNumber:    sqn,
		PolicyName:        policyName,
		MCC:               mcc,
		MNC:               mnc,
		SST:               sst,
		SD:                sd,
		TAC:               tac,
		DNN:               dnn,
		GnbN2Address:      gnbN2Address,
		GnbN3Address:      gnbN3Address,
		EllaCoreN2Address: ellaCoreN2Address,
	}

	err := register.Register(ctx, registerConfig)
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
