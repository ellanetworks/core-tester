package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/register"
	"github.com/ellanetworks/core-tester/internal/release"
	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests"
	"github.com/ellanetworks/core/client"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	outputFile         string
	imsi               string
	key                string
	opc                string
	sqn                string
	policyName         string
	mcc                string
	mnc                string
	sst                int32
	sd                 string
	tac                string
	dnn                string
	amfUENGAPID        int64
	gnbN2Address       string
	gnbN3Address       string
	ellaCoreN2Address  string
	ellaCoreAPIAddress string
	ellaCoreAPIToken   string
	verbose            bool
)

var rootCmd = &cobra.Command{
	Use:   "ella-core-tester [command]",
	Short: "A tool for testing Ella Core",
	Long:  `Ella Core Tester validates functionality, connectivity, and performance.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			logger.Init(zap.DebugLevel)
		} else {
			logger.Init(zap.InfoLevel)
		}
	},
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run the complete test suite",
	Long:  "Run all registered tests against the Ella Core instance. This procedure is intrusive and will create and delete resources in Ella Core.",
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

var releaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Release the UE context",
	Long:  "Release the UE context in Ella Core. The subscriber needs to already be created in Ella Core. This procedure will not try to create and delete resources in Ella Core.",
	Args:  cobra.NoArgs,
	Run:   Release,
}

func main() {
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(releaseCmd)
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose (debug) logging")

	testCmd.Flags().StringVar(&ellaCoreAPIAddress, "ella-core-api-address", "", "Ella Core API address")
	testCmd.Flags().StringVar(&ellaCoreAPIToken, "ella-core-api-token", "", "Ella Core API token")
	testCmd.Flags().StringVar(&ellaCoreN2Address, "ella-core-n2-address", "", "Ella Core N2 address")
	testCmd.Flags().StringVar(&gnbN2Address, "gnb-n2-address", "", "gNB N2 address")
	testCmd.Flags().StringVar(&gnbN3Address, "gnb-n3-address", "", "gNB N3 address")
	testCmd.Flags().StringVarP(&outputFile, "write", "w", "", "Write test results (JSON) to file")
	_ = testCmd.MarkFlagRequired("ella-core-api-address")
	_ = testCmd.MarkFlagRequired("ella-core-api-token")
	_ = testCmd.MarkFlagRequired("ella-core-n2-address")
	_ = testCmd.MarkFlagRequired("gnb-n2-address")
	_ = testCmd.MarkFlagRequired("gnb-n3-address")

	registerCmd.Flags().StringVar(&imsi, "imsi", "", "IMSI of the subscriber")
	registerCmd.Flags().StringVar(&key, "key", "", "Key of the subscriber")
	registerCmd.Flags().StringVar(&opc, "opc", "", "OPC of the subscriber")
	registerCmd.Flags().StringVar(&sqn, "sqn", "", "SQN of the subscriber")
	registerCmd.Flags().StringVar(&policyName, "policy-name", "", "Policy name of the subscriber")
	registerCmd.Flags().StringVar(&mcc, "mcc", "", "MCC of the subscriber")
	registerCmd.Flags().StringVar(&mnc, "mnc", "", "MNC of the subscriber")
	registerCmd.Flags().Int32Var(&sst, "sst", 0, "SST of the subscriber")
	registerCmd.Flags().StringVar(&sd, "sd", "", "SD of the subscriber")
	registerCmd.Flags().StringVar(&tac, "tac", "", "TAC of the subscriber")
	registerCmd.Flags().StringVar(&dnn, "dnn", "dnn", "DNN of the subscriber")
	registerCmd.Flags().StringVar(&gnbN2Address, "gnb-n2-address", "", "gNB N2 address")
	registerCmd.Flags().StringVar(&gnbN3Address, "gnb-n3-address", "", "gNB N3 address")
	registerCmd.Flags().StringVar(&ellaCoreN2Address, "ella-core-n2-address", "", "Ella Core N2 address")
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

	releaseCmd.Flags().Int64Var(&amfUENGAPID, "amfuengapid", 0, "AMF UE NGAP ID")
	_ = releaseCmd.MarkFlagRequired("amfuengapid")

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func Test(cmd *cobra.Command, args []string) {
	testConfig := engine.Config{
		Subscriber: engine.SubscriberConfig{
			IMSI:           "001017271246546",
			Key:            "640f441067cd56f1474cbcacd7a0588f",
			OPC:            "cb698a2341629c3241ae01de9d89de4f",
			SequenceNumber: "000000000022",
			PolicyName:     "bbb",
		},
		EllaCore: engine.EllaCoreConfig{
			N2Address: ellaCoreN2Address,
			MCC:       "001",
			MNC:       "01",
			SST:       1,
			SD:        "102030",
			TAC:       "000001",
			DNN:       "internet",
		},
		Gnb: engine.GnbConfig{
			N2Address: gnbN2Address,
			N3Address: gnbN3Address,
		},
	}

	err := tests.RegisterAll()
	if err != nil {
		logger.Logger.Fatal("Could not register tests", zap.Error(err))
	}

	clientConfig := &client.Config{
		BaseURL:  ellaCoreAPIAddress,
		APIToken: ellaCoreAPIToken,
	}

	ellaClient, err := client.New(clientConfig)
	if err != nil {
		logger.Logger.Fatal("failed to create ella client", zap.Error(err))
	}

	testEnv := engine.Env{
		Config:         testConfig,
		EllaCoreClient: ellaClient,
	}

	allPassed, testResults := engine.Run(context.Background(), testEnv)

	err = writeResultsToFile(outputFile, testResults)
	if err != nil {
		logger.Logger.Fatal("Could not write test results to file", zap.Error(err))
	}

	if !allPassed {
		logger.Logger.Fatal("Some tests failed")
	}
}

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
		logger.Logger.Fatal("Could not register", zap.Error(err))
	}
}

func Release(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	releaseConfig := release.ReleaseConfig{
		AMFUENGAPID:       amfUENGAPID,
		GnbN2Address:      gnbN2Address,
		EllaCoreN2Address: ellaCoreN2Address,
	}

	err := release.Release(ctx, releaseConfig)
	if err != nil {
		logger.Logger.Fatal("Could not release", zap.Error(err))
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
