package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/register"
	nasLogger "github.com/free5gc/nas/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	imsi              string
	key               string
	opc               string
	sqn               string
	profileName       string
	mcc               string
	mnc               string
	sst               int32
	sd                string
	tac               string
	dnn               string
	gnbN2Address      string
	gnbN3Address      string
	ellaCoreN2Address string
	verbose           bool
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

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a subscriber in Ella Core and create a GTP tunnel",
	Long:  "Register a subscriber in Ella Core and create a GTP tunnel. The subscriber needs to already be created in Ella Core. This procedure will not try to create and delete resources in Ela Core.",
	Args:  cobra.NoArgs,
	Run:   Register,
}

func main() {
	nasLogger.SetLogLevel(0)

	rootCmd.AddCommand(registerCmd)
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose (debug) logging")

	registerCmd.Flags().StringVar(&imsi, "imsi", "", "IMSI of the subscriber")
	registerCmd.Flags().StringVar(&key, "key", "", "Key of the subscriber")
	registerCmd.Flags().StringVar(&opc, "opc", "", "OPC of the subscriber")
	registerCmd.Flags().StringVar(&sqn, "sqn", "", "SQN of the subscriber")
	registerCmd.Flags().StringVar(&profileName, "profile-name", "", "Profile name of the subscriber")
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
	_ = registerCmd.MarkFlagRequired("profile-name")
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

func Register(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	registerConfig := register.RegisterConfig{
		IMSI:              imsi,
		Key:               key,
		OPC:               opc,
		SequenceNumber:    sqn,
		ProfileName:       profileName,
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
