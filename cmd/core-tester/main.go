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
	pduSessionType    string
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
	Long:  "Register a subscriber in Ella Core and create a GTP tunnel. The subscriber needs to already be created in Ella Core. This procedure will not try to create and delete resources in Ella Core.",
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
	registerCmd.Flags().StringVar(&pduSessionType, "pdu-session-type", "ipv4", "PDU session type: ipv4, ipv6, or ipv4v6")

	for _, name := range []string{
		"imsi",
		"key",
		"opc",
		"sqn",
		"profile-name",
		"mcc",
		"mnc",
		"sst",
		"tac",
		"dnn",
		"gnb-n2-address",
		"gnb-n3-address",
		"ella-core-n2-address",
		"pdu-session-type",
	} {
		if err := registerCmd.MarkFlagRequired(name); err != nil {
			panic(fmt.Sprintf("failed to mark flag %q required: %v", name, err))
		}
	}

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func Register(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	registerConfig := register.Config{
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
		PDUSessionType:    pduSessionType,
	}

	err := register.Run(ctx, registerConfig)
	if err != nil {
		logger.Logger.Fatal("Could not register", zap.Error(err))
	}
}
