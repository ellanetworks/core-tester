package gnb

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type SCTPBasic struct{}

func (SCTPBasic) Meta() engine.Meta {
	return engine.Meta{
		ID:      "gnb/sctp",
		Summary: "SCTP connectivity test validating SCTP Stream Identifier and PPID for NGSetup procedure",
		Timeout: 500 * time.Millisecond,
	}
}

func (t SCTPBasic) Run(ctx context.Context, env engine.Env) error {
	gNodeB, err := gnb.Start(env.Config.EllaCore.N2Address, env.Config.Gnb.N2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	opts := &gnb.NGSetupRequestOpts{
		Mcc: env.Config.EllaCore.MCC,
		Mnc: env.Config.EllaCore.MNC,
		Sst: env.Config.EllaCore.SST,
		Tac: env.Config.EllaCore.TAC,
	}

	err = gNodeB.SendNGSetupRequest(opts)
	if err != nil {
		return fmt.Errorf("could not send NGSetupRequest: %v", err)
	}

	logger.Logger.Debug(
		"Sent NGSetupRequest",
		zap.String("MCC", opts.Mcc),
		zap.String("MNC", opts.Mnc),
		zap.Int32("SST", opts.Sst),
		zap.String("TAC", opts.Tac),
	)

	fr, err := gNodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 0)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Received SCTP frame",
		zap.Uint16("StreamIdentifier", fr.Info.Stream),
		zap.Uint32("PPID", fr.Info.PPID),
	)

	pdu, err := ngap.Decoder(fr.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.SuccessfulOutcome == nil {
		return fmt.Errorf("NGAP PDU is not a SuccessfulOutcome")
	}

	if pdu.SuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodeNGSetup {
		return fmt.Errorf("NGAP ProcedureCode is not NGSetup (%d)", ngapType.ProcedureCodeNGSetup)
	}

	nGSetupResponse := pdu.SuccessfulOutcome.Value.NGSetupResponse
	if nGSetupResponse == nil {
		return fmt.Errorf("NGSetupResponse is nil")
	}

	return nil
}
