package gnb

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type NGReset struct{}

func (NGReset) Meta() engine.Meta {
	return engine.Meta{
		ID:      "gnb/ngap/reset",
		Summary: "NGReset test validating the NGResetAcknowledge message is received after sending NGReset",
		Timeout: 500 * time.Millisecond,
	}
}

func (t NGReset) Run(ctx context.Context, env engine.Env) error {
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

	err = validate.NGSetupResponse(nGSetupResponse, &validate.NGSetupResponseValidationOpts{
		MCC: env.Config.EllaCore.MCC,
		MNC: env.Config.EllaCore.MNC,
		SST: env.Config.EllaCore.SST,
		SD:  env.Config.EllaCore.SD,
	})
	if err != nil {
		return fmt.Errorf("NGSetupResponse validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Received NGSetupResponse",
		zap.String("MCC", env.Config.EllaCore.MCC),
		zap.String("MNC", env.Config.EllaCore.MNC),
		zap.Int32("SST", env.Config.EllaCore.SST),
		zap.String("SD", env.Config.EllaCore.SD),
	)

	err = gNodeB.SendNGReset(&gnb.NGResetOpts{
		Cause: &ngapType.Cause{
			Present: ngapType.CausePresentMisc,
			Misc: &ngapType.CauseMisc{
				Value: ngapType.CauseMiscPresentUnspecified,
			},
		},
		ResetAll: true,
	})
	if err != nil {
		return fmt.Errorf("could not send NGReset: %v", err)
	}

	logger.Logger.Debug(
		"Sent NGReset",
	)

	fr, err = gNodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 0)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err = ngap.Decoder(fr.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.SuccessfulOutcome == nil {
		return fmt.Errorf("NGAP PDU is not a SuccessfulOutcome")
	}

	if pdu.SuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodeNGReset {
		return fmt.Errorf("NGAP ProcedureCode is not NGReset (%d)", ngapType.ProcedureCodeNGReset)
	}

	nGResetAcknowledge := pdu.SuccessfulOutcome.Value.NGResetAcknowledge
	if nGResetAcknowledge == nil {
		return fmt.Errorf("NG Reset Acknowledge is nil")
	}

	logger.Logger.Debug("Received NGResetAcknowledge")

	return nil
}
