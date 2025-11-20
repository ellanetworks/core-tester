package gnb

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/core"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type NGSetupFailure_UnknownPLMN struct{}

func (NGSetupFailure_UnknownPLMN) Meta() engine.Meta {
	return engine.Meta{
		ID:      "gnb/ngap/setup_failure/unknown_plmn",
		Summary: "NGSetup failure test validating the NGSetupFailure message contents when unknown PLMN is provided part of the NGSetupRequest",
		Timeout: 500 * time.Millisecond,
	}
}

func (t NGSetupFailure_UnknownPLMN) Run(ctx context.Context, env engine.Env) error {
	ellaCoreEnv := core.NewEllaCoreEnv(env.EllaCoreClient, core.EllaCoreConfig{
		Operator: core.OperatorConfig{
			ID: core.OperatorID{
				MCC: env.Config.EllaCore.MCC,
				MNC: env.Config.EllaCore.MNC,
			},
			Slice: core.OperatorSlice{
				SST: env.Config.EllaCore.SST,
				SD:  env.Config.EllaCore.SD,
			},
			Tracking: core.OperatorTracking{
				SupportedTACs: []string{env.Config.EllaCore.TAC},
			},
		},
	})

	err := ellaCoreEnv.Create(ctx)
	if err != nil {
		return fmt.Errorf("could not create EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Created EllaCore environment")

	gNodeB, err := gnb.Start(
		fmt.Sprintf("%06x", 1),
		"002", // Unknown MCC to trigger NGSetupFailure
		env.Config.EllaCore.MNC,
		env.Config.EllaCore.SST,
		env.Config.EllaCore.SD,
		env.Config.EllaCore.DNN,
		env.Config.EllaCore.TAC,
		"Ella-Core-Tester",
		env.Config.EllaCore.N2Address,
		env.Config.Gnb.N2Address,
		"0.0.0.0",
	)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	nextFrame, err := gNodeB.WaitForMessage(ngapType.NGAPPDUPresentUnsuccessfulOutcome, ngapType.UnsuccessfulOutcomePresentNGSetupFailure, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(nextFrame.Info, 60, 0)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(nextFrame.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.UnsuccessfulOutcome == nil {
		return fmt.Errorf("NGAP PDU is not a UnsuccessfulOutcome")
	}

	if pdu.UnsuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodeNGSetup {
		return fmt.Errorf("NGAP ProcedureCode is not NGSetup (%d)", ngapType.ProcedureCodeNGSetup)
	}

	nGSetupFailure := pdu.UnsuccessfulOutcome.Value.NGSetupFailure
	if nGSetupFailure == nil {
		return fmt.Errorf("NGSetupFailure is nil")
	}

	err = validateNGSetupFailure(nGSetupFailure, ngapType.CausePresentMisc, ngapType.CauseMiscPresentUnknownPLMN)
	if err != nil {
		return fmt.Errorf("NGSetupResponse validation failed: %v", err)
	}

	// Cleanup
	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}

func validateNGSetupFailure(nGSetupFailure *ngapType.NGSetupFailure, expectedCauseType int, expectedCauseValue aper.Enumerated) error {
	var cause *ngapType.Cause

	for _, ie := range nGSetupFailure.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			cause = ie.Value.Cause

		default:
			return fmt.Errorf("NGSetupResponse IE ID (%d) not supported", ie.Id.Value)
		}
	}

	return validateCause(cause, expectedCauseType, expectedCauseValue)
}

func validateCause(cause *ngapType.Cause, expectedCauseType int, expectedCauseValue aper.Enumerated) error {
	if cause == nil {
		return fmt.Errorf("cause is missing in NGSetupFailure")
	}

	if cause.Present != expectedCauseType {
		return fmt.Errorf("unexpected Cause Present: %d", cause.Present)
	}

	switch cause.Present {
	case ngapType.CausePresentRadioNetwork:
		if cause.RadioNetwork.Value != expectedCauseValue {
			return fmt.Errorf("unexpected RadioNetwork Cause Value: %d", cause.RadioNetwork.Value)
		}
	case ngapType.CausePresentTransport:
		if cause.Transport.Value != expectedCauseValue {
			return fmt.Errorf("unexpected Transport Cause Value: %d", cause.Transport.Value)
		}
	case ngapType.CausePresentNas:
		if cause.Nas.Value != expectedCauseValue {
			return fmt.Errorf("unexpected Nas Cause Value: %d", cause.Nas.Value)
		}
	case ngapType.CausePresentProtocol:
		if cause.Protocol.Value != expectedCauseValue {
			return fmt.Errorf("unexpected Protocol Cause Value: %d", cause.Protocol.Value)
		}
	case ngapType.CausePresentMisc:
		if cause.Misc.Value != expectedCauseValue {
			return fmt.Errorf("unexpected Misc Cause Value: %d", cause.Misc.Value)
		}
	default:
		return fmt.Errorf("unexpected Cause Present: %d", cause.Present)
	}

	return nil
}
