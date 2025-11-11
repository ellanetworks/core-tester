package gnb

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/tests/utils"
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
	gNodeB, err := gnb.Start(env.Config.EllaCore.N2Address, env.Config.Gnb.N2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	opts := &gnb.NGSetupRequestOpts{
		Mcc: "002", // Unknown MCC to trigger NGSetupFailure
		Mnc: env.Config.EllaCore.MNC,
		Sst: env.Config.EllaCore.SST,
		Tac: env.Config.EllaCore.TAC,
	}

	err = gNodeB.SendNGSetupRequest(opts)
	if err != nil {
		return fmt.Errorf("could not send NGSetupRequest: %v", err)
	}

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
