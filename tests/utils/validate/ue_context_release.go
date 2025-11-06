package validate

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type UEContextReleaseOpts struct {
	Frame gnb.SCTPFrame
	Cause *ngapType.Cause
}

func UEContextRelease(opts *UEContextReleaseOpts) error {
	err := utils.ValidateSCTP(opts.Frame.Info, 60, 1)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(opts.Frame.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeUEContextRelease {
		return fmt.Errorf("NGAP ProcedureCode is not UEContextRelease (%d), received %d", ngapType.ProcedureCodeUEContextRelease, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	ueContextReleaseCommand := pdu.InitiatingMessage.Value.UEContextReleaseCommand
	if ueContextReleaseCommand == nil {
		return fmt.Errorf("UE Context Release Command is nil")
	}

	var (
		ueNGAPIDs *ngapType.UENGAPIDs
		cause     *ngapType.Cause
	)

	for _, ie := range ueContextReleaseCommand.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUENGAPIDs:
			ueNGAPIDs = ie.Value.UENGAPIDs
		case ngapType.ProtocolIEIDCause:
			cause = ie.Value.Cause
		default:
			return fmt.Errorf("UEContextReleaseCommand IE ID (%d) not supported", ie.Id.Value)
		}
	}

	if cause.Present != opts.Cause.Present {
		return fmt.Errorf("unexpected Cause Present: got %d, want %d", cause.Present, opts.Cause.Present)
	}

	switch cause.Present {
	case ngapType.CausePresentRadioNetwork:
		if cause.RadioNetwork != opts.Cause.RadioNetwork {
			return fmt.Errorf("unexpected RadioNetwork Cause value: got %d, want %d", cause.RadioNetwork.Value, opts.Cause.RadioNetwork.Value)
		}
	case ngapType.CausePresentNas:
		if cause.Nas.Value != opts.Cause.Nas.Value {
			return fmt.Errorf("unexpected NAS Cause value: got %d, want %d", cause.Nas.Value, opts.Cause.Nas.Value)
		}
	default:
		return fmt.Errorf("unexpected Cause Present type: %d", cause.Present)
	}

	if ueNGAPIDs == nil {
		return fmt.Errorf("UENGAPIDs is nil")
	}

	return nil
}
