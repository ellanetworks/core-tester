package gnb

import (
	"fmt"

	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func handleFrame(data []byte) error {
	pdu, err := ngap.Decoder(data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		return handleNGAPInitiatingMessage(pdu)
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		return handleNGAPSuccessfulOutcome(pdu)
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		return handleNGAPUnsuccessfulOutcome(pdu)
	default:
		return fmt.Errorf("NGAP PDU Present is invalid: %d", pdu.Present)
	}
}

func handleNGAPInitiatingMessage(pdu *ngapType.NGAPPDU) error {
	switch pdu.InitiatingMessage.Value.Present {
	case ngapType.InitiatingMessagePresentDownlinkNASTransport:
		return handleDownlinkNASTransport(pdu.InitiatingMessage.Value.DownlinkNASTransport)
	case ngapType.InitiatingMessagePresentInitialContextSetupRequest:
		return handleInitialContextSetupRequest(pdu.InitiatingMessage.Value.InitialContextSetupRequest)
	case ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest:
		return handlePDUSessionResourceSetupRequest(pdu.InitiatingMessage.Value.PDUSessionResourceSetupRequest)
	case ngapType.InitiatingMessagePresentUEContextReleaseCommand:
		return handleUEContextReleaseCommand(pdu.InitiatingMessage.Value.UEContextReleaseCommand)
	default:
		return fmt.Errorf("NGAP InitiatingMessage Present is invalid: %d", pdu.InitiatingMessage.Value.Present)
	}
}

func handleDownlinkNASTransport(downlinkNASTransport *ngapType.DownlinkNASTransport) error {
	return nil
}

func handleInitialContextSetupRequest(initialContextSetupRequest *ngapType.InitialContextSetupRequest) error {
	return nil
}

func handlePDUSessionResourceSetupRequest(pDUSessionResourceSetupRequest *ngapType.PDUSessionResourceSetupRequest) error {
	return nil
}

func handleUEContextReleaseCommand(uEContextReleaseCommand *ngapType.UEContextReleaseCommand) error {
	return nil
}

func handleNGAPSuccessfulOutcome(pdu *ngapType.NGAPPDU) error {
	switch pdu.SuccessfulOutcome.Value.Present {
	case ngapType.SuccessfulOutcomePresentNGSetupResponse:
		return handleNGSetupResponse(pdu.SuccessfulOutcome.Value.NGSetupResponse)
	case ngapType.SuccessfulOutcomePresentNGResetAcknowledge:
		return handleNGResetAcknowledge(pdu.SuccessfulOutcome.Value.NGResetAcknowledge)
	default:
		return fmt.Errorf("NGAP SuccessfulOutcome Present is invalid: %d", pdu.SuccessfulOutcome.Value.Present)
	}
}

func handleNGAPUnsuccessfulOutcome(pdu *ngapType.NGAPPDU) error {
	switch pdu.UnsuccessfulOutcome.Value.Present {
	case ngapType.UnsuccessfulOutcomePresentNGSetupFailure:
		return handleNGSetupFailure(pdu.UnsuccessfulOutcome.Value.NGSetupFailure)
	default:
		return fmt.Errorf("NGAP UnsuccessfulOutcome Present is invalid: %d", pdu.UnsuccessfulOutcome.Value.Present)
	}
}

func handleNGSetupResponse(nGSetupResponse *ngapType.NGSetupResponse) error {
	return nil
}

func handleNGSetupFailure(nGSetupFailure *ngapType.NGSetupFailure) error {
	return nil
}

func handleNGResetAcknowledge(nGResetAcknowledge *ngapType.NGResetAcknowledge) error {
	return nil
}
