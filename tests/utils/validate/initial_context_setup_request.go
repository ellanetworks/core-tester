package validate

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type InitialContextSetupRequestOpts struct {
	Frame gnb.SCTPFrame
}

func InitialContextSetupRequest(opts *InitialContextSetupRequestOpts) (*ngapType.InitialContextSetupRequest, error) {
	err := utils.ValidateSCTP(opts.Frame.Info, 60, 1)
	if err != nil {
		return nil, fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(opts.Frame.Data)
	if err != nil {
		return nil, fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return nil, fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeInitialContextSetup {
		return nil, fmt.Errorf("NGAP ProcedureCode is not InitialContextSetup (%d), received %d", ngapType.ProcedureCodeInitialContextSetup, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	initialContextSetupRequest := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	if initialContextSetupRequest == nil {
		return nil, fmt.Errorf("InitialContextSetupRequest is nil")
	}

	return initialContextSetupRequest, nil
}
