package validate

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func DownlinkNASTransport(frame gnb.SCTPFrame) (*ngapType.DownlinkNASTransport, error) {
	err := utils.ValidateSCTP(frame.Info, 60, 1)
	if err != nil {
		return nil, fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(frame.Data)
	if err != nil {
		return nil, fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return nil, fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport {
		return nil, fmt.Errorf("NGAP ProcedureCode is not DownlinkNASTransport (%d), received %d", ngapType.ProcedureCodeDownlinkNASTransport, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	downlinkNASTransport := pdu.InitiatingMessage.Value.DownlinkNASTransport
	if downlinkNASTransport == nil {
		return nil, fmt.Errorf("DownlinkNASTransport is nil")
	}

	return downlinkNASTransport, nil
}
