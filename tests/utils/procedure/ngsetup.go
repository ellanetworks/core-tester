package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type NGSetupOpts struct {
	Mcc    string
	Mnc    string
	Sst    int32
	Tac    string
	GnodeB *gnb.GnodeB
}

func NGSetup(opts *NGSetupOpts) error {
	err := opts.GnodeB.SendNGSetupRequest(&gnb.NGSetupRequestOpts{
		Mcc: opts.Mcc,
		Mnc: opts.Mnc,
		Sst: opts.Sst,
		Tac: opts.Tac,
	})
	if err != nil {
		return fmt.Errorf("could not send NGSetupRequest: %v", err)
	}

	timeout := 1 * time.Microsecond

	fr, err := opts.GnodeB.ReceiveFrame(timeout)
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

	return nil
}
