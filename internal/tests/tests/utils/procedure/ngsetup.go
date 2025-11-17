package procedure

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type NGSetupOpts struct {
	Mcc    string
	Mnc    string
	Sst    int32
	Tac    string
	GnodeB *gnb.GnodeB
}

func NGSetup(ctx context.Context, opts *NGSetupOpts) error {
	err := opts.GnodeB.SendNGSetupRequest(&gnb.NGSetupRequestOpts{
		Mcc:  opts.Mcc,
		Mnc:  opts.Mnc,
		Sst:  opts.Sst,
		Tac:  opts.Tac,
		Name: "Ella-Core-Tester",
	})
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

	fr, err := opts.GnodeB.WaitForNextFrame(100 * time.Millisecond)
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
