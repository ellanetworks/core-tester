package gnb

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type NGSetupResponse struct{}

func (NGSetupResponse) Meta() engine.Meta {
	return engine.Meta{
		ID:      "gnb/ngap/setup_response",
		Summary: "NGSetup request/response test validating the NGSetupResponse message contents",
		Timeout: 500 * time.Millisecond,
	}
}

func (t NGSetupResponse) Run(ctx context.Context, env engine.Env) error {
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

	return nil
}
