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
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/validate"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"golang.org/x/sync/errgroup"
)

const NumRadios = 12

type NGSetupResponse struct{}

func (NGSetupResponse) Meta() engine.Meta {
	return engine.Meta{
		ID:      "gnb/ngap/setup_response",
		Summary: "NGSetup request/response test validating the NGSetupResponse message contents with 12 radios in parallel",
		Timeout: 1 * time.Second,
	}
}

func (t NGSetupResponse) Run(ctx context.Context, env engine.Env) error {
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

	eg := errgroup.Group{}

	for i := range NumRadios {
		func() {
			eg.Go(func() error {
				return ngSetupTest(env, i)
			})
		}()
	}

	err = eg.Wait()
	if err != nil {
		return fmt.Errorf("NGSetupResponse test failed: %v", err)
	}

	// Cleanup
	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}

func ngSetupTest(env engine.Env, index int) error {
	gNodeB, err := gnb.Start(
		fmt.Sprintf("%06x", index+1),
		env.Config.EllaCore.MCC,
		env.Config.EllaCore.MNC,
		env.Config.EllaCore.SST,
		env.Config.EllaCore.TAC,
		fmt.Sprintf("Ella-Core-Tester-%d", index),
		env.Config.EllaCore.N2Address,
		env.Config.Gnb.N2Address,
		"1.2.3.4",
		1,
	)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	nextFrame, err := gNodeB.WaitForNextFrame(200 * time.Millisecond)
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
