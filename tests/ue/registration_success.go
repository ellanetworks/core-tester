package ue

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/core"
	"github.com/ellanetworks/core-tester/tests/utils/procedure"
)

const (
	RANUENGAPID  = 1
	GNBID        = "000008"
	PDUSessionID = 1
)

const (
	IMSI       = "001012989077253"
	Key        = "369f7bd3067faec142c47ed9132e942a"
	OPC        = "34e89843fe0683dc961873ebc05b8a35"
	SQN        = "000000000001"
	PolicyName = "default"
)

type RegistrationSuccess struct{}

func (RegistrationSuccess) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration_success",
		Summary: "UE registration success test validating the Registration Request and Authentication procedures",
		Timeout: 2 * time.Second,
	}
}

func (t RegistrationSuccess) Run(ctx context.Context, env engine.Env) error {
	ellaCoreEnv := core.NewEllaCoreEnv(env.EllaCoreClient, core.EllaCoreConfig{
		Policies: []core.PolicyConfig{
			{
				Name:            PolicyName,
				BitrateUplink:   "100 Mbps",
				BitrateDownlink: "100 Mbps",
				Var5qi:          9,
				Arp:             15,
				DataNetworkName: env.CoreConfig.DNN,
			},
		},
		Subscribers: []core.SubscriberConfig{
			{
				Imsi:           IMSI,
				Key:            Key,
				SequenceNumber: SQN,
				OPc:            OPC,
				PolicyName:     PolicyName,
			},
		},
	})

	err := ellaCoreEnv.Create(ctx)
	if err != nil {
		return fmt.Errorf("could not create EllaCore environment: %v", err)
	}

	gNodeB, err := gnb.Start(env.CoreConfig.N2Address, env.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = procedure.NGSetup(ctx, &procedure.NGSetupOpts{
		Mcc:    env.CoreConfig.MCC,
		Mnc:    env.CoreConfig.MNC,
		Sst:    env.CoreConfig.SST,
		Tac:    env.CoreConfig.TAC,
		GnodeB: gNodeB,
	})
	if err != nil {
		return fmt.Errorf("NGSetupProcedure failed: %v", err)
	}

	newUE, err := ue.NewUE(&ue.UEOpts{
		Msin: IMSI[5:],
		K:    Key,
		OpC:  OPC,
		Amf:  "80000000000000000000000000000000",
		Sqn:  SQN,
		Mcc:  env.CoreConfig.MCC,
		Mnc:  env.CoreConfig.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              env.CoreConfig.DNN,
		Sst:              env.CoreConfig.SST,
		Sd:               env.CoreConfig.SD,
		IMEISV:           "3569380356438091",
		UeSecurityCapability: utils.GetUESecurityCapability(&utils.UeSecurityCapability{
			Integrity: utils.IntegrityAlgorithms{
				Nia2: true,
			},
			Ciphering: utils.CipheringAlgorithms{
				Nea0: true,
				Nea2: true,
			},
		}),
	})
	if err != nil {
		return fmt.Errorf("could not create UE: %v", err)
	}

	resp, err := procedure.InitialRegistration(ctx, &procedure.InitialRegistrationOpts{
		Mcc:          env.CoreConfig.MCC,
		Mnc:          env.CoreConfig.MNC,
		Sst:          env.CoreConfig.SST,
		Sd:           env.CoreConfig.SD,
		Tac:          env.CoreConfig.TAC,
		DNN:          env.CoreConfig.DNN,
		GNBID:        GNBID,
		RANUENGAPID:  RANUENGAPID,
		PDUSessionID: PDUSessionID,
		UE:           newUE,
		GnodeB:       gNodeB,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	// Cleanup
	err = procedure.Deregistration(ctx, &procedure.DeregistrationOpts{
		GnodeB:      gNodeB,
		UE:          newUE,
		AMFUENGAPID: resp.AMFUENGAPID,
		RANUENGAPID: RANUENGAPID,
		MCC:         env.CoreConfig.MCC,
		MNC:         env.CoreConfig.MNC,
		GNBID:       GNBID,
		TAC:         env.CoreConfig.TAC,
	})
	if err != nil {
		return fmt.Errorf("DeregistrationProcedure failed: %v", err)
	}

	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	return nil
}
