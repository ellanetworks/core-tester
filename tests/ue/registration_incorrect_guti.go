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
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type RegistrationIncorrectGUTI struct{}

func (RegistrationIncorrectGUTI) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration/incorrect_guti",
		Summary: "UE registration test validating the Registration Request procedure with incorrect GUTI",
		Timeout: 2 * time.Second,
	}
}

func (t RegistrationIncorrectGUTI) Run(ctx context.Context, env engine.Env) error {
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

	// Create a random GUTI
	guti := &nasType.GUTI5G{}
	guti.SetAMFRegionID(205)
	guti.SetAMFSetID(1018)
	guti.SetAMFPointer(1)
	guti.SetTMSI5G([4]uint8{0x21, 0x43, 0x65, 0x84})
	guti.SetLen(11)
	guti.SetTypeOfIdentity(nasMessage.MobileIdentity5GSType5gGuti)
	guti.SetIei(nasMessage.RegistrationAcceptGUTI5GType)

	newUE, err := ue.NewUE(&ue.UEOpts{
		Guti: guti,
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

	_, err = procedure.InitialRegistrationWithIdentityRequest(ctx, &procedure.InitialRegistrationWithIdentityRequestOpts{
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
	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	return nil
}
