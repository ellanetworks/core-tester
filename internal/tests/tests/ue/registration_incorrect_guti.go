package ue

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/core"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/procedure"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"go.uber.org/zap"
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
				Name:            env.Config.Subscriber.PolicyName,
				BitrateUplink:   "100 Mbps",
				BitrateDownlink: "100 Mbps",
				Var5qi:          9,
				Arp:             15,
				DataNetworkName: env.Config.EllaCore.DNN,
			},
		},
		Subscribers: []core.SubscriberConfig{
			{
				Imsi:           env.Config.Subscriber.IMSI,
				Key:            env.Config.Subscriber.Key,
				SequenceNumber: env.Config.Subscriber.SequenceNumber,
				OPc:            env.Config.Subscriber.OPC,
				PolicyName:     env.Config.Subscriber.PolicyName,
			},
		},
	})

	err := ellaCoreEnv.Create(ctx)
	if err != nil {
		return fmt.Errorf("could not create EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Created EllaCore environment")

	gNodeB, err := gnb.Start(env.Config.EllaCore.N2Address, env.Config.Gnb.N2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = procedure.NGSetup(ctx, &procedure.NGSetupOpts{
		Mcc:    env.Config.EllaCore.MCC,
		Mnc:    env.Config.EllaCore.MNC,
		Sst:    env.Config.EllaCore.SST,
		Tac:    env.Config.EllaCore.TAC,
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
		Msin: env.Config.Subscriber.IMSI[5:],
		K:    env.Config.Subscriber.Key,
		OpC:  env.Config.Subscriber.OPC,
		Amf:  "80000000000000000000000000000000",
		Sqn:  env.Config.Subscriber.SequenceNumber,
		Mcc:  env.Config.EllaCore.MCC,
		Mnc:  env.Config.EllaCore.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              env.Config.EllaCore.DNN,
		Sst:              env.Config.EllaCore.SST,
		Sd:               env.Config.EllaCore.SD,
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

	gnbN3Address, err := netip.ParseAddr(env.Config.Gnb.N3Address)
	if err != nil {
		logger.Logger.Fatal("could not parse gNB N3 address", zap.Error(err))
	}

	resp, err := procedure.InitialRegistrationWithIdentityRequest(ctx, &procedure.InitialRegistrationWithIdentityRequestOpts{
		Mcc:          env.Config.EllaCore.MCC,
		Mnc:          env.Config.EllaCore.MNC,
		Sst:          env.Config.EllaCore.SST,
		Sd:           env.Config.EllaCore.SD,
		Tac:          env.Config.EllaCore.TAC,
		DNN:          env.Config.EllaCore.DNN,
		GNBID:        GNBID,
		RANUENGAPID:  RANUENGAPID,
		PDUSessionID: PDUSessionID,
		UE:           newUE,
		GnodeB:       gNodeB,
		DownlinkTEID: DownlinkTEID,
		N3GnbAddress: gnbN3Address,
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
		MCC:         env.Config.EllaCore.MCC,
		MNC:         env.Config.EllaCore.MNC,
		GNBID:       GNBID,
		TAC:         env.Config.EllaCore.TAC,
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
