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
)

type UEContextRelease struct{}

func (UEContextRelease) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/context/release",
		Summary: "UE context release test validating the Context Release Request and Response procedures",
		Timeout: 2 * time.Second,
	}
}

func (t UEContextRelease) Run(ctx context.Context, env engine.Env) error {
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

	newUE, err := ue.NewUE(&ue.UEOpts{
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
		return fmt.Errorf("could not parse gNB N3 address: %v", err)
	}

	resp, err := procedure.InitialRegistration(ctx, &procedure.InitialRegistrationOpts{
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
		N3GNBAddress: gnbN3Address,
		GnodeB:       gNodeB,
		DownlinkTEID: DownlinkTEID,
	})
	if err != nil {
		return fmt.Errorf("InitialRegistrationProcedure failed: %v", err)
	}

	pduSessionStatus := [16]bool{}
	pduSessionStatus[PDUSessionID] = true

	err = procedure.UEContextRelease(ctx, &procedure.UEContextReleaseOpts{
		AMFUENGAPID:   resp.AMFUENGAPID,
		RANUENGAPID:   RANUENGAPID,
		GnodeB:        gNodeB,
		PDUSessionIDs: pduSessionStatus,
	})
	if err != nil {
		return fmt.Errorf("UEContextReleaseProcedure failed: %v", err)
	}

	// Cleanup
	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}
