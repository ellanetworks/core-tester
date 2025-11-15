package ue

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
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

const testStartIMSI = "001017271246546"

type RegistrationSuccess50Sequential struct{}

func (RegistrationSuccess50Sequential) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration_success_50_sequential",
		Summary: "UE sequential registration success test validating the Registration Request and Authentication procedures with 50 UEs",
		Timeout: 60 * time.Second,
	}
}

func computeIMSI(baseIMSI string, increment int) (string, error) {
	intBaseImsi, err := strconv.Atoi(baseIMSI)
	if err != nil {
		return "", fmt.Errorf("failed to convert base IMSI to int: %v", err)
	}

	newIMSI := intBaseImsi + increment

	return fmt.Sprintf("%015d", newIMSI), nil
}

func buildSubscriberConfig() ([]core.SubscriberConfig, error) {
	subs := []core.SubscriberConfig{}

	for i := range 50 {
		imsi, err := computeIMSI(testStartIMSI, i)
		if err != nil {
			return nil, fmt.Errorf("failed to compute IMSI: %v", err)
		}

		subs = append(subs, core.SubscriberConfig{
			Imsi:           imsi,
			Key:            "640f441067cd56f1474cbcacd7a0588f",
			SequenceNumber: "000000000022",
			OPc:            "cb698a2341629c3241ae01de9d89de4f",
			PolicyName:     "bbb",
		})
	}

	return subs, nil
}

func (t RegistrationSuccess50Sequential) Run(ctx context.Context, env engine.Env) error {
	subs, err := buildSubscriberConfig()
	if err != nil {
		return fmt.Errorf("could not build subscriber config: %v", err)
	}

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
		DataNetworks: []core.DataNetworkConfig{
			{
				Name:   env.Config.EllaCore.DNN,
				IPPool: "10.45.0.0/16",
				DNS:    "8.8.8.8",
				Mtu:    1500,
			},
		},
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
		Subscribers: subs,
	})

	err = ellaCoreEnv.Create(ctx)
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

	for i, subscriber := range subs {
		newUE, err := ue.NewUE(&ue.UEOpts{
			Msin: subscriber.Imsi[5:],
			K:    subscriber.Key,
			OpC:  subscriber.OPc,
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
			RANUENGAPID:  int64(i + 1),
			PDUSessionID: PDUSessionID,
			UE:           newUE,
			N3GNBAddress: gnbN3Address,
			GnodeB:       gNodeB,
			DownlinkTEID: DownlinkTEID,
		})
		if err != nil {
			return fmt.Errorf("initial registration procedure failed: %v", err)
		}

		// Cleanup
		err = procedure.Deregistration(ctx, &procedure.DeregistrationOpts{
			GnodeB:      gNodeB,
			UE:          newUE,
			AMFUENGAPID: resp.AMFUENGAPID,
			RANUENGAPID: int64(i + 1),
			MCC:         env.Config.EllaCore.MCC,
			MNC:         env.Config.EllaCore.MNC,
			GNBID:       GNBID,
			TAC:         env.Config.EllaCore.TAC,
		})
		if err != nil {
			return fmt.Errorf("DeregistrationProcedure failed: %v", err)
		}
	}

	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}
