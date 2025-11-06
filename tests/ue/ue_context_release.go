package ue

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/procedure"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/ngap/ngapType"
)

type UEContextRelease struct{}

func (UEContextRelease) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/context/release",
		Summary: "UE context release test validating the Context Release Request and Response procedures",
	}
}

func (t UEContextRelease) Run(env engine.Env) error {
	gNodeB, err := gnb.Start(env.CoreN2Address, env.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = procedure.NGSetup(&procedure.NGSetupOpts{
		Mcc:              MCC,
		Mnc:              MNC,
		Sst:              SST,
		Tac:              TAC,
		GnodeB:           gNodeB,
		NGAPFrameTimeout: NGAPFrameTimeout,
	})
	if err != nil {
		return fmt.Errorf("NGSetupProcedure failed: %v", err)
	}

	newUE, err := ue.NewUE(&ue.UEOpts{
		Msin: "2989077253",
		K:    "369f7bd3067faec142c47ed9132e942a",
		OpC:  "34e89843fe0683dc961873ebc05b8a35",
		Amf:  "80000000000000000000000000000000",
		Sqn:  "000000000001",
		Mcc:  MCC,
		Mnc:  MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              DNN,
		Sst:              SST,
		Sd:               SD,
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

	resp, err := procedure.InitialRegistration(&procedure.InitialRegistrationOpts{
		Mcc:              MCC,
		Mnc:              MNC,
		Sst:              SST,
		Sd:               SD,
		Tac:              TAC,
		DNN:              DNN,
		GNBID:            GNBID,
		RANUENGAPID:      RANUENGAPID,
		PDUSessionID:     PDUSessionID,
		UE:               newUE,
		GnodeB:           gNodeB,
		NGAPFrameTimeout: NGAPFrameTimeout,
	})
	if err != nil {
		return fmt.Errorf("InitialRegistrationProcedure failed: %v", err)
	}

	err = gNodeB.SendUEContextReleaseRequest(&gnb.UEContextReleaseRequestOpts{
		AMFUENGAPID: resp.AMFUENGAPID,
		RANUENGAPID: RANUENGAPID,
		PDUSessionIDs: [16]bool{
			true, false, false, false, false, false, false, false,
			false, false, false, false, false, false, false, false,
		},
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	fr, err := gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = validate.UEContextReleaseCommand(&validate.UEContextReleaseCommandOpts{
		Frame: fr,
		Cause: &ngapType.Cause{
			Present: ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentUserInactivity,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("UEContextRelease validation failed: %v", err)
	}

	err = gNodeB.SendUEContextReleaseComplete(&gnb.UEContextReleaseCompleteOpts{
		AMFUENGAPID: resp.AMFUENGAPID,
		RANUENGAPID: RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	// // Cleanup
	// err = procedure.Deregistration(&procedure.DeregistrationOpts{
	// 	GnodeB:           gNodeB,
	// 	UE:               newUE,
	// 	AMFUENGAPID:      resp.AMFUENGAPID,
	// 	RANUENGAPID:      RANUENGAPID,
	// 	MCC:              MCC,
	// 	MNC:              MNC,
	// 	GNBID:            GNBID,
	// 	TAC:              TAC,
	// 	NGAPFrameTimeout: NGAPFrameTimeout,
	// })
	// if err != nil {
	// 	return fmt.Errorf("DeregistrationProcedure failed: %v", err)
	// }

	return nil
}
