package ue

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/procedure"
)

const (
	NGAPFrameTimeout = 50 * time.Microsecond
	RANUENGAPID      = 1
	MCC              = "001"
	MNC              = "01"
	DNN              = "internet"
	SST              = 1
	SD               = "102030"
	TAC              = "000001"
	GNBID            = "000008"
	PDUSessionID     = 1
)

type RegistrationSuccess struct{}

func (RegistrationSuccess) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration_success",
		Summary: "UE registration success test validating the Registration Request and Authentication procedures",
	}
}

func (t RegistrationSuccess) Run(env engine.Env) error {
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

	_, err = procedure.InitialRegistration(&procedure.InitialRegistrationOpts{
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
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	return nil
}
