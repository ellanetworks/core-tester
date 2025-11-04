package ue

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/common/sidf"
	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/gnb/build"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas/nasMessage"
)

type RegistrationBasic struct{}

func (RegistrationBasic) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration_basic",
		Summary: "Basic UE registration test validating initial registration procedure",
	}
}

func (t RegistrationBasic) Run(env engine.Env) error {
	gNodeB, err := gnb.Start(env.CoreN2Address, env.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer func() {
		err := gNodeB.Close()
		if err != nil {
			fmt.Printf("error closing gNB: %v\n", err)
		}
	}()

	err = NGSetupProcedure(gNodeB)
	if err != nil {
		return fmt.Errorf("NGSetupProcedure failed: %v", err)
	}

	secCap := UeSecurityCapability{
		Integrity: IntegrityAlgorithms{
			Nia2: true,
		},
		Ciphering: CipheringAlgorithms{
			Nea0: true,
			Nea2: true,
		},
	}

	newUEOpts := &ue.UEOpts{
		Msin: "1234567890",
		K:    "465B5CE8B199B49FAA5F0A2EE238A6BC",
		OpC:  "E8ED289DEBA952E4283B54E88E6183CA",
		Amf:  "80000000000000000000000000000000",
		Sqn:  "000000000001",
		Mcc:  "001",
		Mnc:  "01",
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator:     "0000",
		Dnn:                  "internet",
		Sst:                  1,
		Sd:                   "010203",
		UeSecurityCapability: GetUESecurityCapability(&secCap),
	}

	newUE, err := ue.NewUE(newUEOpts)
	if err != nil {
		return fmt.Errorf("could not create UE: %v", err)
	}

	regReqOpts := &ue.RegistrationRequestOpts{
		RegistrationType:  nasMessage.RegistrationType5GSInitialRegistration,
		RequestedNSSAI:    nil,
		UplinkDataStatus:  nil,
		IncludeCapability: false,
		UESecurity:        newUE.UeSecurity,
	}

	nasPDU, err := ue.BuildRegistrationRequest(regReqOpts)
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	initialUEMsgOpts := &build.InitialUEMessageOpts{
		Mcc:   "001",
		Mnc:   "01",
		GnbID: "000008",
		Tac:   "0001",
		// RanUENGAPIID: 1,
		NasPDU: nasPDU,
	}

	err = gNodeB.SendInitialUEMessage(initialUEMsgOpts)
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	return nil
}
