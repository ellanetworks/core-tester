package ue

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/ue/validate"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/procedure"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type RegistrationReject_UnknownUE struct{}

func (RegistrationReject_UnknownUE) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration_reject/unknown_ue",
		Summary: "UE registration reject test for unknown UE",
	}
}

func (t RegistrationReject_UnknownUE) Run(env engine.Env) error {
	gNodeB, err := gnb.Start(env.CoreN2Address, env.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = procedure.NGSetup(&procedure.NGSetupOpts{
		Mcc:    MCC,
		Mnc:    MNC,
		Sst:    SST,
		Tac:    TAC,
		GnodeB: gNodeB,
	})
	if err != nil {
		return fmt.Errorf("NGSetupProcedure failed: %v", err)
	}

	secCap := utils.UeSecurityCapability{
		Integrity: utils.IntegrityAlgorithms{
			Nia2: true,
		},
		Ciphering: utils.CipheringAlgorithms{
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
		Mcc:  MCC,
		Mnc:  MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator:     "0000",
		DNN:                  DNN,
		Sst:                  SST,
		Sd:                   SD,
		UeSecurityCapability: utils.GetUESecurityCapability(&secCap),
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

	initialUEMsgOpts := &gnb.InitialUEMessageOpts{
		Mcc:         MCC,
		Mnc:         MNC,
		GnbID:       GNBID,
		Tac:         TAC,
		RanUENGAPID: RANUENGAPID,
		NasPDU:      nasPDU,
		Guti5g:      newUE.UeSecurity.Guti,
	}

	err = gNodeB.SendInitialUEMessage(initialUEMsgOpts)
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	fr, err := gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 1)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(fr.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport {
		return fmt.Errorf("NGAP ProcedureCode is not DownlinkNASTransport (%d)", ngapType.ProcedureCodeDownlinkNASTransport)
	}

	downlinkNASTransport := pdu.InitiatingMessage.Value.DownlinkNASTransport
	if downlinkNASTransport == nil {
		return fmt.Errorf("DownlinkNASTransport is nil")
	}

	receivedNASPDU := utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	if receivedNASPDU == nil {
		return fmt.Errorf("could not get NAS PDU from DownlinkNASTransport")
	}

	err = validate.RegistrationReject(&validate.RegistrationRejectOpts{
		NASPDU: receivedNASPDU,
		UE:     newUE,
		Cause:  nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork,
	})
	if err != nil {
		return fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	return nil
}
