package ue

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/common/sidf"
	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/gnb/build"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/nas"
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

	defer func() {
		err := gNodeB.Close()
		if err != nil {
			fmt.Printf("error closing gNB: %v\n", err)
		}
	}()

	err = utils.NGSetupProcedure(gNodeB)
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

	initialUEMsgOpts := &build.InitialUEMessageOpts{
		Mcc:         "001",
		Mnc:         "01",
		GnbID:       "000008",
		Tac:         "000001",
		RanUENGAPID: 1,
		NasPDU:      nasPDU,
		Guti5g:      newUE.UeSecurity.Guti,
	}

	err = gNodeB.SendInitialUEMessage(initialUEMsgOpts)
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	timeout := 1 * time.Microsecond

	fr, err := gNodeB.ReceiveFrame(timeout)
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

	err = validateDownlinkNASTransport(downlinkNASTransport, newUE)
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	return nil
}

func validateDownlinkNASTransport(downlinkNASTransport *ngapType.DownlinkNASTransport, ueIns *ue.UE) error {
	var nasPDU *ngapType.NASPDU

	for _, ie := range downlinkNASTransport.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
		case ngapType.ProtocolIEIDRANUENGAPID:
		case ngapType.ProtocolIEIDOldAMF:
		case ngapType.ProtocolIEIDRANPagingPriority:
		case ngapType.ProtocolIEIDNASPDU:
			nasPDU = ie.Value.NASPDU
		case ngapType.ProtocolIEIDMobilityRestrictionList:
		case ngapType.ProtocolIEIDIndexToRFSP:
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
		case ngapType.ProtocolIEIDAllowedNSSAI:

		default:
			return fmt.Errorf("DownlinkNASTransport IE ID (%d) not supported", ie.Id.Value)
		}
	}

	if nasPDU == nil {
		return fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ueIns.DecodeNAS(nasPDU.Value)
	if err != nil {
		return fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeRegistrationReject {
		return fmt.Errorf("NAS message type is not Registration Reject (%d)", nas.MsgTypeRegistrationReject)
	}

	if msg.RegistrationReject == nil {
		return fmt.Errorf("NAS Registration Reject message is nil")
	}

	if msg.RegistrationReject.GetCauseValue() != nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork {
		return fmt.Errorf("NAS Registration Reject Cause is not Unknown UE (%x), received (%x)", nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork, msg.RegistrationReject.GetCauseValue())
	}

	return nil
}
