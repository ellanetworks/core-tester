package ue

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/ue/validate"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

const (
	NGAPFrameTimeout = 1 * time.Microsecond
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

func (t RegistrationSuccess) Run(env engine.Env) error { // nolint:gocognit
	gNodeB, err := gnb.Start(env.CoreN2Address, env.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = utils.NGSetupProcedure(gNodeB)
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

	err = gNodeB.SendInitialUEMessage(&gnb.InitialUEMessageOpts{
		Mcc:         MCC,
		Mnc:         MNC,
		GnbID:       GNBID,
		Tac:         TAC,
		RanUENGAPID: RANUENGAPID,
		NasPDU:      nasPDU,
		Guti5g:      newUE.UeSecurity.Guti,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	fr, err := gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err := validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	amfUENGAPID := utils.GetAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport)
	if amfUENGAPID == nil {
		return fmt.Errorf("could not get AMF UE NGAP ID from DownlinkNASTransport: %v", err)
	}

	receivedNASPDU := utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	rand, autn, err := validate.AuthenticationRequest(&validate.AuthenticationRequestOpts{
		NASPDU: receivedNASPDU,
		UE:     newUE,
	})
	if err != nil {
		return fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	paramAutn, err := newUE.DeriveRESstarAndSetKey(newUE.UeSecurity.AuthenticationSubs, rand[:], newUE.UeSecurity.Snn, autn[:])
	if err != nil {
		return fmt.Errorf("could not derive RES* and set key: %v", err)
	}

	authResp, err := ue.BuildAuthenticationResponse(&ue.AuthenticationResponseOpts{
		AuthenticationResponseParam: paramAutn,
		EapMsg:                      "",
	})
	if err != nil {
		return fmt.Errorf("could not build authentication response: %v", err)
	}

	err = gNodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: RANUENGAPID,
		Mcc:         MCC,
		Mnc:         MNC,
		GnbID:       GNBID,
		Tac:         TAC,
		NasPDU:      authResp,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	fr, err = gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err = validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	receivedNASPDU = utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	ksi, tsc, err := validate.SecurityModeCommand(&validate.SecurityModeCommandOpts{
		NASPDU: receivedNASPDU,
		UE:     newUE,
	})
	if err != nil {
		return fmt.Errorf("could not validate NAS PDU Security Mode Command: %v", err)
	}

	newUE.UeSecurity.NgKsi.Ksi = ksi
	newUE.UeSecurity.NgKsi.Tsc = tsc

	securityModeComplete, err := ue.BuildSecurityModeComplete(&ue.SecurityModeCompleteOpts{
		UESecurity: newUE.UeSecurity,
	})
	if err != nil {
		return fmt.Errorf("error sending Security Mode Complete: %w", err)
	}

	encodedPdu, err := newUE.EncodeNasPduWithSecurity(securityModeComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", newUE.UeSecurity.Supi, err)
	}

	err = gNodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: RANUENGAPID,
		Mcc:         MCC,
		Mnc:         MNC,
		GnbID:       GNBID,
		Tac:         TAC,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	fr, err = gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	initialContextSetupRequest, err := validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("initial context setup request validation failed: %v", err)
	}

	err = gNodeB.SendInitialContextSetupResponse(&gnb.InitialContextSetupResponseOpts{
		AMFUENGAPID: amfUENGAPID.Value,
		RANUENGAPID: RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	receivedNASPDU = utils.GetNASPDUFromInitialContextSetupRequest(initialContextSetupRequest)

	guti5g, err := validate.RegistrationAcceptInitialContextSetupRequest(&validate.RegistrationAcceptOpts{
		NASPDU: receivedNASPDU,
		UE:     newUE,
		Sst:    SST,
		Sd:     SD,
	})
	if err != nil {
		return fmt.Errorf("could not validate NAS PDU Registration Accept Initial Context Setup Request: %v", err)
	}

	newUE.Set5gGuti(guti5g)

	regComplete, err := ue.BuildRegistrationComplete(&ue.RegistrationCompleteOpts{
		SORTransparentContainer: nil,
	})
	if err != nil {
		return fmt.Errorf("could not build Registration Complete NAS PDU: %v", err)
	}

	encodedPdu, err = newUE.EncodeNasPduWithSecurity(regComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Registration Complete Msg", newUE.UeSecurity.Supi)
	}

	err = gNodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: RANUENGAPID,
		Mcc:         MCC,
		Mnc:         MNC,
		GnbID:       GNBID,
		Tac:         TAC,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	pduReq, err := ue.BuildPduSessionEstablishmentRequest(&ue.PduSessionEstablishmentRequestOpts{
		PDUSessionID: PDUSessionID,
	})
	if err != nil {
		return fmt.Errorf("could not build PDU Session Establishment Request: %v", err)
	}

	pduUplink, err := ue.BuildUplinkNasTransport(&ue.UplinkNasTransportOpts{
		PDUSessionID:     PDUSessionID,
		PayloadContainer: pduReq,
		DNN:              newUE.DNN,
		SNSSAI:           newUE.Snssai,
	})
	if err != nil {
		return fmt.Errorf("could not build Uplink NAS Transport for PDU Session: %v", err)
	}

	encodedPdu, err = newUE.EncodeNasPduWithSecurity(pduUplink, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Uplink NAS Transport for PDU Session Msg", newUE.UeSecurity.Supi)
	}

	err = gNodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: RANUENGAPID,
		Mcc:         MCC,
		Mnc:         MNC,
		GnbID:       GNBID,
		Tac:         TAC,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport for PDU Session Establishment: %v", err)
	}

	fr, err = gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive NGAP frame: %v", err)
	}

	expectedUEIP := net.ParseIP("10.45.0.1")

	err = validate.PDUSessionResourceSetupRequest(&validate.PDUSessionResourceSetupRequestOpts{
		Frame:                fr,
		ExpectedPDUSessionID: PDUSessionID,
		ExpectedSST:          SST,
		ExpectedSD:           SD,
		UEIns:                newUE,
		ExpectedPDUSessionEstablishmentAccept: &validate.ExpectedPDUSessionEstablishmentAccept{
			PDUSessionID: PDUSessionID,
			UeIP:         &expectedUEIP,
			Dnn:          DNN,
			Sst:          SST,
			Sd:           SD,
			Qfi:          1,
			FiveQI:       9,
		},
	})
	if err != nil {
		return fmt.Errorf("PDUSessionResourceSetupRequest validation failed: %v", err)
	}

	n3GnbIP, err := netip.ParseAddr("1.2.3.4")
	if err != nil {
		return fmt.Errorf("failed to parse N3 GNB IP address: %v", err)
	}

	err = gNodeB.SendPDUSessionResourceSetupResponse(&gnb.PDUSessionResourceSetupResponseOpts{
		AMFUENGAPID: amfUENGAPID.Value,
		RANUENGAPID: RANUENGAPID,
		N3GnbIp:     n3GnbIP,
		PDUSessions: [16]*gnb.GnbPDUSession{
			{
				PDUSessionId: 1,
				DownlinkTeid: 100,
				QosId:        1,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send PDUSessionResourceSetupResponse: %v", err)
	}

	return nil
}
