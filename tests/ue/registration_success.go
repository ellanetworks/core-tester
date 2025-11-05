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
		Msin: "2989077253",
		K:    "369f7bd3067faec142c47ed9132e942a",
		OpC:  "34e89843fe0683dc961873ebc05b8a35",
		Amf:  "80000000000000000000000000000000",
		Sqn:  "000000000001",
		Mcc:  "001",
		Mnc:  "01",
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator:     "0000",
		DNN:                  "internet",
		Sst:                  1,
		Sd:                   "102030",
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

	fr, err := gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err := validate.DownlinkNASTransport(fr)
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	amfUENGAPID := utils.GetAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport)
	if amfUENGAPID == nil {
		return fmt.Errorf("could not get AMF UE NGAP ID from DownlinkNASTransport: %v", err)
	}

	receivedNASPDU := utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	rand, autn, err := validate.AuthenticationRequest(receivedNASPDU, newUE)
	if err != nil {
		return fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	paramAutn, err := newUE.DeriveRESstarAndSetKey(newUE.UeSecurity.AuthenticationSubs, rand[:], newUE.UeSecurity.Snn, autn[:])
	if err != nil {
		return fmt.Errorf("could not derive RES* and set key: %v", err)
	}

	authRespOpts := &ue.AuthenticationResponseOpts{
		AuthenticationResponseParam: paramAutn,
		EapMsg:                      "",
	}

	authResp, err := ue.BuildAuthenticationResponse(authRespOpts)
	if err != nil {
		return fmt.Errorf("could not build authentication response: %v", err)
	}

	uplinkNasTransportOpts := &gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: 1,
		Mcc:         "001",
		Mnc:         "01",
		GnbID:       "000008",
		Tac:         "000001",
		NasPDU:      authResp,
	}

	err = gNodeB.SendUplinkNASTransport(uplinkNasTransportOpts)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	fr, err = gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err = validate.DownlinkNASTransport(fr)
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	receivedNASPDU = utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	ksi, tsc, err := validate.SecurityModeCommand(receivedNASPDU, newUE)
	if err != nil {
		return fmt.Errorf("could not validate NAS PDU Security Mode Command: %v", err)
	}

	newUE.UeSecurity.NgKsi.Ksi = ksi
	newUE.UeSecurity.NgKsi.Tsc = tsc

	secModeCompOpts := &ue.SecurityModeCompleteOpts{
		UESecurity: newUE.UeSecurity,
	}

	securityModeComplete, err := ue.BuildSecurityModeComplete(secModeCompOpts)
	if err != nil {
		return fmt.Errorf("error sending Security Mode Complete: %w", err)
	}

	encodedPdu, err := newUE.EncodeNasPduWithSecurity(securityModeComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", newUE.UeSecurity.Supi, err)
	}

	uplinkNasTransportOpts = &gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: 1,
		Mcc:         "001",
		Mnc:         "01",
		GnbID:       "000008",
		Tac:         "000001",
		NasPDU:      encodedPdu,
	}

	err = gNodeB.SendUplinkNASTransport(uplinkNasTransportOpts)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	fr, err = gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	initialContextSetupRequest, err := validate.InitialContextSetupRequest(fr)
	if err != nil {
		return fmt.Errorf("initial context setup request validation failed: %v", err)
	}

	initialContextSetupRespOpts := &gnb.InitialContextSetupResponseOpts{
		AMFUENGAPID: amfUENGAPID.Value,
		RANUENGAPID: 1,
	}

	err = gNodeB.SendInitialContextSetupResponse(initialContextSetupRespOpts)
	if err != nil {
		return fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	receivedNASPDU = utils.GetNASPDUFromInitialContextSetupRequest(initialContextSetupRequest)

	guti5g, err := validate.RegistrationAcceptInitialContextSetupRequest(receivedNASPDU, newUE)
	if err != nil {
		return fmt.Errorf("could not validate NAS PDU Registration Accept Initial Context Setup Request: %v", err)
	}

	newUE.Set5gGuti(guti5g)

	regCompOpts := &ue.RegistrationCompleteOpts{
		SORTransparentContainer: nil,
	}

	regComplete, err := ue.BuildRegistrationComplete(regCompOpts)
	if err != nil {
		return fmt.Errorf("could not build Registration Complete NAS PDU: %v", err)
	}

	encodedPdu, err = newUE.EncodeNasPduWithSecurity(regComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Registration Complete Msg", newUE.UeSecurity.Supi)
	}

	uplinkNasTransportOpts = &gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: 1,
		Mcc:         "001",
		Mnc:         "01",
		GnbID:       "000008",
		Tac:         "000001",
		NasPDU:      encodedPdu,
	}

	err = gNodeB.SendUplinkNASTransport(uplinkNasTransportOpts)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	pduReqOpts := &ue.PduSessionEstablishmentRequestOpts{
		PDUSessionID: 1,
	}

	pduReq, err := ue.BuildPduSessionEstablishmentRequest(pduReqOpts)
	if err != nil {
		return fmt.Errorf("could not build PDU Session Establishment Request: %v", err)
	}

	uplinkNasTransportPDUOpts := &ue.UplinkNasTransportOpts{
		PDUSessionID:     1,
		PayloadContainer: pduReq,
		DNN:              newUE.DNN,
		SNSSAI:           newUE.Snssai,
	}

	pduUplink, err := ue.BuildUplinkNasTransport(uplinkNasTransportPDUOpts)
	if err != nil {
		return fmt.Errorf("could not build Uplink NAS Transport for PDU Session: %v", err)
	}

	encodedPdu, err = newUE.EncodeNasPduWithSecurity(pduUplink, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Uplink NAS Transport for PDU Session Msg", newUE.UeSecurity.Supi)
	}

	uplinkNasTransportOpts = &gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: 1,
		Mcc:         "001",
		Mnc:         "01",
		GnbID:       "000008",
		Tac:         "000001",
		NasPDU:      encodedPdu,
	}

	err = gNodeB.SendUplinkNASTransport(uplinkNasTransportOpts)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport for PDU Session Establishment: %v", err)
	}

	fr, err = gNodeB.ReceiveFrame(NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive NGAP frame: %v", err)
	}

	expectedUEIP := net.ParseIP("10.45.0.1")
	expectedPDUSessionEstablishmentAccept := &validate.ExpectedPDUSessionEstablishmentAccept{
		PDUSessionID: 1,
		UeIP:         &expectedUEIP,
		Dnn:          "internet",
		Sst:          1,
		Sd:           "102030",
		Qfi:          1,
		FiveQI:       9,
	}

	err = validate.PDUSessionResourceSetupRequest(fr, 1, "01", "102030", newUE, expectedPDUSessionEstablishmentAccept)
	if err != nil {
		return fmt.Errorf("PDUSessionResourceSetupRequest validation failed: %v", err)
	}

	n3GnbIP, err := netip.ParseAddr("1.2.3.4")
	if err != nil {
		return fmt.Errorf("failed to parse N3 GNB IP address: %v", err)
	}

	optsPduResp := &gnb.PDUSessionResourceSetupResponseOpts{
		AMFUENGAPID: amfUENGAPID.Value,
		RANUENGAPID: 1,
		N3GnbIp:     n3GnbIP,
		PDUSessions: [16]*gnb.GnbPDUSession{
			{
				PDUSessionId: 1,
				DownlinkTeid: 100,
				QosId:        1,
			},
		},
	}

	err = gNodeB.SendPDUSessionResourceSetupResponse(optsPduResp)
	if err != nil {
		return fmt.Errorf("failed to send PDUSessionResourceSetupResponse: %v", err)
	}

	return nil
}
