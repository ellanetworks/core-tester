package ue

import (
	"fmt"
	"reflect"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/gnb/build"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
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
		Dnn:                  "internet",
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
		return fmt.Errorf("NGAP ProcedureCode is not DownlinkNASTransport (%d), received %d", ngapType.ProcedureCodeDownlinkNASTransport, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	downlinkNASTransport := pdu.InitiatingMessage.Value.DownlinkNASTransport
	if downlinkNASTransport == nil {
		return fmt.Errorf("DownlinkNASTransport is nil")
	}

	amfUENGAPID := getAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport)
	if amfUENGAPID == nil {
		return fmt.Errorf("could not get AMF UE NGAP ID from DownlinkNASTransport: %v", err)
	}

	receivedNASPDU := getNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	if receivedNASPDU == nil {
		return fmt.Errorf("could not get NAS PDU from DownlinkNASTransport")
	}

	rand, autn, err := validateNASPDUAuthenticationRequest(receivedNASPDU, newUE)
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

	uplinkNasTransportOpts := &build.UplinkNasTransportOpts{
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

	fr, err = gNodeB.ReceiveFrame(timeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 1)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err = ngap.Decoder(fr.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport {
		return fmt.Errorf("NGAP ProcedureCode is not DownlinkNASTransport (%d), received %d", ngapType.ProcedureCodeDownlinkNASTransport, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	downlinkNASTransport = pdu.InitiatingMessage.Value.DownlinkNASTransport
	if downlinkNASTransport == nil {
		return fmt.Errorf("DownlinkNASTransport is nil")
	}

	receivedNASPDU = getNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	if receivedNASPDU == nil {
		return fmt.Errorf("could not get NAS PDU from DownlinkNASTransport")
	}

	ksi, tsc, err := validateNASPDUSecurityModeCommand(receivedNASPDU, newUE)
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

	uplinkNasTransportOpts = &build.UplinkNasTransportOpts{
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

	fr, err = gNodeB.ReceiveFrame(timeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 1)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err = ngap.Decoder(fr.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeInitialContextSetup {
		return fmt.Errorf("NGAP ProcedureCode is not InitialContextSetup (%d), received %d", ngapType.ProcedureCodeInitialContextSetup, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	initialContextSetupRequest := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	if initialContextSetupRequest == nil {
		return fmt.Errorf("InitialContextSetupRequest is nil")
	}

	initialContextSetupRespOpts := &build.InitialContextSetupResponseOpts{
		AMFUENGAPID: amfUENGAPID.Value,
		RANUENGAPID: 1,
	}

	err = gNodeB.SendInitialContextSetupResponse(initialContextSetupRespOpts)
	if err != nil {
		return fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	receivedNASPDU = getNASPDUFromInitialContextSetupRequest(initialContextSetupRequest)

	if receivedNASPDU == nil {
		return fmt.Errorf("could not get NAS PDU from InitialContextSetupRequest")
	}

	guti5g, err := validateNASPDURegistrationAcceptInitialContextSetupRequest(receivedNASPDU, newUE)
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

	uplinkNasTransportOpts = &build.UplinkNasTransportOpts{
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

	time.Sleep(1 * time.Second)

	return nil
}

func getNASPDUFromDownlinkNasTransport(downlinkNASTransport *ngapType.DownlinkNASTransport) *ngapType.NASPDU {
	for _, ie := range downlinkNASTransport.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDNASPDU:
			return ie.Value.NASPDU
		default:
			continue
		}
	}

	return nil
}

func getNASPDUFromInitialContextSetupRequest(initialContextSetupRequest *ngapType.InitialContextSetupRequest) *ngapType.NASPDU {
	for _, ie := range initialContextSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDNASPDU:
			return ie.Value.NASPDU
		default:
			continue
		}
	}

	return nil
}

func getAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport *ngapType.DownlinkNASTransport) *ngapType.AMFUENGAPID {
	for _, ie := range downlinkNASTransport.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			return ie.Value.AMFUENGAPID
		default:
			continue
		}
	}

	return nil
}

func validateNASPDUAuthenticationRequest(nasPDU *ngapType.NASPDU, ueIns *ue.UE) ([16]uint8, [16]uint8, error) {
	if nasPDU == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ueIns.DecodeNAS(nasPDU.Value)
	if err != nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeAuthenticationRequest {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS message type is not Authentication Request (%d), got (%d)", nas.MsgTypeAuthenticationRequest, msg.GmmMessage.GetMessageType())
	}

	if msg.AuthenticationRequest == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS Authentication Request message is nil")
	}

	if msg.AuthenticationParameterRAND == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS Authentication Request RAND is nil")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.ExtendedProtocolDiscriminator).IsZero() {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("extended protocol is missing")
	}

	if msg.AuthenticationRequest.GetExtendedProtocolDiscriminator() != 126 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("extended protocol not the expected value")
	}

	if msg.AuthenticationRequest.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("spare half octet not the expected value")
	}

	if msg.AuthenticationRequest.GetSecurityHeaderType() != 0 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.AuthenticationRequestMessageIdentity).IsZero() {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("message type is missing")
	}

	if msg.AuthenticationRequest.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("spare half octet not the expected value")
	}

	if msg.AuthenticationRequest.GetNasKeySetIdentifiler() == 7 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.ABBA).IsZero() {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("ABBA is missing")
	}

	if msg.AuthenticationRequest.GetABBAContents() == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("ABBA content is missing")
	}

	rand := msg.GetRANDValue()
	autn := msg.GetAUTN()

	return rand, autn, nil
}

func validateNASPDUSecurityModeCommand(nasPDU *ngapType.NASPDU, ueIns *ue.UE) (int32, models.ScType, error) {
	if nasPDU == nil {
		return 0, "", fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ueIns.DecodeNAS(nasPDU.Value)
	if err != nil {
		return 0, "", fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return 0, "", fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return 0, "", fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeSecurityModeCommand {
		return 0, "", fmt.Errorf("NAS message type is not Security Mode Command (%d), got (%d)", nas.MsgTypeSecurityModeCommand, msg.GmmMessage.GetMessageType())
	}

	if reflect.ValueOf(msg.SecurityModeCommand.ExtendedProtocolDiscriminator).IsZero() {
		return 0, "", fmt.Errorf("extended protocol is missing")
	}

	if msg.SecurityModeCommand.GetExtendedProtocolDiscriminator() != 126 {
		return 0, "", fmt.Errorf("extended protocol not the expected value")
	}

	if msg.SecurityModeCommand.GetSecurityHeaderType() != 0 {
		return 0, "", fmt.Errorf("security header type not the expected value")
	}

	if msg.SecurityModeCommand.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return 0, "", fmt.Errorf("spare half octet not the expected value")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.SecurityModeCommandMessageIdentity).IsZero() {
		return 0, "", fmt.Errorf("message type is missing")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.SelectedNASSecurityAlgorithms).IsZero() {
		return 0, "", fmt.Errorf("nas security algorithms is missing")
	}

	if msg.SecurityModeCommand.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return 0, "", fmt.Errorf("spare half octet not the expected value")
	}

	if msg.SecurityModeCommand.GetNasKeySetIdentifiler() == 7 {
		return 0, "", fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.ReplayedUESecurityCapabilities).IsZero() {
		return 0, "", fmt.Errorf("replayed ue security capabilities is missing")
	}

	ksi := int32(msg.SecurityModeCommand.GetNasKeySetIdentifiler())

	var tsc models.ScType

	switch msg.SecurityModeCommand.GetTSC() {
	case nasMessage.TypeOfSecurityContextFlagNative:
		tsc = models.ScType_NATIVE
	case nasMessage.TypeOfSecurityContextFlagMapped:
		tsc = models.ScType_MAPPED
	}

	return ksi, tsc, nil
}

func validateNASPDURegistrationAcceptInitialContextSetupRequest(nasPDU *ngapType.NASPDU, ueIns *ue.UE) (*nasType.GUTI5G, error) {
	if nasPDU == nil {
		return nil, fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ueIns.DecodeNAS(nasPDU.Value)
	if err != nil {
		return nil, fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return nil, fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return nil, fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeRegistrationAccept {
		return nil, fmt.Errorf("NAS message type is not Registration Accept (%d), got (%d)", nas.MsgTypeRegistrationAccept, msg.GmmMessage.GetMessageType())
	}

	if msg.RegistrationAccept == nil {
		return nil, fmt.Errorf("NAS Registration Accept message is nil")
	}

	if reflect.ValueOf(msg.RegistrationAccept.ExtendedProtocolDiscriminator).IsZero() {
		return nil, fmt.Errorf("extended protocol is missing")
	}

	if msg.RegistrationAccept.GetExtendedProtocolDiscriminator() != 126 {
		return nil, fmt.Errorf("extended protocol not the expected value")
	}

	if msg.RegistrationAccept.GetSpareHalfOctet() != 0 {
		return nil, fmt.Errorf("spare half octet not the expected value")
	}

	if msg.RegistrationAccept.GetSecurityHeaderType() != 0 {
		return nil, fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.RegistrationAccept.RegistrationAcceptMessageIdentity).IsZero() {
		return nil, fmt.Errorf("message type is missing")
	}

	if msg.RegistrationAcceptMessageIdentity.GetMessageType() != 66 {
		return nil, fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(msg.RegistrationAccept.RegistrationResult5GS).IsZero() {
		return nil, fmt.Errorf("registration result 5GS is missing")
	}

	if msg.GetRegistrationResultValue5GS() != 1 {
		return nil, fmt.Errorf("registration result 5GS not the expected value")
	}

	if msg.RegistrationAccept.GUTI5G == nil {
		return nil, fmt.Errorf("GUTI5G is nil")
	}

	snssai := msg.RegistrationAccept.AllowedNSSAI.GetSNSSAIValue()

	if len(snssai) == 0 {
		return nil, fmt.Errorf("allowed NSSAI is missing")
	}

	sst := int32(snssai[1])
	sd := fmt.Sprintf("%x%x%x", snssai[2], snssai[3], snssai[4])

	if sst != ueIns.Snssai.Sst {
		return nil, fmt.Errorf("allowed NSSAI SST not the expected value, got: %d, want: %d", sst, ueIns.Snssai.Sst)
	}

	if sd != ueIns.Snssai.Sd {
		return nil, fmt.Errorf("allowed NSSAI SD not the expected value, got: %s, want: %s", sd, ueIns.Snssai.Sd)
	}

	if msg.T3512Value == nil {
		return nil, fmt.Errorf("T3512 value is nil")
	}

	timerInSeconds := utils.NasToGPRSTimer3(msg.T3512Value.Octet)
	if timerInSeconds != 3600 {
		return nil, fmt.Errorf("T3512 timer in seconds not the expected value, got: %d, want: 3600", timerInSeconds)
	}

	return msg.RegistrationAccept.GUTI5G, nil
}
