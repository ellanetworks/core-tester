package ue

import (
	"bytes"
	"fmt"
	"net"
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

	downlinkNASTransport, err := validateDownlinkNASTransport(fr)
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	amfUENGAPID := getAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport)
	if amfUENGAPID == nil {
		return fmt.Errorf("could not get AMF UE NGAP ID from DownlinkNASTransport: %v", err)
	}

	receivedNASPDU := getNASPDUFromDownlinkNasTransport(downlinkNASTransport)

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

	downlinkNASTransport, err = validateDownlinkNASTransport(fr)
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	receivedNASPDU = getNASPDUFromDownlinkNasTransport(downlinkNASTransport)

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

	initialContextSetupRequest, err := validateInitialContextSetupRequest(fr)
	if err != nil {
		return fmt.Errorf("initial context setup request validation failed: %v", err)
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
		return fmt.Errorf("could not send UplinkNASTransport for PDU Session Establishment: %v", err)
	}

	fr, err = gNodeB.ReceiveFrame(timeout)
	if err != nil {
		return fmt.Errorf("could not receive NGAP frame: %v", err)
	}

	expectedUEIP := net.ParseIP("10.45.0.1")
	expectedPDUSessionEstablishmentAccept := &ExpectedPDUSessionEstablishmentAccept{
		PDUSessionID: 1,
		UeIP:         &expectedUEIP,
		Dnn:          "internet",
		Sst:          1,
		Sd:           "102030",
		Qfi:          1,
		FiveQI:       9,
	}

	err = validatePDUSessionResourceSetupRequest(fr, 1, "01", "102030", newUE, expectedPDUSessionEstablishmentAccept)
	if err != nil {
		return fmt.Errorf("PDUSessionResourceSetupRequest validation failed: %v", err)
	}

	return nil
}

func validateDownlinkNASTransport(frame gnb.SCTPFrame) (*ngapType.DownlinkNASTransport, error) {
	err := utils.ValidateSCTP(frame.Info, 60, 1)
	if err != nil {
		return nil, fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(frame.Data)
	if err != nil {
		return nil, fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return nil, fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport {
		return nil, fmt.Errorf("NGAP ProcedureCode is not DownlinkNASTransport (%d), received %d", ngapType.ProcedureCodeDownlinkNASTransport, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	downlinkNASTransport := pdu.InitiatingMessage.Value.DownlinkNASTransport
	if downlinkNASTransport == nil {
		return nil, fmt.Errorf("DownlinkNASTransport is nil")
	}

	return downlinkNASTransport, nil
}

func validateInitialContextSetupRequest(frame gnb.SCTPFrame) (*ngapType.InitialContextSetupRequest, error) {
	err := utils.ValidateSCTP(frame.Info, 60, 1)
	if err != nil {
		return nil, fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(frame.Data)
	if err != nil {
		return nil, fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return nil, fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeInitialContextSetup {
		return nil, fmt.Errorf("NGAP ProcedureCode is not InitialContextSetup (%d), received %d", ngapType.ProcedureCodeInitialContextSetup, pdu.InitiatingMessage.ProcedureCode.Value)
	}

	initialContextSetupRequest := pdu.InitiatingMessage.Value.InitialContextSetupRequest
	if initialContextSetupRequest == nil {
		return nil, fmt.Errorf("InitialContextSetupRequest is nil")
	}

	return initialContextSetupRequest, nil
}

func validatePDUSessionResourceSetupRequest(
	frame gnb.SCTPFrame,
	expectedPDUSessionID int64,
	expectedSST string,
	expectedSD string,
	ueIns *ue.UE,
	expectedPDUSessionEstablishmentAccept *ExpectedPDUSessionEstablishmentAccept,
) error {
	err := utils.ValidateSCTP(frame.Info, 60, 1)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(frame.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodePDUSessionResourceSetup {
		return fmt.Errorf("NGAP PDU is not a PDUSessionResourceSetupRequest")
	}

	pDUSessionResourceSetupRequest := pdu.InitiatingMessage.Value.PDUSessionResourceSetupRequest
	if pDUSessionResourceSetupRequest == nil {
		return fmt.Errorf("PDUSessionResourceSetupRequest is nil")
	}

	var (
		amfueNGAPID                                  *ngapType.AMFUENGAPID
		ranueNGAPID                                  *ngapType.RANUENGAPID
		protocolIEIDPDUSessionResourceSetupListSUReq *ngapType.PDUSessionResourceSetupListSUReq
		protocolIEIDUEAggregateMaximumBitRate        *ngapType.UEAggregateMaximumBitRate
	)

	for _, ie := range pDUSessionResourceSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			amfueNGAPID = ie.Value.AMFUENGAPID
		case ngapType.ProtocolIEIDRANUENGAPID:
			ranueNGAPID = ie.Value.RANUENGAPID
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq:
			protocolIEIDPDUSessionResourceSetupListSUReq = ie.Value.PDUSessionResourceSetupListSUReq
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			protocolIEIDUEAggregateMaximumBitRate = ie.Value.UEAggregateMaximumBitRate
		default:
			return fmt.Errorf("PDUSessionResourceSetupRequest IE ID (%d) not supported", ie.Id.Value)
		}
	}

	if amfueNGAPID == nil {
		return fmt.Errorf("AMFUENGAPID is missing in PDUSessionResourceSetupRequest")
	}

	if ranueNGAPID == nil {
		return fmt.Errorf("RANUENGAPID is missing in PDUSessionResourceSetupRequest")
	}

	if protocolIEIDPDUSessionResourceSetupListSUReq == nil {
		return fmt.Errorf("PDUSessionResourceSetupListSUReq is missing in PDUSessionResourceSetupRequest")
	}

	if protocolIEIDUEAggregateMaximumBitRate == nil {
		return fmt.Errorf("UEAggregateMaximumBitRate is missing in PDUSessionResourceSetupRequest")
	}

	err = validatePDUSessionResourceSetupListSUReq(protocolIEIDPDUSessionResourceSetupListSUReq, expectedPDUSessionID, expectedSST, expectedSD, ueIns, expectedPDUSessionEstablishmentAccept)
	if err != nil {
		return fmt.Errorf("PDUSessionResourceSetupListSUReq validation failed: %v", err)
	}

	return nil
}

func validatePDUSessionResourceSetupListSUReq(
	pDUSessionResourceSetupListSUReq *ngapType.PDUSessionResourceSetupListSUReq,
	expectedPDUSessionID int64,
	expectedSST string,
	expectedSD string,
	ueIns *ue.UE,
	expectedPDUSessionEstablishmentAccept *ExpectedPDUSessionEstablishmentAccept,
) error {
	if len(pDUSessionResourceSetupListSUReq.List) != 1 {
		return fmt.Errorf("PDUSessionResourceSetupListSUReq should have exactly one item, got: %d", len(pDUSessionResourceSetupListSUReq.List))
	}

	item := pDUSessionResourceSetupListSUReq.List[0]
	if item.PDUSessionID.Value != expectedPDUSessionID {
		return fmt.Errorf("unexpected PDUSessionID: %d", item.PDUSessionID.Value)
	}

	expectedSSTBytes, expectedSDBytes, err := build.GetSliceInBytes(expectedSST, expectedSD)
	if err != nil {
		return fmt.Errorf("could not convert expected SST and SD to byte slices: %v", err)
	}

	if !bytes.Equal(item.SNSSAI.SST.Value, expectedSSTBytes) {
		return fmt.Errorf("unexpected SNSSAI SST: %x, expected: %x", item.SNSSAI.SST.Value, expectedSSTBytes)
	}

	if !bytes.Equal(item.SNSSAI.SD.Value, expectedSDBytes) {
		return fmt.Errorf("unexpected SNSSAI SD: %x, expected: %x", item.SNSSAI.SD.Value, expectedSDBytes)
	}

	if item.PDUSessionNASPDU == nil {
		return fmt.Errorf("PDUSessionNASPDU is nil")
	}

	msg, err := ueIns.DecodeNAS(item.PDUSessionNASPDU.Value)
	if err != nil {
		return fmt.Errorf("could not decode PDU Session NAS PDU: %v", err)
	}

	if msg.GmmMessage == nil {
		return fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeDLNASTransport {
		return fmt.Errorf("NAS message type is not DLNASTransport (%d), got (%d)", nas.MsgTypeDLNASTransport, msg.GmmMessage.GetMessageType())
	}

	if msg.DLNASTransport == nil {
		return fmt.Errorf("NAS DLNASTransport message is nil")
	}

	if reflect.ValueOf(msg.DLNASTransport.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.DLNASTransport.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.DLNASTransport.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half not expected value")
	}

	if msg.DLNASTransport.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header not expected value")
	}

	if reflect.ValueOf(msg.DLNASTransport.SpareHalfOctetAndPayloadContainerType).IsZero() {
		return fmt.Errorf("payload container type is missing")
	}

	if msg.DLNASTransport.GetPayloadContainerType() != 1 {
		return fmt.Errorf("payload container type not expected value")
	}

	if reflect.ValueOf(msg.DLNASTransport.PayloadContainer).IsZero() || msg.DLNASTransport.GetPayloadContainerContents() == nil {
		return fmt.Errorf("payload container is missing")
	}

	if reflect.ValueOf(msg.DLNASTransport.PduSessionID2Value).IsZero() {
		return fmt.Errorf("pdu session id is missing")
	}

	if msg.DLNASTransport.PduSessionID2Value.GetIei() != 18 {
		return fmt.Errorf("pdu session id not expected value")
	}

	payloadContainer, err := getNasPduFromPduAccept(msg)
	if err != nil {
		return fmt.Errorf("could not get PDU Session establishment accept: %v", err)
	}

	pcMsgType := payloadContainer.GsmHeader.GetMessageType()
	if pcMsgType != nas.MsgTypePDUSessionEstablishmentAccept {
		return fmt.Errorf("PDU Session Establishment Accept message type is not correct, expected: %d, got: %d", nas.MsgTypePDUSessionEstablishmentAccept, pcMsgType)
	}

	err = validatePDUSessionEstablishmentAccept(payloadContainer.PDUSessionEstablishmentAccept, expectedPDUSessionEstablishmentAccept)
	if err != nil {
		return fmt.Errorf("could not validate PDU Session Establishment Accept: %v", err)
	}

	return nil
}

type ExpectedPDUSessionEstablishmentAccept struct {
	PDUSessionID uint8
	UeIP         *net.IP
	Dnn          string
	Sst          uint8
	Sd           string
	Qfi          uint8
	FiveQI       uint8
}

func validatePDUSessionEstablishmentAccept(msg *nasMessage.PDUSessionEstablishmentAccept, opts *ExpectedPDUSessionEstablishmentAccept) error {
	// check the mandatory fields
	if reflect.ValueOf(msg.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol discriminator is missing")
	}

	if msg.GetExtendedProtocolDiscriminator() != 46 {
		return fmt.Errorf("extended protocol discriminator not expected value")
	}

	if reflect.ValueOf(msg.PDUSessionID).IsZero() {
		return fmt.Errorf("pdu session id is missing or not expected value")
	}

	if reflect.ValueOf(msg.PTI).IsZero() {
		return fmt.Errorf("pti is missing")
	}

	if msg.GetPTI() != 1 {
		return fmt.Errorf("pti not expected value")
	}

	if msg.GetMessageType() != nas.MsgTypePDUSessionEstablishmentAccept {
		return fmt.Errorf("message type is missing or not expected value, got: %d, expected: %d", msg.GetMessageType(), nas.MsgTypePDUSessionEstablishmentAccept)
	}

	if reflect.ValueOf(msg.SelectedSSCModeAndSelectedPDUSessionType).IsZero() {
		return fmt.Errorf("ssc mode or pdu session type is missing")
	}

	if msg.GetPDUSessionType() != 1 {
		return fmt.Errorf("pdu session type not expected value")
	}

	if reflect.ValueOf(msg.AuthorizedQosRules).IsZero() {
		return fmt.Errorf("authorized qos rules is missing")
	}

	if reflect.ValueOf(msg.SessionAMBR).IsZero() {
		return fmt.Errorf("session ambr is missing")
	}

	pduSessionId := msg.GetPDUSessionID()
	if pduSessionId != opts.PDUSessionID {
		return fmt.Errorf("unexpected PDUSessionID: %d", pduSessionId)
	}

	ueIP, err := ueIPFromNAS(msg.GetPDUAddressInformation())
	if err != nil {
		return fmt.Errorf("could not get UE IP from NAS PDU Address Information: %v", err)
	}

	if ueIP.String() != opts.UeIP.String() {
		return fmt.Errorf("unexpected UE IP: %s, expected: %s", ueIP, opts.UeIP)
	}

	qosRulesBytes := msg.GetQosRule()

	qosRules, err := utils.UnmarshalQosRules(qosRulesBytes)
	if err != nil {
		return fmt.Errorf("could not unmarshal QoS Rules: %v", err)
	}

	if len(qosRules) != 1 {
		return fmt.Errorf("unexpected number of QoS Rules: %d", len(qosRules))
	}

	qosRule := qosRules[0]
	if qosRule.QFI != opts.Qfi {
		return fmt.Errorf("unexpected QoS Rules Identifier: %d, expected: %d", qosRule.QFI, opts.Qfi)
	}

	qosFlowDescs, err := utils.ParseAuthorizedQosFlowDescriptions(msg.GetQoSFlowDescriptions())
	if err != nil {
		return fmt.Errorf("could not parse AuthorizedQosFlowDescriptions: %v", err)
	}

	if len(qosFlowDescs) != 1 {
		return fmt.Errorf("unexpected number of AuthorizedQosFlowDescriptions: %d", len(qosFlowDescs))
	}

	qosFlowDesc := qosFlowDescs[0]

	if qosFlowDesc.Qfi != opts.Qfi {
		return fmt.Errorf("unexpected AuthorizedQosFlowDescriptions QFI: %d", qosFlowDesc.Qfi)
	}

	if len(qosFlowDesc.ParamList) != 1 {
		return fmt.Errorf("unexpected number of AuthorizedQosFlowDescriptions Parameters: %d, expected: 1", len(qosFlowDesc.ParamList))
	}

	// check FiveQI
	if qosFlowDesc.ParamList[0].ParamID != utils.QFDParamID5QI {
		return fmt.Errorf("unexpected AuthorizedQosFlowDescriptions Parameter Type: %d, expected: %d", qosFlowDesc.ParamList[0].ParamID, utils.QFDParamID5QI)
	}

	fiveQI := qosFlowDesc.ParamList[0].FiveQI
	// if fiveQI != &opts.FiveQI {
	// 	return fmt.Errorf("unexpected AuthorizedQosFlowDescriptions FiveQI: %d, expected: %d", *fiveQI, opts.FiveQI)
	// }
	if ptrToVal(fiveQI) != opts.FiveQI {
		return fmt.Errorf("unexpected AuthorizedQosFlowDescriptions FiveQI: %d, expected: %d", ptrToVal(fiveQI), opts.FiveQI)
	}

	dnn := msg.GetDNN()
	if dnn != opts.Dnn {
		return fmt.Errorf("unexpected DNN: %s", dnn)
	}

	sst := msg.GetSST()

	sd := msg.GetSD()

	if sst != opts.Sst {
		return fmt.Errorf("unexpected SNSSAI SST: %d", sst)
	}

	sdStr := sdFromNAS(sd)
	if sdStr != opts.Sd {
		return fmt.Errorf("unexpected SNSSAI SD: %s", sdStr)
	}

	return nil
}

func getNasPduFromPduAccept(dlNas *nas.Message) (*nas.Message, error) {
	payload := dlNas.DLNASTransport.GetPayloadContainerContents()
	m := new(nas.Message)

	err := m.PlainNasDecode(&payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NAS PDU: %v", err)
	}

	return m, nil
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

func ueIPFromNAS(ip [12]uint8) (*net.IP, error) {
	ueIPString := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])

	ueIP := net.ParseIP(ueIPString)
	if ueIP == nil {
		return nil, fmt.Errorf("could not parse UE IP: %s", ueIPString)
	}

	return &ueIP, nil
}

func sdFromNAS(sd [3]uint8) string {
	return fmt.Sprintf("%x%x%x", sd[0], sd[1], sd[2])
}

func ptrToVal(p *uint8) uint8 {
	if p == nil {
		return 0
	}

	return *p
}
