package validate

import (
	"bytes"
	"fmt"
	"net"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func PDUSessionResourceSetupRequest(
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

	expectedSSTBytes, expectedSDBytes, err := gnb.GetSliceInBytes(expectedSST, expectedSD)
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

	payloadContainer, err := utils.GetNasPduFromPduAccept(msg)
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

	ueIP, err := utils.UEIPFromNAS(msg.GetPDUAddressInformation())
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

	sdStr := utils.SDFromNAS(sd)
	if sdStr != opts.Sd {
		return fmt.Errorf("unexpected SNSSAI SD: %s", sdStr)
	}

	return nil
}

func ptrToVal(p *uint8) uint8 {
	if p == nil {
		return 0
	}

	return *p
}
