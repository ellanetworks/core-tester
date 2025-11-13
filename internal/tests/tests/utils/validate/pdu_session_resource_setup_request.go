package validate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/aper"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type PDUSessionResourceSetupRequestOpts struct {
	Frame                                 gnb.SCTPFrame
	ExpectedPDUSessionID                  uint8
	ExpectedSST                           int32
	ExpectedSD                            string
	UEIns                                 *ue.UE
	ExpectedPDUSessionEstablishmentAccept *ExpectedPDUSessionEstablishmentAccept
}

type PDUSessionResourceSetupRequestResult struct {
	PDUSessionResourceSetupListValue *PDUSessionResourceSetupListValue
}

func PDUSessionResourceSetupRequest(opts *PDUSessionResourceSetupRequestOpts) (*PDUSessionResourceSetupRequestResult, error) {
	err := utils.ValidateSCTP(opts.Frame.Info, 60, 1)
	if err != nil {
		return nil, fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(opts.Frame.Data)
	if err != nil {
		return nil, fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return nil, fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodePDUSessionResourceSetup {
		return nil, fmt.Errorf("NGAP PDU is not a PDUSessionResourceSetupRequest")
	}

	pDUSessionResourceSetupRequest := pdu.InitiatingMessage.Value.PDUSessionResourceSetupRequest
	if pDUSessionResourceSetupRequest == nil {
		return nil, fmt.Errorf("PDUSessionResourceSetupRequest is nil")
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
			return nil, fmt.Errorf("PDUSessionResourceSetupRequest IE ID (%d) not supported", ie.Id.Value)
		}
	}

	if amfueNGAPID == nil {
		return nil, fmt.Errorf("AMFUENGAPID is missing in PDUSessionResourceSetupRequest")
	}

	if ranueNGAPID == nil {
		return nil, fmt.Errorf("RANUENGAPID is missing in PDUSessionResourceSetupRequest")
	}

	if protocolIEIDPDUSessionResourceSetupListSUReq == nil {
		return nil, fmt.Errorf("PDUSessionResourceSetupListSUReq is missing in PDUSessionResourceSetupRequest")
	}

	if protocolIEIDUEAggregateMaximumBitRate == nil {
		return nil, fmt.Errorf("UEAggregateMaximumBitRate is missing in PDUSessionResourceSetupRequest")
	}

	resp, err := pduSessionResourceSetupListSUReq(protocolIEIDPDUSessionResourceSetupListSUReq, opts.ExpectedPDUSessionID, opts.ExpectedSST, opts.ExpectedSD, opts.UEIns, opts.ExpectedPDUSessionEstablishmentAccept)
	if err != nil {
		return nil, fmt.Errorf("PDUSessionResourceSetupListSUReq validation failed: %v", err)
	}

	return &PDUSessionResourceSetupRequestResult{
		PDUSessionResourceSetupListValue: resp,
	}, nil
}

type PDUSessionResourceSetupListValue struct {
	UEIP                                   *netip.Addr
	PDUSessionResourceSetupRequestTransfer *PDUSessionResourceSetupRequestTransfer
}

func pduSessionResourceSetupListSUReq(
	pDUSessionResourceSetupListSUReq *ngapType.PDUSessionResourceSetupListSUReq,
	expectedPDUSessionID uint8,
	expectedSST int32,
	expectedSD string,
	ueIns *ue.UE,
	expectedPDUSessionEstablishmentAccept *ExpectedPDUSessionEstablishmentAccept,
) (*PDUSessionResourceSetupListValue, error) {
	if len(pDUSessionResourceSetupListSUReq.List) != 1 {
		return nil, fmt.Errorf("PDUSessionResourceSetupListSUReq should have exactly one item, got: %d", len(pDUSessionResourceSetupListSUReq.List))
	}

	item := pDUSessionResourceSetupListSUReq.List[0]
	if item.PDUSessionID.Value != int64(expectedPDUSessionID) {
		return nil, fmt.Errorf("unexpected PDUSessionID: %d", item.PDUSessionID.Value)
	}

	expectedSSTBytes, expectedSDBytes, err := gnb.GetSliceInBytes(expectedSST, expectedSD)
	if err != nil {
		return nil, fmt.Errorf("could not convert expected SST and SD to byte slices: %v", err)
	}

	if !bytes.Equal(item.SNSSAI.SST.Value, expectedSSTBytes) {
		return nil, fmt.Errorf("unexpected SNSSAI SST: %x, expected: %x", item.SNSSAI.SST.Value, expectedSSTBytes)
	}

	if !bytes.Equal(item.SNSSAI.SD.Value, expectedSDBytes) {
		return nil, fmt.Errorf("unexpected SNSSAI SD: %x, expected: %x", item.SNSSAI.SD.Value, expectedSDBytes)
	}

	if item.PDUSessionNASPDU == nil {
		return nil, fmt.Errorf("PDUSessionNASPDU is nil")
	}

	msg, err := ueIns.DecodeNAS(item.PDUSessionNASPDU.Value)
	if err != nil {
		return nil, fmt.Errorf("could not decode PDU Session NAS PDU: %v", err)
	}

	if msg.GmmMessage == nil {
		return nil, fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeDLNASTransport {
		return nil, fmt.Errorf("NAS message type is not DLNASTransport (%d), got (%d)", nas.MsgTypeDLNASTransport, msg.GmmMessage.GetMessageType())
	}

	if msg.DLNASTransport == nil {
		return nil, fmt.Errorf("NAS DLNASTransport message is nil")
	}

	if reflect.ValueOf(msg.DLNASTransport.ExtendedProtocolDiscriminator).IsZero() {
		return nil, fmt.Errorf("extended protocol is missing")
	}

	if msg.DLNASTransport.GetExtendedProtocolDiscriminator() != 126 {
		return nil, fmt.Errorf("extended protocol not the expected value")
	}

	if msg.DLNASTransport.GetSpareHalfOctet() != 0 {
		return nil, fmt.Errorf("spare half not expected value")
	}

	if msg.DLNASTransport.GetSecurityHeaderType() != 0 {
		return nil, fmt.Errorf("security header not expected value")
	}

	if reflect.ValueOf(msg.DLNASTransport.SpareHalfOctetAndPayloadContainerType).IsZero() {
		return nil, fmt.Errorf("payload container type is missing")
	}

	if msg.DLNASTransport.GetPayloadContainerType() != 1 {
		return nil, fmt.Errorf("payload container type not expected value")
	}

	if reflect.ValueOf(msg.DLNASTransport.PayloadContainer).IsZero() || msg.DLNASTransport.GetPayloadContainerContents() == nil {
		return nil, fmt.Errorf("payload container is missing")
	}

	if reflect.ValueOf(msg.DLNASTransport.PduSessionID2Value).IsZero() {
		return nil, fmt.Errorf("pdu session id is missing")
	}

	if msg.DLNASTransport.PduSessionID2Value.GetIei() != 18 {
		return nil, fmt.Errorf("pdu session id not expected value")
	}

	payloadContainer, err := utils.GetNasPduFromPduAccept(msg)
	if err != nil {
		return nil, fmt.Errorf("could not get PDU Session establishment accept: %v", err)
	}

	pcMsgType := payloadContainer.GsmHeader.GetMessageType()
	if pcMsgType != nas.MsgTypePDUSessionEstablishmentAccept {
		return nil, fmt.Errorf("PDU Session Establishment Accept message type is not correct, expected: %d, got: %d", nas.MsgTypePDUSessionEstablishmentAccept, pcMsgType)
	}

	ueIP, err := pduSessionEstablishmentAccept(payloadContainer.PDUSessionEstablishmentAccept, expectedPDUSessionEstablishmentAccept)
	if err != nil {
		return nil, fmt.Errorf("could not validate PDU Session Establishment Accept: %v", err)
	}

	pduSessionResourceSetupTransfer, err := pduSessionResourceSetupTransfer(item.PDUSessionResourceSetupRequestTransfer)
	if err != nil {
		return nil, fmt.Errorf("could not validate PDU Session Resource Setup Transfer: %v", err)
	}

	resp := &PDUSessionResourceSetupListValue{
		UEIP:                                   ueIP,
		PDUSessionResourceSetupRequestTransfer: pduSessionResourceSetupTransfer,
	}

	return resp, nil
}

type PDUSessionResourceSetupRequestTransfer struct {
	ULTeid     uint32
	UpfAddress string
	QosId      int64
	FiveQi     int64
	PriArp     int64
	PduSType   uint64
}

func pduSessionResourceSetupTransfer(transfer aper.OctetString) (*PDUSessionResourceSetupRequestTransfer, error) {
	if transfer == nil {
		return nil, fmt.Errorf("PDU Session Resource Setup Request Transfer is missing")
	}

	pdu := &ngapType.PDUSessionResourceSetupRequestTransfer{}

	err := aper.UnmarshalWithParams(transfer, pdu, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal Pdu Session Resource Setup Request Transfer: %v", err)
	}

	var (
		ulTeid     uint32
		upfAddress []byte
		qosId      int64
		fiveQi     int64
		priArp     int64
		pduSType   uint64
	)

	for _, ies := range pdu.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDULNGUUPTNLInformation:
			ulTeid = binary.BigEndian.Uint32(ies.Value.ULNGUUPTNLInformation.GTPTunnel.GTPTEID.Value)
			upfAddress = ies.Value.ULNGUUPTNLInformation.GTPTunnel.TransportLayerAddress.Value.Bytes

		case ngapType.ProtocolIEIDQosFlowSetupRequestList:
			for _, itemsQos := range ies.Value.QosFlowSetupRequestList.List {
				qosId = itemsQos.QosFlowIdentifier.Value
				fiveQi = itemsQos.QosFlowLevelQosParameters.QosCharacteristics.NonDynamic5QI.FiveQI.Value
				priArp = itemsQos.QosFlowLevelQosParameters.AllocationAndRetentionPriority.PriorityLevelARP.Value
			}

		case ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate:

		case ngapType.ProtocolIEIDPDUSessionType:
			pduSType = uint64(ies.Value.PDUSessionType.Value)

		case ngapType.ProtocolIEIDSecurityIndication:
		}
	}

	upfIp := fmt.Sprintf("%d.%d.%d.%d", upfAddress[0], upfAddress[1], upfAddress[2], upfAddress[3])

	return &PDUSessionResourceSetupRequestTransfer{
		ULTeid:     ulTeid,
		UpfAddress: upfIp,
		QosId:      qosId,
		FiveQi:     fiveQi,
		PriArp:     priArp,
		PduSType:   pduSType,
	}, nil
}

type ExpectedPDUSessionEstablishmentAccept struct {
	PDUSessionID uint8
	UeIPSubnet   netip.Prefix
	Dnn          string
	Sst          int32
	Sd           string
	Qfi          uint8
	FiveQI       uint8
}

func pduSessionEstablishmentAccept(msg *nasMessage.PDUSessionEstablishmentAccept, opts *ExpectedPDUSessionEstablishmentAccept) (*netip.Addr, error) {
	// check the mandatory fields
	if reflect.ValueOf(msg.ExtendedProtocolDiscriminator).IsZero() {
		return nil, fmt.Errorf("extended protocol discriminator is missing")
	}

	if msg.GetExtendedProtocolDiscriminator() != 46 {
		return nil, fmt.Errorf("extended protocol discriminator not expected value")
	}

	if reflect.ValueOf(msg.PDUSessionID).IsZero() {
		return nil, fmt.Errorf("pdu session id is missing or not expected value")
	}

	if reflect.ValueOf(msg.PTI).IsZero() {
		return nil, fmt.Errorf("pti is missing")
	}

	if msg.GetPTI() != 1 {
		return nil, fmt.Errorf("pti not expected value")
	}

	if msg.GetMessageType() != nas.MsgTypePDUSessionEstablishmentAccept {
		return nil, fmt.Errorf("message type is missing or not expected value, got: %d, expected: %d", msg.GetMessageType(), nas.MsgTypePDUSessionEstablishmentAccept)
	}

	if reflect.ValueOf(msg.SelectedSSCModeAndSelectedPDUSessionType).IsZero() {
		return nil, fmt.Errorf("ssc mode or pdu session type is missing")
	}

	if msg.GetPDUSessionType() != 1 {
		return nil, fmt.Errorf("pdu session type not expected value")
	}

	if reflect.ValueOf(msg.AuthorizedQosRules).IsZero() {
		return nil, fmt.Errorf("authorized qos rules is missing")
	}

	if reflect.ValueOf(msg.SessionAMBR).IsZero() {
		return nil, fmt.Errorf("session ambr is missing")
	}

	pduSessionId := msg.GetPDUSessionID()
	if pduSessionId != opts.PDUSessionID {
		return nil, fmt.Errorf("unexpected PDUSessionID: %d", pduSessionId)
	}

	ueIP, err := utils.UEIPFromNAS(msg.GetPDUAddressInformation())
	if err != nil {
		return nil, fmt.Errorf("could not get UE IP from NAS PDU Address Information: %v", err)
	}

	if !opts.UeIPSubnet.Contains(ueIP) {
		return nil, fmt.Errorf("UE IP %s is not contained in expected subnet %s", ueIP.String(), opts.UeIPSubnet.String())
	}

	qosRulesBytes := msg.GetQosRule()

	qosRules, err := utils.UnmarshalQosRules(qosRulesBytes)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal QoS Rules: %v", err)
	}

	if len(qosRules) != 1 {
		return nil, fmt.Errorf("unexpected number of QoS Rules: %d", len(qosRules))
	}

	qosRule := qosRules[0]
	if qosRule.QFI != opts.Qfi {
		return nil, fmt.Errorf("unexpected QoS Rules Identifier: %d, expected: %d", qosRule.QFI, opts.Qfi)
	}

	qosFlowDescs, err := utils.ParseAuthorizedQosFlowDescriptions(msg.GetQoSFlowDescriptions())
	if err != nil {
		return nil, fmt.Errorf("could not parse AuthorizedQosFlowDescriptions: %v", err)
	}

	if len(qosFlowDescs) != 1 {
		return nil, fmt.Errorf("unexpected number of AuthorizedQosFlowDescriptions: %d", len(qosFlowDescs))
	}

	qosFlowDesc := qosFlowDescs[0]

	if qosFlowDesc.Qfi != opts.Qfi {
		return nil, fmt.Errorf("unexpected AuthorizedQosFlowDescriptions QFI: %d", qosFlowDesc.Qfi)
	}

	if len(qosFlowDesc.ParamList) != 1 {
		return nil, fmt.Errorf("unexpected number of AuthorizedQosFlowDescriptions Parameters: %d, expected: 1", len(qosFlowDesc.ParamList))
	}

	// check FiveQI
	if qosFlowDesc.ParamList[0].ParamID != utils.QFDParamID5QI {
		return nil, fmt.Errorf("unexpected AuthorizedQosFlowDescriptions Parameter Type: %d, expected: %d", qosFlowDesc.ParamList[0].ParamID, utils.QFDParamID5QI)
	}

	fiveQI := qosFlowDesc.ParamList[0].FiveQI

	if ptrToVal(fiveQI) != opts.FiveQI {
		return nil, fmt.Errorf("unexpected AuthorizedQosFlowDescriptions FiveQI: %d, expected: %d", ptrToVal(fiveQI), opts.FiveQI)
	}

	dnn := msg.GetDNN()
	if dnn != opts.Dnn {
		return nil, fmt.Errorf("unexpected DNN: %s", dnn)
	}

	sst := msg.GetSST()

	sd := msg.GetSD()

	if sst != uint8(opts.Sst) {
		return nil, fmt.Errorf("unexpected SNSSAI SST: %d", sst)
	}

	sdStr := utils.SDFromNAS(sd)
	if sdStr != opts.Sd {
		return nil, fmt.Errorf("unexpected SNSSAI SD: %s", sdStr)
	}

	return &ueIP, nil
}

func ptrToVal(p *uint8) uint8 {
	if p == nil {
		return 0
	}

	return *p
}
