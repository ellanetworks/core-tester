package validate

import (
	"fmt"
	"net/netip"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/free5gc/nas"
)

type ExpectedPDUSessionEstablishmentAccept struct {
	PDUSessionID uint8
	UeIPSubnet   netip.Prefix
	Dnn          string
	Sst          int32
	Sd           string
	Qfi          uint8
	FiveQI       uint8
}

func PDUSessionEstablishmentAccept(nasMsg *nas.Message, opts *ExpectedPDUSessionEstablishmentAccept) error {
	msg := nasMsg.GsmHeader.GetMessageType()
	if msg != nas.MsgTypePDUSessionEstablishmentAccept {
		return fmt.Errorf("PDU Session Establishment Accept message type is not correct, expected: %d, got: %d", nas.MsgTypePDUSessionEstablishmentAccept, msg)
	}

	if reflect.ValueOf(nasMsg.PDUSessionEstablishmentAccept.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol discriminator is missing")
	}

	if nasMsg.PDUSessionEstablishmentAccept.GetExtendedProtocolDiscriminator() != 46 {
		return fmt.Errorf("extended protocol discriminator not expected value")
	}

	if reflect.ValueOf(nasMsg.PDUSessionEstablishmentAccept.PDUSessionID).IsZero() {
		return fmt.Errorf("pdu session id is missing or not expected value")
	}

	if reflect.ValueOf(nasMsg.PDUSessionEstablishmentAccept.PTI).IsZero() {
		return fmt.Errorf("pti is missing")
	}

	if nasMsg.PDUSessionEstablishmentAccept.GetPTI() != 1 {
		return fmt.Errorf("pti not expected value")
	}

	if nasMsg.PDUSessionEstablishmentAccept.GetMessageType() != nas.MsgTypePDUSessionEstablishmentAccept {
		return fmt.Errorf("message type is missing or not expected value, got: %d, expected: %d", nasMsg.PDUSessionEstablishmentAccept.GetMessageType(), nas.MsgTypePDUSessionEstablishmentAccept)
	}

	if reflect.ValueOf(nasMsg.PDUSessionEstablishmentAccept.SelectedSSCModeAndSelectedPDUSessionType).IsZero() {
		return fmt.Errorf("ssc mode or pdu session type is missing")
	}

	if nasMsg.GetPDUSessionType() != 1 {
		return fmt.Errorf("pdu session type not expected value")
	}

	if reflect.ValueOf(nasMsg.PDUSessionEstablishmentAccept.AuthorizedQosRules).IsZero() {
		return fmt.Errorf("authorized qos rules is missing")
	}

	if reflect.ValueOf(nasMsg.PDUSessionEstablishmentAccept.SessionAMBR).IsZero() {
		return fmt.Errorf("session ambr is missing")
	}

	pduSessionId := nasMsg.PDUSessionEstablishmentAccept.GetPDUSessionID()
	if pduSessionId != opts.PDUSessionID {
		return fmt.Errorf("unexpected PDUSessionID: %d", pduSessionId)
	}

	ueIP, err := utils.UEIPFromNAS(nasMsg.GetPDUAddressInformation())
	if err != nil {
		return fmt.Errorf("could not get UE IP from NAS PDU Address Information: %v", err)
	}

	if !opts.UeIPSubnet.Contains(ueIP) {
		return fmt.Errorf("UE IP %s is not contained in expected subnet %s", ueIP.String(), opts.UeIPSubnet.String())
	}

	qosRulesBytes := nasMsg.PDUSessionEstablishmentAccept.GetQosRule()

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

	qosFlowDescs, err := utils.ParseAuthorizedQosFlowDescriptions(nasMsg.PDUSessionEstablishmentAccept.GetQoSFlowDescriptions())
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

	if ptrToVal(fiveQI) != opts.FiveQI {
		return fmt.Errorf("unexpected AuthorizedQosFlowDescriptions FiveQI: %d, expected: %d", ptrToVal(fiveQI), opts.FiveQI)
	}

	dnn := nasMsg.PDUSessionEstablishmentAccept.GetDNN()
	if dnn != opts.Dnn {
		return fmt.Errorf("unexpected DNN: %s", dnn)
	}

	sst := nasMsg.PDUSessionEstablishmentAccept.GetSST()

	sd := nasMsg.PDUSessionEstablishmentAccept.GetSD()

	if sst != uint8(opts.Sst) {
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
