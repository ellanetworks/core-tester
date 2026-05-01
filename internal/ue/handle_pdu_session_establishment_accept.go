package ue

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/nas/nasMessage"
	"go.uber.org/zap"
)

func handlePDUSessionEstablishmentAccept(ue *UE, msg *nasMessage.PDUSessionEstablishmentAccept) error {
	addrInfo := msg.GetPDUAddressInformation()

	pduSessionType := msg.SelectedSSCModeAndSelectedPDUSessionType.Octet & 0x07

	logger.UeLogger.Debug(
		"Received PDU Session Establishment Accept NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.Uint8("PDU Session ID", msg.GetPDUSessionID()),
		zap.Uint8("PTI", msg.GetPTI()),
		zap.Uint8("Extended Protocol Discriminator", msg.GetExtendedProtocolDiscriminator()),
		zap.Uint8("Message Identity", msg.GetMessageType()),
		zap.Any("PDU Address Raw", addrInfo),
		zap.Any("PDU Address Raw Hex", fmt.Sprintf("%#x", addrInfo)),
		zap.Uint8("PDU Session Type (from SSC octet)", pduSessionType),
	)

	if msg.PDUAddress != nil {
		logger.UeLogger.Debug(
			"PDU Address IE details",
			zap.Uint8("IEI", msg.PDUAddress.GetIei()),
			zap.Uint8("Length", msg.PDUAddress.GetLen()),                                 //nolint:staticcheck // PDUAddress is a pointer field, not embedded
			zap.Uint8("PDU Session Type Value", msg.PDUAddress.GetPDUSessionTypeValue()), //nolint:staticcheck // PDUAddress is a pointer field, not embedded
			zap.Any("Octets", msg.PDUAddress.Octet[:msg.PDUAddress.GetLen()]),
			zap.Any("Octets Hex", fmt.Sprintf("%#x", msg.PDUAddress.Octet[:msg.PDUAddress.GetLen()])),
		)
	}

	if msg.SelectedSSCModeAndSelectedPDUSessionType.Octet != 0 {
		logger.UeLogger.Debug(
			"SSC Mode and PDU Session Type",
			zap.Uint8("Octet", msg.SelectedSSCModeAndSelectedPDUSessionType.Octet),
			zap.Uint8("SSC Mode", msg.SelectedSSCModeAndSelectedPDUSessionType.Octet>>3),
			zap.Uint8("PDU Session Type", pduSessionType),
		)
	}

	if msg.AuthorizedQosRules.Len != 0 {
		logger.UeLogger.Debug(
			"Authorized QoS Rules",
			zap.Uint16("Length", msg.AuthorizedQosRules.GetLen()),
			zap.Any("Buffer", msg.AuthorizedQosRules.Buffer[:msg.AuthorizedQosRules.GetLen()]),
			zap.Any("Buffer Hex", fmt.Sprintf("%#x", msg.AuthorizedQosRules.Buffer[:msg.AuthorizedQosRules.GetLen()])),
		)
	}

	if msg.SessionAMBR.GetLen() != 0 {
		logger.UeLogger.Debug(
			"Session AMBR",
			zap.Uint8("Length", msg.SessionAMBR.GetLen()),
			zap.Any("Octets", msg.SessionAMBR.Octet[:msg.SessionAMBR.GetLen()]),
			zap.Any("Octets Hex", fmt.Sprintf("%#x", msg.SessionAMBR.Octet[:msg.SessionAMBR.GetLen()])),
		)
	}

	if msg.Cause5GSM != nil {
		logger.UeLogger.Debug(
			"Cause 5GSM",
			zap.Uint8("IEI", msg.Cause5GSM.GetIei()),
			zap.Any("Octet", msg.Cause5GSM.Octet),
		)
	}

	if msg.RQTimerValue != nil {
		logger.UeLogger.Debug(
			"RQ Timer Value",
			zap.Uint8("IEI", msg.RQTimerValue.GetIei()),
			zap.Any("Octet", msg.RQTimerValue.Octet),
		)
	}

	if msg.SNSSAI != nil {
		logger.UeLogger.Debug(
			"SNSSAI",
			zap.Uint8("IEI", msg.SNSSAI.GetIei()),
			zap.Uint8("Length", msg.SNSSAI.GetLen()),
			zap.Any("Octets", msg.SNSSAI.Octet[:msg.SNSSAI.GetLen()]),
			zap.Any("Octets Hex", fmt.Sprintf("%#x", msg.SNSSAI.Octet[:msg.SNSSAI.GetLen()])),
		)
	}

	if msg.AlwaysonPDUSessionIndication != nil {
		logger.UeLogger.Debug(
			"Always-on PDU Session Indication",
			zap.Uint8("IEI", msg.AlwaysonPDUSessionIndication.GetIei()),
			zap.Any("Octet", msg.AlwaysonPDUSessionIndication.Octet),
		)
	}

	if msg.MappedEPSBearerContexts != nil {
		logger.UeLogger.Debug(
			"Mapped EPS Bearer Contexts",
			zap.Uint8("IEI", msg.MappedEPSBearerContexts.GetIei()),
			zap.Any("Mapped EPS Bearer Context", msg.MappedEPSBearerContexts.GetMappedEPSBearerContext()), //nolint:staticcheck // MappedEPSBearerContexts is a pointer field, not embedded
		)
	}

	if msg.EAPMessage != nil {
		logger.UeLogger.Debug(
			"EAP Message",
			zap.Uint8("IEI", msg.EAPMessage.GetIei()),
			zap.Any("EAP Message", msg.EAPMessage.GetEAPMessage()), //nolint:staticcheck // EAPMessage is a pointer field, not embedded
		)
	}

	if msg.DNN != nil {
		logger.UeLogger.Debug(
			"DNN",
			zap.Uint8("IEI", msg.DNN.GetIei()),
			zap.String("DNN", msg.DNN.GetDNN()), //nolint:staticcheck // DNN is a pointer field, not embedded
		)
	}

	pcoContents := msg.GetExtendedProtocolConfigurationOptionsContents()
	if len(pcoContents) > 0 {
		logger.UeLogger.Debug(
			"Extended Protocol Configuration Options",
			zap.Any("PCO Contents", pcoContents),
			zap.Any("PCO Contents Hex", fmt.Sprintf("%#x", pcoContents)),
		)
	}

	qosFlowDescsRaw := msg.GetQoSFlowDescriptions()
	if len(qosFlowDescsRaw) > 0 {
		logger.UeLogger.Debug(
			"QoS Flow Descriptions (raw)",
			zap.Any("QoS Flow Descriptions", qosFlowDescsRaw),
			zap.Any("QoS Flow Descriptions Hex", fmt.Sprintf("%#x", qosFlowDescsRaw)),
		)
	}

	pduAddr, err := parsePduAddressInformation(addrInfo, pduSessionType)
	if err != nil {
		return fmt.Errorf("could not parse PDU address from NAS: %v", err)
	}

	mtu, err := mtuFromExtendProtocolConfigurationOptionsContents(pcoContents)
	if err != nil {
		return fmt.Errorf("could not get MTU from Extended Protocol Configuration Options: %v", err)
	}

	qosFlowDescs, err := parseAuthorizedQosFlowDescriptions(qosFlowDescsRaw)
	if err != nil {
		return fmt.Errorf("could not parse AuthorizedQosFlowDescriptions: %v", err)
	}

	if len(qosFlowDescs) < 1 {
		return fmt.Errorf("not enough AuthorizedQosFlowDescriptions: %v", err)
	}

	qfi := qosFlowDescs[0].Qfi

	var ipStr string

	if pduAddr.IP.IsValid() {
		ipStr = pduAddr.IP.String()
	}

	if pduAddr.IPV6.IsValid() {
		if ipStr != "" {
			ipStr += ", " + pduAddr.IPV6.String()
		} else {
			ipStr = pduAddr.IPV6.String()
		}
	}

	logger.UeLogger.Debug(
		"Parsed PDU Session info",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.Uint8("PDU Session ID", msg.GetPDUSessionID()),
		zap.String("UE IP", ipStr),
		zap.Uint16("MTU", mtu),
		zap.Uint8("QFI", qfi),
		zap.Uint8("PDU Session Type", pduAddr.PDUSessionType),
	)

	ue.SetPDUSession(PDUSessionInfo{
		PDUSessionID:      msg.GetPDUSessionID(),
		UEIP:              pduAddr.IP.String(),
		UEIPV6:            pduAddr.IPV6.String(),
		MTU:               mtu,
		QFI:               qfi,
		PDUSessionVersion: pduAddr.PDUSessionType,
	})

	return nil
}
