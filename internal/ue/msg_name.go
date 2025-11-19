package ue

import "github.com/free5gc/nas"

func getMessageName(msgType uint8) string {
	switch msgType {
	case nas.MsgTypePDUSessionEstablishmentRequest:
		return "PDU Session Establishment Request"
	case nas.MsgTypePDUSessionEstablishmentAccept:
		return "PDU Session Establishment Accept"
	case nas.MsgTypePDUSessionEstablishmentReject:
		return "PDU Session Establishment Reject"
	case nas.MsgTypePDUSessionAuthenticationCommand:
		return "PDU Session Authentication Command"
	case nas.MsgTypePDUSessionAuthenticationComplete:
		return "PDU Session Authentication Complete"
	case nas.MsgTypePDUSessionAuthenticationResult:
		return "PDU Session Authentication Result"
	case nas.MsgTypePDUSessionModificationRequest:
		return "PDU Session Modification Request"
	case nas.MsgTypePDUSessionModificationReject:
		return "PDU Session Modification Reject"
	case nas.MsgTypePDUSessionModificationCommand:
		return "PDU Session Modification Command"
	case nas.MsgTypePDUSessionModificationComplete:
		return "PDU Session Modification Complete"
	case nas.MsgTypePDUSessionModificationCommandReject:
		return "PDU Session Modification Command Reject"
	case nas.MsgTypePDUSessionReleaseRequest:
		return "PDU Session Release Request"
	case nas.MsgTypePDUSessionReleaseReject:
		return "PDU Session Release Reject"
	case nas.MsgTypePDUSessionReleaseCommand:
		return "PDU Session Release Command"
	case nas.MsgTypePDUSessionReleaseComplete:
		return "PDU Session Release Complete"
	case nas.MsgTypeStatus5GSM:
		return "5GSM Status"
	default:
		return "Unknown Message Type"
	}
}
