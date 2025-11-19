package ue

import (
	"fmt"

	"github.com/free5gc/nas/nasMessage"
)

const (
	Cause5GMMIllegalUE                                      uint8 = 0x03
	Cause5GMMPEINotAccepted                                 uint8 = 0x05
	Cause5GMMIllegalME                                      uint8 = 0x06
	Cause5GMM5GSServicesNotAllowed                          uint8 = 0x07
	Cause5GMMUEIdentityCannotBeDerivedByTheNetwork          uint8 = 0x09
	Cause5GMMImplicitlyDeregistered                         uint8 = 0x0a
	Cause5GMMPLMNNotAllowed                                 uint8 = 0x0b
	Cause5GMMTrackingAreaNotAllowed                         uint8 = 0x0c
	Cause5GMMRoamingNotAllowedInThisTrackingArea            uint8 = 0x0d
	Cause5GMMNoSuitableCellsInTrackingArea                  uint8 = 0x0f
	Cause5GMMMACFailure                                     uint8 = 0x14
	Cause5GMMSynchFailure                                   uint8 = 0x15
	Cause5GMMCongestion                                     uint8 = 0x16
	Cause5GMMUESecurityCapabilitiesMismatch                 uint8 = 0x17
	Cause5GMMSecurityModeRejectedUnspecified                uint8 = 0x18
	Cause5GMMNon5GAuthenticationUnacceptable                uint8 = 0x1a
	Cause5GMMN1ModeNotAllowed                               uint8 = 0x1b
	Cause5GMMRestrictedServiceArea                          uint8 = 0x1c
	Cause5GMMLADNNotAvailable                               uint8 = 0x2b
	Cause5GMMMaximumNumberOfPDUSessionsReached              uint8 = 0x41
	Cause5GMMInsufficientResourcesForSpecificSliceAndDNN    uint8 = 0x43
	Cause5GMMInsufficientResourcesForSpecificSlice          uint8 = 0x45
	Cause5GMMngKSIAlreadyInUse                              uint8 = 0x47
	Cause5GMMNon3GPPAccessTo5GCNNotAllowed                  uint8 = 0x48
	Cause5GMMServingNetworkNotAuthorized                    uint8 = 0x49
	Cause5GMMPayloadWasNotForwarded                         uint8 = 0x5a
	Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice       uint8 = 0x5b
	Cause5GMMInsufficientUserPlaneResourcesForThePDUSession uint8 = 0x5c
	Cause5GMMSemanticallyIncorrectMessage                   uint8 = 0x5f
	Cause5GMMInvalidMandatoryInformation                    uint8 = 0x60
	Cause5GMMMessageTypeNonExistentOrNotImplemented         uint8 = 0x61
	Cause5GMMMessageTypeNotCompatibleWithTheProtocolState   uint8 = 0x62
	Cause5GMMInformationElementNonExistentOrNotImplemented  uint8 = 0x63
	Cause5GMMConditionalIEError                             uint8 = 0x64
	Cause5GMMMessageNotCompatibleWithTheProtocolState       uint8 = 0x65
	Cause5GMMProtocolErrorUnspecified                       uint8 = 0x6f
)

func cause5GSMToString(cause uint8) string {
	switch cause {
	case nasMessage.Cause5GSMInsufficientResources:
		return "Insufficient Resources"
	case nasMessage.Cause5GSMMissingOrUnknownDNN:
		return "Missing Or Unknown DNN"
	case nasMessage.Cause5GSMUnknownPDUSessionType:
		return "Unknown PDU Session Type"
	case nasMessage.Cause5GSMUserAuthenticationOrAuthorizationFailed:
		return "User Authentication Or Authorization Failed"
	case nasMessage.Cause5GSMRequestRejectedUnspecified:
		return "Request Rejected Unspecified"
	case nasMessage.Cause5GSMServiceOptionTemporarilyOutOfOrder:
		return "Service Option Temporarily Out Of Order"
	case nasMessage.Cause5GSMPTIAlreadyInUse:
		return "PTI Already In Use"
	case nasMessage.Cause5GSMRegularDeactivation:
		return "Regular Deactivation"
	case nasMessage.Cause5GSMNetworkFailure:
		return "Network Failure"
	case nasMessage.Cause5GSMReactivationRequested:
		return "Reactivation Requested"
	case nasMessage.Cause5GSMInvalidPDUSessionIdentity:
		return "Invalid PDU Session Identity"
	case nasMessage.Cause5GSMSemanticErrorsInPacketFilter:
		return "Semantic Errors In Packet Filter"
	case nasMessage.Cause5GSMSyntacticalErrorInPacketFilter:
		return "Syntactical Error In Packet Filter"
	case nasMessage.Cause5GSMOutOfLADNServiceArea:
		return "Out Of LADN Service Area"
	case nasMessage.Cause5GSMPTIMismatch:
		return "PTI Mismatch"
	case nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed:
		return "PDU Session Type IPv4 Only Allowed"
	case nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed:
		return "PDU Session Type IPv6 Only Allowed"
	case nasMessage.Cause5GSMPDUSessionDoesNotExist:
		return "PDU Session Does Not Exist"
	case nasMessage.Cause5GSMInsufficientResourcesForSpecificSliceAndDNN:
		return "Insufficient Resources For Specific Slice And DNN"
	case nasMessage.Cause5GSMNotSupportedSSCMode:
		return "Not Supported SSC Mode"
	case nasMessage.Cause5GSMInsufficientResourcesForSpecificSlice:
		return "Insufficient Resources For Specific Slice"
	case nasMessage.Cause5GSMMissingOrUnknownDNNInASlice:
		return "Missing Or Unknown DNN In A Slice"
	case nasMessage.Cause5GSMInvalidPTIValue:
		return "Invalid PTI Value"
	case nasMessage.Cause5GSMMaximumDataRatePerUEForUserPlaneIntegrityProtectionIsTooLow:
		return "Maximum Data Rate Per UE For User Plane Integrity Protection Is Too Low"
	case nasMessage.Cause5GSMSemanticErrorInTheQoSOperation:
		return "Semantic Error In The QoS Operation"
	case nasMessage.Cause5GSMSyntacticalErrorInTheQoSOperation:
		return "Syntactical Error In The QoS Operation"
	case nasMessage.Cause5GSMInvalidMappedEPSBearerIdentity:
		return "Invalid Mapped EPS Bearer Identity"
	case nasMessage.Cause5GSMSemanticallyIncorrectMessage:
		return "Semantically Incorrect Message"
	case nasMessage.Cause5GSMInvalidMandatoryInformation:
		return "Invalid Mandatory Information"
	case nasMessage.Cause5GSMMessageTypeNonExistentOrNotImplemented:
		return "Message Type Non Existent Or Not Implemented"
	case nasMessage.Cause5GSMMessageTypeNotCompatibleWithTheProtocolState:
		return "Message Type Not Compatible With The Protocol State"
	case nasMessage.Cause5GSMInformationElementNonExistentOrNotImplemented:
		return "Information Element Non Existent Or Not Implemented"
	case nasMessage.Cause5GSMConditionalIEError:
		return "Conditional IE Error"
	case nasMessage.Cause5GSMMessageNotCompatibleWithTheProtocolState:
		return "Message Not Compatible With The Protocol State"
	case nasMessage.Cause5GSMProtocolErrorUnspecified:
		return "Protocol Error Unspecified"
	default:
		return fmt.Sprintf("Unknown Cause (%d)", cause)
	}
}
