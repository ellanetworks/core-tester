/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package nas

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/ellanetworks/core-tester/internal/ue/nas/handler"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
)

func DispatchNas(ue *context.UEContext, message []byte) error {
	var cph bool

	// check if message is null.
	if message == nil {
		return fmt.Errorf("nas message is nil")
	}

	// decode NAS message.
	m := new(nas.Message)
	m.SecurityHeaderType = nas.GetSecurityHeaderType(message) & 0x0f

	payload := make([]byte, len(message))
	copy(payload, message)

	newSecurityContext := false

	// check if NAS is security protected
	if m.SecurityHeaderType != nas.SecurityHeaderTypePlainNas {
		logger.UELog.Info("Message with security header")

		// information to check integrity and ciphered.

		// sequence number.
		sequenceNumber := message[6]

		// mac verification.
		macReceived := message[2:6]

		// remove security Header
		payload := payload[7:]

		// check security header type.
		cph = false
		switch m.SecurityHeaderType {
		case nas.SecurityHeaderTypeIntegrityProtected:
			logger.UELog.Info("Message with integrity")

		case nas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
			logger.UELog.Info("Message with integrity and ciphered")
			cph = true

		case nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
			logger.UELog.Info("Message with integrity and with NEW 5G NAS SECURITY CONTEXT")
			newSecurityContext = true

		case nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
			return fmt.Errorf("received message with security header \"Integrity protected and ciphered with new 5G NAS security context\", this is reserved for a SECURITY MODE COMPLETE and UE should not receive this code")
		}

		// check security header(Downlink data).
		if ue.UeSecurity.DLCount.SQN() > sequenceNumber {
			ue.UeSecurity.DLCount.SetOverflow(ue.UeSecurity.DLCount.Overflow() + 1)
		}
		ue.UeSecurity.DLCount.SetSQN(sequenceNumber)

		// check ciphering.
		if cph {
			if err := security.NASEncrypt(ue.UeSecurity.CipheringAlg, ue.UeSecurity.KnasEnc, ue.UeSecurity.DLCount.Get(), security.Bearer3GPP,
				security.DirectionDownlink, payload); err != nil {
				return fmt.Errorf("error in encrypt algorithm %v", err)
			} else {
				logger.UELog.Info("successful NAS CIPHERING")
			}
		}

		// decode NAS message.
		err := m.PlainNasDecode(&payload)
		if err != nil {
			logger.UELog.Error("decode NAS error", err)
		}

		if newSecurityContext {
			if m.GmmHeader.GetMessageType() == nas.MsgTypeSecurityModeCommand {
				ue.UeSecurity.DLCount.Set(0, 0)
				ue.UeSecurity.CipheringAlg = m.SecurityModeCommand.SelectedNASSecurityAlgorithms.GetTypeOfCipheringAlgorithm()
				ue.UeSecurity.IntegrityAlg = m.SecurityModeCommand.SelectedNASSecurityAlgorithms.GetTypeOfIntegrityProtectionAlgorithm()
				err := ue.DerivateAlgKey()
				if err != nil {
					return fmt.Errorf("error in DerivateAlgKey %v", err)
				}
			} else {
				return fmt.Errorf("received message with security header \"Integrity protected with new 5G NAS security context\", but message type is not SECURITY MODE COMMAND")
			}
		}

		mac32, err := security.NASMacCalculate(ue.UeSecurity.IntegrityAlg,
			ue.UeSecurity.KnasInt,
			ue.UeSecurity.DLCount.Get(),
			security.Bearer3GPP,
			security.DirectionDownlink, message[6:])
		if err != nil {
			return fmt.Errorf("error in MAC algorithm %v", err)
		}

		// check integrity
		if !reflect.DeepEqual(mac32, macReceived) {
			return fmt.Errorf("MAC verification failed")
		} else {
			logger.UELog.Info("successful NAS MAC verification")
		}
	} else {
		logger.UELog.Info("Message without security header")

		// decode NAS message.
		err := m.PlainNasDecode(&payload)
		if err != nil {
			logger.UELog.Info("Decode NAS error", err)
		}
	}

	switch m.GmmHeader.GetMessageType() {
	case nas.MsgTypeAuthenticationRequest:
		// handler authentication request.
		logger.UELog.Info("Receive Authentication Request")
		err := handler.HandlerAuthenticationRequest(ue, m)
		if err != nil {
			return fmt.Errorf("error in Authentication Request %v", err)
		}

	case nas.MsgTypeAuthenticationReject:
		// handler authentication reject.
		logger.UELog.Info("Receive Authentication Reject")
		handler.HandlerAuthenticationReject(ue, m)

	case nas.MsgTypeIdentityRequest:
		logger.UELog.Info("Receive Identify Request")
		// handler identity request.
		err := handler.HandlerIdentityRequest(ue, m)
		if err != nil {
			return fmt.Errorf("error in Identity Request %v", err)
		}

	case nas.MsgTypeSecurityModeCommand:
		// handler security mode command.
		logger.UELog.Info("Receive Security Mode Command")
		if !newSecurityContext {
			logger.UELog.Warn("Received Security Mode Command with security header different from \"Integrity protected with new 5G NAS security context\" ")
		}
		err := handler.HandlerSecurityModeCommand(ue, m)
		if err != nil {
			return fmt.Errorf("error in Security Mode Command %v", err)
		}

	case nas.MsgTypeRegistrationAccept:
		// handler registration accept.
		logger.UELog.Info("Receive Registration Accept")
		err := handler.HandlerRegistrationAccept(ue, m)
		if err != nil {
			return fmt.Errorf("error in Registration Accept %v", err)
		}

	case nas.MsgTypeConfigurationUpdateCommand:
		logger.UELog.Info("Receive Configuration Update Command")
		err := handler.HandlerConfigurationUpdateCommand(ue, m)
		if err != nil {
			return fmt.Errorf("error in Configuration Update Command %v", err)
		}

	case nas.MsgTypeDLNASTransport:
		// handler DL NAS Transport.
		logger.UELog.Info("Receive DL NAS Transport")
		handleCause5GMM(m.DLNASTransport.Cause5GMM)
		err := handler.HandlerDlNasTransportPduaccept(ue, m)
		if err != nil {
			return fmt.Errorf("error in DL NAS Transport PDU accept %v", err)
		}

	case nas.MsgTypeServiceAccept:
		// handler service reject
		logger.UELog.Info("Receive Service Accept")
		handler.HandlerServiceAccept(ue, m)

	case nas.MsgTypeServiceReject:
		// handler service reject
		logger.UELog.Error("Receive Service Reject")
		handleCause5GMM(&m.ServiceReject.Cause5GMM)

	case nas.MsgTypeRegistrationReject:
		// handler registration reject
		logger.UELog.Error("Receive Registration Reject")
		handleCause5GMM(&m.RegistrationReject.Cause5GMM)

	case nas.MsgTypeStatus5GMM:
		logger.UELog.Error("Receive Status 5GMM")
		handleCause5GMM(&m.Status5GMM.Cause5GMM)

	case nas.MsgTypeStatus5GSM:
		logger.UELog.Error("Receive Status 5GSM")
		handleCause5GSM(&m.Status5GSM.Cause5GSM)

	default:
		logger.UELog.Warnf("Received unknown NAS message 0x%x", m.GmmHeader.GetMessageType())
	}
	return nil
}

func handleCause5GSM(cause5SMM *nasType.Cause5GSM) {
	if cause5SMM != nil {
		logger.UELog.Error("UE received a 5GSM Failure, cause: ", cause5GMMToString(cause5SMM.Octet))
	}
}

func handleCause5GMM(cause5GMM *nasType.Cause5GMM) {
	if cause5GMM != nil {
		logger.UELog.Error("UE received a 5GMM Failure, cause: ", cause5GMMToString(cause5GMM.Octet))
	}
}

func cause5GMMToString(cause5GMM uint8) string {
	switch cause5GMM {
	case nasMessage.Cause5GMMIllegalUE:
		return "Illegal UE"
	case nasMessage.Cause5GMMPEINotAccepted:
		return "PEI not accepted"
	case nasMessage.Cause5GMMIllegalME:
		return "5GS services not allowed"
	case nasMessage.Cause5GMM5GSServicesNotAllowed:
		return "5GS services not allowed"
	case nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork:
		return "UE identity cannot be derived by the network"
	case nasMessage.Cause5GMMImplicitlyDeregistered:
		return "Implicitly de-registered"
	case nasMessage.Cause5GMMPLMNNotAllowed:
		return "PLMN not allowed"
	case nasMessage.Cause5GMMTrackingAreaNotAllowed:
		return "Tracking area not allowed"
	case nasMessage.Cause5GMMRoamingNotAllowedInThisTrackingArea:
		return "Roaming not allowed in this tracking area"
	case nasMessage.Cause5GMMNoSuitableCellsInTrackingArea:
		return "No suitable cells in tracking area"
	case nasMessage.Cause5GMMMACFailure:
		return "MAC failure"
	case nasMessage.Cause5GMMSynchFailure:
		return "Synch failure"
	case nasMessage.Cause5GMMCongestion:
		return "Congestion"
	case nasMessage.Cause5GMMUESecurityCapabilitiesMismatch:
		return "UE security capabilities mismatch"
	case nasMessage.Cause5GMMSecurityModeRejectedUnspecified:
		return "Security mode rejected, unspecified"
	case nasMessage.Cause5GMMNon5GAuthenticationUnacceptable:
		return "Non-5G authentication unacceptable"
	case nasMessage.Cause5GMMN1ModeNotAllowed:
		return "N1 mode not allowed"
	case nasMessage.Cause5GMMRestrictedServiceArea:
		return "Restricted service area"
	case nasMessage.Cause5GMMLADNNotAvailable:
		return "LADN not available"
	case nasMessage.Cause5GMMMaximumNumberOfPDUSessionsReached:
		return "Maximum number of PDU sessions reached"
	case nasMessage.Cause5GMMInsufficientResourcesForSpecificSliceAndDNN:
		return "Insufficient resources for specific slice and DNN"
	case nasMessage.Cause5GMMInsufficientResourcesForSpecificSlice:
		return "Insufficient resources for specific slice"
	case nasMessage.Cause5GMMngKSIAlreadyInUse:
		return "ngKSI already in use"
	case nasMessage.Cause5GMMNon3GPPAccessTo5GCNNotAllowed:
		return "Non-3GPP access to 5GCN not allowed"
	case nasMessage.Cause5GMMServingNetworkNotAuthorized:
		return "Serving network not authorized"
	case nasMessage.Cause5GMMPayloadWasNotForwarded:
		return "Payload was not forwarded"
	case nasMessage.Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice:
		return "DNN not supported or not subscribed in the slice"
	case nasMessage.Cause5GMMInsufficientUserPlaneResourcesForThePDUSession:
		return "Insufficient user-plane resources for the PDU session"
	case nasMessage.Cause5GMMSemanticallyIncorrectMessage:
		return "Semantically incorrect message"
	case nasMessage.Cause5GMMInvalidMandatoryInformation:
		return "Invalid mandatory information"
	case nasMessage.Cause5GMMMessageTypeNonExistentOrNotImplemented:
		return "Message type non-existent or not implementedE"
	case nasMessage.Cause5GMMMessageTypeNotCompatibleWithTheProtocolState:
		return "Message type not compatible with the protocol state"
	case nasMessage.Cause5GMMInformationElementNonExistentOrNotImplemented:
		return "Information element non-existent or not implemented"
	case nasMessage.Cause5GMMConditionalIEError:
		return "Conditional IE error"
	case nasMessage.Cause5GMMMessageNotCompatibleWithTheProtocolState:
		return "Message not compatible with the protocol state"
	case nasMessage.Cause5GMMProtocolErrorUnspecified:
		return "Protocol error, unspecified. Please share the pcap with packetrusher@hpe.com."
	default:
		return "Protocol error, unspecified. Please share the pcap with packetrusher@hpe.com."
	}
}
