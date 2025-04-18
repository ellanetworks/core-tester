/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package handler

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/nas_control"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/nas_control/mm_5gs"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/sender"
	"github.com/ellanetworks/core-tester/internal/ue/nas/trigger"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/openapi/models"
)

func HandlerAuthenticationReject(ue *context.UEContext, message *nas.Message) {
	logger.UELog.Info("Authentication of UE ", ue.GetUeId(), " failed")

	ue.SetStateMM_DEREGISTERED()
}

func HandlerAuthenticationRequest(ue *context.UEContext, message *nas.Message) error {
	var authenticationResponse []byte

	// check the mandatory fields
	if reflect.ValueOf(message.AuthenticationRequest.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if message.AuthenticationRequest.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(message.AuthenticationRequest.AuthenticationRequestMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if message.AuthenticationRequest.AuthenticationRequestMessageIdentity.GetMessageType() != 86 {
		return fmt.Errorf("message type not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if message.AuthenticationRequest.SpareHalfOctetAndNgksi.GetNasKeySetIdentifiler() == 7 {
		return fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(message.AuthenticationRequest.ABBA).IsZero() {
		return fmt.Errorf("ABBA is missing")
	}

	if message.AuthenticationRequest.GetABBAContents() == nil {
		return fmt.Errorf("ABBA content is missing")
	}

	// getting RAND and AUTN from the message.
	rand := message.AuthenticationRequest.GetRANDValue()
	autn := message.AuthenticationRequest.GetAUTN()

	// getting resStar
	paramAutn, err := ue.DeriveRESstarAndSetKey(ue.UeSecurity.AuthenticationSubs, rand[:], ue.UeSecurity.Snn, autn[:])

	switch err {
	case context.ErrMACFailure:
		logger.UELog.Info("[UE][NAS][MAC] Authenticity of the authentication request message: FAILED")
		logger.UELog.Info("Send authentication failure with MAC failure")
		authenticationResponse = mm_5gs.AuthenticationFailure("MAC failure", "", paramAutn)
		// not change the state of UE.

	case context.ErrSQNFailure:
		logger.UELog.Info("[UE][NAS][MAC] Authenticity of the authentication request message: OK")
		logger.UELog.Info("[UE][NAS][SQN] SQN of the authentication request message: INVALID")
		logger.UELog.Info("Send authentication failure with Synch failure")
		authenticationResponse = mm_5gs.AuthenticationFailure("SQN failure", "", paramAutn)
		// not change the state of UE.

	case nil:
		// getting NAS Authentication Response.
		logger.UELog.Info("[UE][NAS][MAC] Authenticity of the authentication request message: OK")
		logger.UELog.Info("[UE][NAS][SQN] SQN of the authentication request message: VALID")
		logger.UELog.Info("Send authentication response")
		authenticationResponse = mm_5gs.AuthenticationResponse(paramAutn, "")

		// change state of UE for registered-initiated
		ue.SetStateMM_REGISTERED_INITIATED()
	default:
		logger.UELog.Error("Error in authentication: ", err)
		return fmt.Errorf("error in authentication: %w", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, authenticationResponse)
	return nil
}

func HandlerSecurityModeCommand(ue *context.UEContext, message *nas.Message) error {
	if reflect.ValueOf(message.SecurityModeCommand.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if message.SecurityModeCommand.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if reflect.ValueOf(message.SecurityModeCommand.SecurityModeCommandMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if message.SecurityModeCommand.SecurityModeCommandMessageIdentity.GetMessageType() != 93 {
		return fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(message.SecurityModeCommand.SelectedNASSecurityAlgorithms).IsZero() {
		return fmt.Errorf("nas security algorithms is missing")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetNasKeySetIdentifiler() == 7 {
		return fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(message.SecurityModeCommand.ReplayedUESecurityCapabilities).IsZero() {
		return fmt.Errorf("replayed ue security capabilities is missing")
	}

	switch ue.UeSecurity.CipheringAlg {
	case 0:
		logger.UELog.Info("Type of ciphering algorithm is 5G-EA0")
	case 1:
		logger.UELog.Info("Type of ciphering algorithm is 128-5G-EA1")
	case 2:
		logger.UELog.Info("Type of ciphering algorithm is 128-5G-EA2")
	}

	switch ue.UeSecurity.IntegrityAlg {
	case 0:
		logger.UELog.Info("Type of integrity protection algorithm is 5G-IA0")
	case 1:
		logger.UELog.Info("Type of integrity protection algorithm is 128-5G-IA1")
	case 2:
		logger.UELog.Info("Type of integrity protection algorithm is 128-5G-IA2")
	}

	rinmr := uint8(0)
	if message.SecurityModeCommand.Additional5GSecurityInformation != nil {
		// checking BIT RINMR that triggered registration request in security mode complete.
		rinmr = message.SecurityModeCommand.Additional5GSecurityInformation.GetRINMR()
	}

	ue.UeSecurity.NgKsi.Ksi = int32(message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetNasKeySetIdentifiler())

	// NgKsi: TS 24.501 9.11.3.32
	switch message.SecurityModeCommand.SpareHalfOctetAndNgksi.GetTSC() {
	case nasMessage.TypeOfSecurityContextFlagNative:
		ue.UeSecurity.NgKsi.Tsc = models.ScType_NATIVE
	case nasMessage.TypeOfSecurityContextFlagMapped:
		ue.UeSecurity.NgKsi.Tsc = models.ScType_MAPPED
	}

	// getting NAS Security Mode Complete.
	securityModeComplete, err := mm_5gs.SecurityModeComplete(ue, rinmr)
	if err != nil {
		return fmt.Errorf("error sending Security Mode Complete: %w", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, securityModeComplete)
	return nil
}

func HandlerRegistrationAccept(ue *context.UEContext, message *nas.Message) error {
	// check the mandatory fields
	if reflect.ValueOf(message.RegistrationAccept.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if message.RegistrationAccept.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if message.RegistrationAccept.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if message.RegistrationAccept.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(message.RegistrationAccept.RegistrationAcceptMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if message.RegistrationAccept.RegistrationAcceptMessageIdentity.GetMessageType() != 66 {
		return fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(message.RegistrationAccept.RegistrationResult5GS).IsZero() {
		return fmt.Errorf("registration result 5GS is missing")
	}

	if message.RegistrationAccept.RegistrationResult5GS.GetRegistrationResultValue5GS() != 1 {
		return fmt.Errorf("registration result 5GS not the expected value")
	}

	// change the state of ue for registered
	ue.SetStateMM_REGISTERED()

	// saved 5g GUTI and others information.
	if message.RegistrationAccept.GUTI5G != nil {
		ue.Set5gGuti(message.RegistrationAccept.GUTI5G)
	} else {
		logger.UELog.Warn("UE was not assigned a 5G-GUTI by AMF")
	}

	// use the slice allowed by the network
	// in PDU session request
	if ue.Snssai.Sst == 0 {
		// check the allowed NSSAI received from the 5GC
		snssai := message.RegistrationAccept.AllowedNSSAI.GetSNSSAIValue()

		// update UE slice selected for PDU Session
		ue.Snssai.Sst = int32(snssai[1])
		ue.Snssai.Sd = fmt.Sprintf("0%x0%x0%x", snssai[2], snssai[3], snssai[4])

		logger.UELog.Warn("ALLOWED NSSAI: SST: ", ue.Snssai.Sst, " SD: ", ue.Snssai.Sd)
	}

	logger.UELog.Info("UE 5G GUTI: ", ue.Get5gGuti())

	// getting NAS registration complete.
	registrationComplete, err := mm_5gs.RegistrationComplete(ue)
	if err != nil {
		return fmt.Errorf("error sending Registration Complete: %w", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, registrationComplete)
	return nil
}

func HandlerServiceAccept(ue *context.UEContext, message *nas.Message) {
	// change the state of ue for registered
	ue.SetStateMM_REGISTERED()
}

func HandlerDlNasTransportPduaccept(ue *context.UEContext, message *nas.Message) error {
	// check the mandatory fields
	if reflect.ValueOf(message.DLNASTransport.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if message.DLNASTransport.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if message.DLNASTransport.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half not expected value")
	}

	if message.DLNASTransport.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header not expected value")
	}

	if message.DLNASTransport.DLNASTRANSPORTMessageIdentity.GetMessageType() != 104 {
		return fmt.Errorf("message type is missing or not expected value")
	}

	if reflect.ValueOf(message.DLNASTransport.SpareHalfOctetAndPayloadContainerType).IsZero() {
		return fmt.Errorf("payload container type is missing")
	}

	if message.DLNASTransport.SpareHalfOctetAndPayloadContainerType.GetPayloadContainerType() != 1 {
		return fmt.Errorf("payload container type not expected value")
	}

	if reflect.ValueOf(message.DLNASTransport.PayloadContainer).IsZero() || message.DLNASTransport.PayloadContainer.GetPayloadContainerContents() == nil {
		return fmt.Errorf("payload container is missing")
	}

	if reflect.ValueOf(message.DLNASTransport.PduSessionID2Value).IsZero() {
		return fmt.Errorf("pdu session id is missing")
	}

	if message.DLNASTransport.PduSessionID2Value.GetIei() != 18 {
		return fmt.Errorf("pdu session id not expected value")
	}

	// getting PDU Session establishment accept.
	payloadContainer, err := nas_control.GetNasPduFromPduAccept(message)
	if err != nil {
		return fmt.Errorf("could not get PDU Session establishment accept: %v", err)
	}

	switch payloadContainer.GsmHeader.GetMessageType() {
	case nas.MsgTypePDUSessionEstablishmentAccept:
		logger.UELog.Info("Receiving PDU Session Establishment Accept")

		// get UE ip
		pduSessionEstablishmentAccept := payloadContainer.PDUSessionEstablishmentAccept

		// check the mandatory fields
		if reflect.ValueOf(pduSessionEstablishmentAccept.ExtendedProtocolDiscriminator).IsZero() {
			return fmt.Errorf("extended protocol discriminator is missing")
		}

		if pduSessionEstablishmentAccept.GetExtendedProtocolDiscriminator() != 46 {
			return fmt.Errorf("extended protocol discriminator not expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.PDUSessionID).IsZero() {
			return fmt.Errorf("pdu session id is missing or not expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.PTI).IsZero() {
			return fmt.Errorf("pti is missing")
		}

		if pduSessionEstablishmentAccept.PTI.GetPTI() != 1 {
			return fmt.Errorf("pti not expected value")
		}

		if pduSessionEstablishmentAccept.PDUSESSIONESTABLISHMENTACCEPTMessageIdentity.GetMessageType() != 194 {
			return fmt.Errorf("message type is missing or not expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.SelectedSSCModeAndSelectedPDUSessionType).IsZero() {
			return fmt.Errorf("ssc mode or pdu session type is missing")
		}

		if pduSessionEstablishmentAccept.SelectedSSCModeAndSelectedPDUSessionType.GetPDUSessionType() != 1 {
			return fmt.Errorf("pdu session type not expected value")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.AuthorizedQosRules).IsZero() {
			return fmt.Errorf("authorized qos rules is missing")
		}

		if reflect.ValueOf(pduSessionEstablishmentAccept.SessionAMBR).IsZero() {
			return fmt.Errorf("session ambr is missing")
		}

		// update PDU Session information.
		pduSessionId := pduSessionEstablishmentAccept.GetPDUSessionID()
		pduSession, err := ue.GetPduSession(pduSessionId)
		// change the state of ue(SM)(PDU Session Active).
		pduSession.SetStateSM_PDU_SESSION_ACTIVE()
		if err != nil {
			return fmt.Errorf("could not get PDU Session: %v", err)
		}

		// get UE IP
		UeIp := pduSessionEstablishmentAccept.GetPDUAddressInformation()
		pduSession.SetIp(UeIp)

		// get QoS Rules
		QosRule := pduSessionEstablishmentAccept.AuthorizedQosRules.GetQosRule()
		// get DNN
		dnn := pduSessionEstablishmentAccept.DNN.GetDNN()
		// get SNSSAI
		sst := pduSessionEstablishmentAccept.SNSSAI.GetSST()
		sd := pduSessionEstablishmentAccept.SNSSAI.GetSD()

		logger.UELog.Info("PDU session QoS RULES: ", QosRule)
		logger.UELog.Info("PDU session DNN: ", dnn)
		logger.UELog.Info("PDU session NSSAI -- sst: ", sst, " sd: ",
			fmt.Sprintf("%x%x%x", sd[0], sd[1], sd[2]))
		logger.UELog.Info("PDU address received: ", pduSession.GetIp())
	case nas.MsgTypePDUSessionReleaseCommand:
		logger.UELog.Info("Receiving PDU Session Release Command")

		pduSessionReleaseCommand := payloadContainer.PDUSessionReleaseCommand
		pduSessionId := pduSessionReleaseCommand.GetPDUSessionID()
		pduSession, err := ue.GetPduSession(pduSessionId)
		if pduSession == nil || err != nil {
			logger.UELog.Error("Unable to delete PDU Session ", pduSessionId, " from UE ", ue.GetMsin(), " as the PDU Session was not found. Ignoring.")
			break
		}
		err = ue.DeletePduSession(pduSessionId)
		if err != nil {
			logger.UELog.Error("Unable to delete PDU Session ", pduSessionId, " from UE ", ue.GetMsin(), " as ", err)
		}
		logger.UELog.Info("Successfully released PDU Session ", pduSessionId, " from UE Context")
		err = trigger.InitPduSessionReleaseComplete(ue, pduSession)
		if err != nil {
			logger.UELog.Error("Error sending PDU Session Release Complete for PDU Session ", pduSessionId, " as ", err)
		}

	case nas.MsgTypePDUSessionEstablishmentReject:
		logger.UELog.Error("Receiving PDU Session Establishment Reject")

		pduSessionEstablishmentReject := payloadContainer.PDUSessionEstablishmentReject
		pduSessionId := pduSessionEstablishmentReject.GetPDUSessionID()

		logger.UELog.Error("PDU Session Establishment Reject for PDU Session ID ", pduSessionId, ", 5GSM Cause: ", cause5GSMToString(pduSessionEstablishmentReject.GetCauseValue()))

		// Per 5GSM state machine in TS 24.501 - 6.1.3.2.1., we re-try the setup until it's successful
		pduSession, err := ue.GetPduSession(pduSessionId)
		if err != nil {
			logger.UELog.Error("Cannot retry PDU Session Request for PDU Session ", pduSessionId, " after Reject as ", err)
			break
		}
		if pduSession.T3580Retries < 5 {
			// T3580 Timer
			go func() {
				// Exponential backoff
				time.Sleep(time.Duration(math.Pow(5, float64(pduSession.T3580Retries))) * time.Second)
				err := trigger.InitPduSessionRequestInner(ue, pduSession)
				if err != nil {
					logger.UELog.Error("Error re-trying PDU Session Request for PDU Session ", pduSessionId, " after Reject as ", err)
				}
				pduSession.T3580Retries++
			}()
		} else {
			logger.UELog.Error("We re-tried five times to create PDU Session ", pduSessionId, ", Aborting.")
		}

	default:
		logger.UELog.Error("Receiving Unknown Dl NAS Transport message!! ", payloadContainer.GsmHeader.GetMessageType())
	}
	return nil
}

func HandlerIdentityRequest(ue *context.UEContext, message *nas.Message) error {
	// check the mandatory fields
	if reflect.ValueOf(message.IdentityRequest.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if message.IdentityRequest.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if message.IdentityRequest.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if message.IdentityRequest.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(message.IdentityRequest.IdentityRequestMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if message.IdentityRequest.IdentityRequestMessageIdentity.GetMessageType() != 91 {
		return fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(message.IdentityRequest.SpareHalfOctetAndIdentityType).IsZero() {
		return fmt.Errorf("spare half octet and identity type is missing")
	}

	switch message.IdentityRequest.GetTypeOfIdentity() {
	case 1:
		logger.UELog.Info("Requested SUCI 5GS type")
	default:
		return fmt.Errorf("only SUCI identity is supported for now inside Ella Core Tester")
	}

	trigger.InitIdentifyResponse(ue)
	return nil
}

func HandlerConfigurationUpdateCommand(ue *context.UEContext, message *nas.Message) error {
	// check the mandatory fields
	if reflect.ValueOf(message.ConfigurationUpdateCommand.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if message.ConfigurationUpdateCommand.ExtendedProtocolDiscriminator.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if message.ConfigurationUpdateCommand.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if message.ConfigurationUpdateCommand.SpareHalfOctetAndSecurityHeaderType.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(message.ConfigurationUpdateCommand.ConfigurationUpdateCommandMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if message.ConfigurationUpdateCommand.ConfigurationUpdateCommandMessageIdentity.GetMessageType() != 84 {
		return fmt.Errorf("message type not the expected value")
	}

	err := trigger.InitConfigurationUpdateComplete(ue)
	if err != nil {
		return fmt.Errorf("error sending Configuration Update Complete: %w", err)
	}
	return nil
}

func cause5GSMToString(causeValue uint8) string {
	switch causeValue {
	case nasMessage.Cause5GSMInsufficientResources:
		return "Insufficient Ressources"
	case nasMessage.Cause5GSMMissingOrUnknownDNN:
		return "Missing or Unknown DNN"
	case nasMessage.Cause5GSMUnknownPDUSessionType:
		return "Unknown PDU Session Type"
	case nasMessage.Cause5GSMUserAuthenticationOrAuthorizationFailed:
		return "User authentification or authorization failed"
	case nasMessage.Cause5GSMRequestRejectedUnspecified:
		return "Request rejected, unspecified"
	case nasMessage.Cause5GSMServiceOptionTemporarilyOutOfOrder:
		return "Service option temporarily out of order."
	case nasMessage.Cause5GSMPTIAlreadyInUse:
		return "PTI already in use"
	case nasMessage.Cause5GSMRegularDeactivation:
		return "Regular deactivation"
	case nasMessage.Cause5GSMReactivationRequested:
		return "Reactivation requested"
	case nasMessage.Cause5GSMInvalidPDUSessionIdentity:
		return "Invalid PDU session identity"
	case nasMessage.Cause5GSMSemanticErrorsInPacketFilter:
		return "Semantic errors in packet filter(s)"
	case nasMessage.Cause5GSMSyntacticalErrorInPacketFilter:
		return "Syntactical error in packet filter(s)"
	case nasMessage.Cause5GSMOutOfLADNServiceArea:
		return "Out of LADN service area"
	case nasMessage.Cause5GSMPTIMismatch:
		return "PTI mismatch"
	case nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed:
		return "PDU session type IPv4 only allowed"
	case nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed:
		return "PDU session type IPv6 only allowed"
	case nasMessage.Cause5GSMPDUSessionDoesNotExist:
		return "PDU session does not exist"
	case nasMessage.Cause5GSMInsufficientResourcesForSpecificSliceAndDNN:
		return "Insufficient resources for specific slice and DNN"
	case nasMessage.Cause5GSMNotSupportedSSCMode:
		return "Not supported SSC mode"
	case nasMessage.Cause5GSMInsufficientResourcesForSpecificSlice:
		return "Insufficient resources for specific slice"
	case nasMessage.Cause5GSMMissingOrUnknownDNNInASlice:
		return "Missing or unknown DNN in a slice"
	case nasMessage.Cause5GSMInvalidPTIValue:
		return "Invalid PTI value"
	case nasMessage.Cause5GSMMaximumDataRatePerUEForUserPlaneIntegrityProtectionIsTooLow:
		return "Maximum data rate per UE for user-plane integrity protection is too low"
	case nasMessage.Cause5GSMSemanticErrorInTheQoSOperation:
		return "Semantic error in the QoS operation"
	case nasMessage.Cause5GSMSyntacticalErrorInTheQoSOperation:
		return "Syntactical error in the QoS operation"
	case nasMessage.Cause5GSMInvalidMappedEPSBearerIdentity:
		return "Invalid mapped EPS bearer identity"
	case nasMessage.Cause5GSMSemanticallyIncorrectMessage:
		return "Semantically incorrect message"
	case nasMessage.Cause5GSMInvalidMandatoryInformation:
		return "Invalid mandatory information"
	case nasMessage.Cause5GSMMessageTypeNonExistentOrNotImplemented:
		return "Message type non-existent or not implemented"
	case nasMessage.Cause5GSMMessageTypeNotCompatibleWithTheProtocolState:
		return "Message type not compatible with the protocol state"
	case nasMessage.Cause5GSMInformationElementNonExistentOrNotImplemented:
		return "Information element non-existent or not implemented"
	case nasMessage.Cause5GSMConditionalIEError:
		return "Conditional IE error"
	case nasMessage.Cause5GSMMessageNotCompatibleWithTheProtocolState:
		return "Message not compatible with the protocol state"
	case nasMessage.Cause5GSMProtocolErrorUnspecified:
		return "Protocol error, unspecified. Please open an issue on Github with pcap."
	default:
		return "Service option temporarily out of order."
	}
}
