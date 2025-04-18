/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */

// Package trigger
// Triggers are the basic building block of test scenarios.
// They allow to trigger NAS procedures by the UE, eg: registration, PDU Session creation...
// Replies from the AMF are handled in the global handler.
package trigger

import (
	context2 "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/nas_control"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/nas_control/mm_5gs"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/sender"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

func InitRegistration(ue *context.UEContext) {
	logger.UELog.Info("Initiating Registration")

	// registration procedure started.
	registrationRequest := mm_5gs.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration,
		nil,
		nil,
		false,
		ue)

	var err error
	if len(ue.UeSecurity.Kamf) != 0 {
		registrationRequest, err = nas_control.EncodeNasPduWithSecurity(ue, registrationRequest, nas.SecurityHeaderTypeIntegrityProtected, true, false)
		if err != nil {
			logger.UELog.Fatalf("Unable to encode with integrity protection Registration Request: %s", err)
		}
	}
	// send to GNB.
	sender.SendToGnb(ue, registrationRequest)

	// change the state of ue for deregistered
	ue.SetStateMM_DEREGISTERED()
}

func InitPduSessionRequest(ue *context.UEContext) {
	logger.UELog.Info("Initiating New PDU Session")

	pduSession, err := ue.CreatePDUSession()
	if err != nil {
		logger.UELog.Fatal("", err)
		return
	}

	InitPduSessionRequestInner(ue, pduSession)
}

func InitPduSessionRequestInner(ue *context.UEContext, pduSession *context.UEPDUSession) {
	ulNasTransport, err := mm_5gs.Request_UlNasTransport(pduSession, ue)
	if err != nil {
		logger.UELog.Fatal("Error sending ul nas transport and pdu session establishment request: ", err)
	}

	// change the state of ue(SM).
	pduSession.SetStateSM_PDU_SESSION_PENDING()

	// sending to GNB
	sender.SendToGnb(ue, ulNasTransport)
}

func InitPduSessionRelease(ue *context.UEContext, pduSession *context.UEPDUSession) {
	logger.UELog.Info("Initiating Release of PDU Session ", pduSession.Id)

	if pduSession.GetStateSM() != context.SM5G_PDU_SESSION_ACTIVE {
		logger.UELog.Warn("Skipping releasing the PDU Session ID ", pduSession.Id, " as it's not active")
		return
	}

	ulNasTransport, err := mm_5gs.Release_UlNasTransport(pduSession, ue)
	if err != nil {
		logger.UELog.Fatal("Error sending ul nas transport and pdu session establishment request: ", err)
	}

	// change the state of ue(SM).
	pduSession.SetStateSM_PDU_SESSION_INACTIVE()

	// sending to GNB
	sender.SendToGnb(ue, ulNasTransport)
}

func InitPduSessionReleaseComplete(ue *context.UEContext, pduSession *context.UEPDUSession) {
	logger.UELog.Info("Initiating PDU Session Release Complete for PDU Session", pduSession.Id)

	if pduSession.GetStateSM() != context.SM5G_PDU_SESSION_INACTIVE {
		logger.UELog.Warn("Unable to send PDU Session Release Complete for a PDU Session which is not inactive")
		return
	}

	ulNasTransport, err := mm_5gs.ReleasComplete_UlNasTransport(pduSession, ue)
	if err != nil {
		logger.UELog.Fatal("Error sending ul nas transport and pdu session establishment request: ", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, ulNasTransport)
}

func InitDeregistration(ue *context.UEContext) {
	logger.UELog.Info("Initiating Deregistration")

	// registration procedure started.
	deregistrationRequest, err := mm_5gs.DeregistrationRequest(ue)
	if err != nil {
		logger.UELog.Fatal("Error sending deregistration request: ", err)
	}

	// send to GNB.
	sender.SendToGnb(ue, deregistrationRequest)

	// change the state of ue for deregistered
	ue.SetStateMM_DEREGISTERED()
}

func InitIdentifyResponse(ue *context.UEContext) {
	logger.UELog.Info("Initiating Identify Response")

	// trigger identity response.
	identityResponse := mm_5gs.IdentityResponse(ue)

	// send to GNB.
	sender.SendToGnb(ue, identityResponse)
}

func InitConfigurationUpdateComplete(ue *context.UEContext) {
	logger.UELog.Info("Initiating Configuration Update Complete")

	// trigger Configuration Update Complete.
	identityResponse, err := mm_5gs.ConfigurationUpdateComplete(ue)
	if err != nil {
		logger.UELog.Fatal("Error sending Configuration Update Complete: ", err)
	}
	// send to GNB.
	sender.SendToGnb(ue, identityResponse)
}

func InitServiceRequest(ue *context.UEContext) {
	logger.UELog.Info("Initiating Service Request")

	// trigger ServiceRequest.
	serviceRequest := mm_5gs.ServiceRequest(ue)
	pdu, err := nas_control.EncodeNasPduWithSecurity(ue, serviceRequest, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	if err != nil {
		logger.UELog.Fatalf("Error encoding %s IMSI UE PduSession Establishment Request Msg", ue.UeSecurity.Supi)
	}

	// send to GNB.
	sender.SendToGnb(ue, pdu)
}

func SwitchToIdle(ue *context.UEContext) {
	logger.UELog.Info("Switching to 5GMM-IDLE")

	// send to GNB.
	sender.SendToGnbMsg(ue, context2.UEMessage{Idle: true})
}
