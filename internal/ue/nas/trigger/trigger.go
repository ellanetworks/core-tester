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
	"fmt"

	context2 "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/nas_control"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/nas_control/mm_5gs"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/sender"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

func InitRegistration(ue *context.UEContext) error {
	logger.UELog.Info("Initiating Registration")

	registrationRequest, err := mm_5gs.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration,
		nil,
		nil,
		false,
		ue,
	)
	if err != nil {
		return fmt.Errorf("could not create registration request: %w", err)
	}
	if len(ue.UeSecurity.Kamf) != 0 {
		registrationRequest, err = nas_control.EncodeNasPduWithSecurity(ue, registrationRequest, nas.SecurityHeaderTypeIntegrityProtected, true, false)
		if err != nil {
			return fmt.Errorf("unable to encode with integrity protection Registration Request: %w", err)
		}
	}
	sender.SendToGnb(ue, registrationRequest)

	ue.SetStateMM_DEREGISTERED()
	return nil
}

func InitPduSessionRequest(ue *context.UEContext) error {
	logger.UELog.Info("Initiating New PDU Session")

	pduSession, err := ue.CreatePDUSession()
	if err != nil {
		return fmt.Errorf("could not create PDU Session: %w", err)
	}

	err = InitPduSessionRequestInner(ue, pduSession)
	if err != nil {
		return fmt.Errorf("could not initiate PDU Session Request: %w", err)
	}
	return nil
}

func InitPduSessionRequestInner(ue *context.UEContext, pduSession *context.UEPDUSession) error {
	ulNasTransport, err := mm_5gs.Request_UlNasTransport(pduSession, ue)
	if err != nil {
		return fmt.Errorf("error sending ul nas transport and pdu session establishment request: %w", err)
	}

	pduSession.SetStateSM_PDU_SESSION_PENDING()

	sender.SendToGnb(ue, ulNasTransport)
	return nil
}

func InitPduSessionRelease(ue *context.UEContext, pduSession *context.UEPDUSession) error {
	logger.UELog.Info("Initiating Release of PDU Session ", pduSession.Id)

	if pduSession.GetStateSM() != context.SM5G_PDU_SESSION_ACTIVE {
		return fmt.Errorf("skipping releasing the PDU Session ID %d as it's not active", pduSession.Id)
	}

	ulNasTransport, err := mm_5gs.Release_UlNasTransport(pduSession, ue)
	if err != nil {
		return fmt.Errorf("error sending ul nas transport and pdu session establishment request: %w", err)
	}

	pduSession.SetStateSM_PDU_SESSION_INACTIVE()

	sender.SendToGnb(ue, ulNasTransport)
	return nil
}

func InitPduSessionReleaseComplete(ue *context.UEContext, pduSession *context.UEPDUSession) error {
	logger.UELog.Info("Initiating PDU Session Release Complete for PDU Session", pduSession.Id)

	if pduSession.GetStateSM() != context.SM5G_PDU_SESSION_INACTIVE {
		logger.UELog.Warn("Unable to send PDU Session Release Complete for a PDU Session which is not inactive")
		return nil
	}

	ulNasTransport, err := mm_5gs.ReleasComplete_UlNasTransport(pduSession, ue)
	if err != nil {
		return fmt.Errorf("error sending ul nas transport and pdu session establishment request: %w", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, ulNasTransport)
	return nil
}

func InitDeregistration(ue *context.UEContext) error {
	logger.UELog.Info("Initiating Deregistration")

	// registration procedure started.
	deregistrationRequest, err := mm_5gs.DeregistrationRequest(ue)
	if err != nil {
		return fmt.Errorf("error sending deregistration request: %w", err)
	}

	// send to GNB.
	sender.SendToGnb(ue, deregistrationRequest)

	// change the state of ue for deregistered
	ue.SetStateMM_DEREGISTERED()
	return nil
}

func InitIdentifyResponse(ue *context.UEContext) {
	logger.UELog.Info("Initiating Identify Response")

	// trigger identity response.
	identityResponse := mm_5gs.IdentityResponse(ue)

	// send to GNB.
	sender.SendToGnb(ue, identityResponse)
}

func InitConfigurationUpdateComplete(ue *context.UEContext) error {
	logger.UELog.Info("Initiating Configuration Update Complete")

	// trigger Configuration Update Complete.
	identityResponse, err := mm_5gs.ConfigurationUpdateComplete(ue)
	if err != nil {
		return fmt.Errorf("error sending Configuration Update Complete: %w", err)
	}
	// send to GNB.
	sender.SendToGnb(ue, identityResponse)
	return nil
}

func InitServiceRequest(ue *context.UEContext) error {
	logger.UELog.Info("Initiating Service Request")

	// trigger ServiceRequest.
	serviceRequest := mm_5gs.ServiceRequest(ue)
	pdu, err := nas_control.EncodeNasPduWithSecurity(ue, serviceRequest, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE PduSession Establishment Request Msg: %w", ue.UeSecurity.Supi, err)
	}

	// send to GNB.
	sender.SendToGnb(ue, pdu)
	return nil
}

func SwitchToIdle(ue *context.UEContext) {
	logger.UELog.Info("Switching to 5GMM-IDLE")

	// send to GNB.
	sender.SendToGnbMsg(ue, context2.UEMessage{Idle: true})
}
