/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package trigger

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb/context"
	ueSender "github.com/ellanetworks/core-tester/internal/gnb/nas/message/sender"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/interface_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/pdu_session_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/ue_context_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/ue_mobility_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/sender"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/ngap/ngapType"
)

func SendPduSessionResourceSetupResponse(pduSessions []*context.GnbPDUSession, ue *context.GNBUe, gnb *context.GNBContext) error {
	logger.GnbLog.Info("Initiating PDU Session Resource Setup Response")

	// send PDU Session Resource Setup Response.
	ngapMsg, err := pdu_session_management.PDUSessionResourceSetupResponse(pduSessions, ue, gnb)
	if err != nil {
		return fmt.Errorf("error sending PDU Session Resource Setup Response: %w", err)
	}

	ue.SetStateReady()

	// Send PDU Session Resource Setup Response.
	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending PDU Session Resource Setup Response: %w", err)
	}
	return nil
}

func SendPduSessionReleaseResponse(pduSessionIds []ngapType.PDUSessionID, ue *context.GNBUe) error {
	logger.GnbLog.Info("Initiating PDU Session Release Response")

	if len(pduSessionIds) == 0 {
		return fmt.Errorf("trying to send a PDU Session Release Response for no PDU Session")
	}

	ngapMsg, err := pdu_session_management.PDUSessionReleaseResponse(pduSessionIds, ue)
	if err != nil {
		return fmt.Errorf("error sending PDU Session Release Response: %w", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending PDU Session Release Response: %w", err)
	}
	return nil
}

func SendInitialContextSetupResponse(ue *context.GNBUe, gnb *context.GNBContext) error {
	logger.GnbLog.Info("Initiating Initial Context Setup Response")

	// send Initial Context Setup Response.
	ngapMsg, err := ue_context_management.InitialContextSetupResponse(ue, gnb)
	if err != nil {
		return fmt.Errorf("error sending Initial Context Setup Response: %w", err)
	}

	// Send Initial Context Setup Response.
	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending Initial Context Setup Response: %w", err)
	}
	return nil
}

func SendUeContextReleaseRequest(ue *context.GNBUe) error {
	logger.GnbLog.Info("Initiating UE Context Release Request")

	// send UE Context Release Complete
	ngapMsg, err := ue_context_management.UeContextReleaseRequest(ue)
	if err != nil {
		return fmt.Errorf("error sending UE Context Release Request: %w", err)
	}

	// Send UE Context Release Complete
	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending UE Context Release Request: %w", err)
	}
	return nil
}

func SendUeContextReleaseComplete(ue *context.GNBUe) error {
	logger.GnbLog.Info("Initiating UE Context Complete")

	// send UE Context Release Complete
	ngapMsg, err := ue_context_management.UeContextReleaseComplete(ue)
	if err != nil {
		return fmt.Errorf("error sending UE Context Release Complete: %w", err)
	}

	// Send UE Context Release Complete
	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending UE Context Release Complete: %w", err)
	}
	return nil
}

func SendAmfConfigurationUpdateAcknowledge(amf *context.GNBAmf) error {
	logger.GnbLog.Info("Initiating AMF Configuration Update Acknowledge")

	// send AMF Configure Update Acknowledge
	ngapMsg, err := interface_management.AmfConfigurationUpdateAcknowledge()
	if err != nil {
		return fmt.Errorf("error creating AMF Configuration Update Acknowledge: %w", err)
	}

	// Send AMF Configure Update Acknowledge
	conn := amf.GetSCTPConn()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending AMF Configuration Update Acknowledge: %w", err)
	}
	return nil
}

func SendNgSetupRequest(gnb *context.GNBContext, amf *context.GNBAmf) error {
	logger.GnbLog.Info("Initiating NG Setup Request")

	// send NG setup response.
	ngapMsg, err := interface_management.NGSetupRequest(gnb, "PacketRusher")
	if err != nil {
		return fmt.Errorf("error creating NG Setup Request: %w", err)
	}

	conn := amf.GetSCTPConn()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending NG Setup Request: %w", err)
	}
	return nil
}

func SendPathSwitchRequest(gnb *context.GNBContext, ue *context.GNBUe) error {
	logger.GnbLog.Info("Initiating Path Switch Request")

	// send NG setup response.
	ngapMsg, err := ue_mobility_management.PathSwitchRequest(gnb, ue)
	if err != nil {
		return fmt.Errorf("error creating Path Switch Request: %w", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending Path Switch Request: %w", err)
	}
	return nil
}

func SendHandoverRequestAcknowledge(gnb *context.GNBContext, ue *context.GNBUe) error {
	logger.GnbLog.Info("Initiating Handover Request Acknowledge")

	// send NG setup response.
	ngapMsg, err := ue_mobility_management.HandoverRequestAcknowledge(gnb, ue)
	if err != nil {
		return fmt.Errorf("error creating Handover Request Acknowledge: %w", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending Handover Request Acknowledge: %w", err)
	}
	return nil
}

func SendHandoverNotify(gnb *context.GNBContext, ue *context.GNBUe) error {
	logger.GnbLog.Info("Initiating Handover Notify")

	// send NG setup response.
	ngapMsg, err := ue_mobility_management.HandoverNotify(gnb, ue)
	if err != nil {
		return fmt.Errorf("error creating Handover Notify: %w", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending Handover Notify: %w", err)
	}
	return nil
}

func TriggerXnHandover(oldGnb *context.GNBContext, newGnb *context.GNBContext, prUeId int64) error {
	logger.GnbLog.Info("Initiating Xn UE Handover")

	gnbUeContext, err := oldGnb.GetGnbUeByPrUeId(prUeId)
	if err != nil {
		return fmt.Errorf("error getting UE from PR UE ID: %w", err)
	}

	newGnbRx := make(chan context.UEMessage, 1)
	newGnbTx := make(chan context.UEMessage, 1)
	newGnb.GetInboundChannel() <- context.UEMessage{GNBRx: newGnbRx, GNBTx: newGnbTx, PrUeId: gnbUeContext.GetPrUeId(), UEContext: gnbUeContext, IsHandover: true}

	msg := context.UEMessage{GNBRx: newGnbRx, GNBTx: newGnbTx, GNBInboundChannel: newGnb.GetInboundChannel()}

	ueSender.SendMessageToUe(gnbUeContext, msg)
	return nil
}

func TriggerNgapHandover(oldGnb *context.GNBContext, newGnb *context.GNBContext, prUeId int64) error {
	logger.GnbLog.Info("Initiating NGAP UE Handover")

	gnbUeContext, err := oldGnb.GetGnbUeByPrUeId(prUeId)
	if err != nil {
		return fmt.Errorf("error getting UE from PR UE ID: %w", err)
	}

	gnbUeContext.SetHandoverGnodeB(newGnb)

	// send NG setup response.
	ngapMsg, err := ue_mobility_management.HandoverRequired(oldGnb, newGnb, gnbUeContext)
	if err != nil {
		return fmt.Errorf("error creating Handover Required: %w", err)
	}

	conn := gnbUeContext.GetSCTP()
	err = sender.SendToAmF(ngapMsg, conn)
	if err != nil {
		return fmt.Errorf("error sending Handover Required: %w", err)
	}
	return nil
}
