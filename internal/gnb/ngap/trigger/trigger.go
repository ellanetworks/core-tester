/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package trigger

import (
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/interface_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/pdu_session_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/ue_context_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/ue_mobility_management"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/sender"
	"github.com/free5gc/ngap/ngapType"
	log "github.com/sirupsen/logrus"
)

func SendPduSessionResourceSetupResponse(pduSessions []*context.GnbPDUSession, ue *context.GNBUe, gnb *context.GNBContext) {
	log.Info("[GNB] Initiating PDU Session Resource Setup Response")

	// send PDU Session Resource Setup Response.
	ngapMsg, err := pdu_session_management.PDUSessionResourceSetupResponse(pduSessions, ue, gnb)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending PDU Session Resource Setup Response: ", err)
	}

	ue.SetStateReady()

	// Send PDU Session Resource Setup Response.
	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][AMF] Error sending PDU Session Resource Setup Response.: ", err)
	}
}

func SendPduSessionReleaseResponse(pduSessionIds []ngapType.PDUSessionID, ue *context.GNBUe) {
	log.Info("[GNB] Initiating PDU Session Release Response")

	if len(pduSessionIds) == 0 {
		log.Fatal("[GNB][NGAP] Trying to send a PDU Session Release Response for no PDU Session")
	}

	ngapMsg, err := pdu_session_management.PDUSessionReleaseResponse(pduSessionIds, ue)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending PDU Session Release Response.: ", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending PDU Session Release Response.: ", err)
	}
}

func SendInitialContextSetupResponse(ue *context.GNBUe, gnb *context.GNBContext) {
	log.Info("[GNB] Initiating Initial Context Setup Response")

	// send Initial Context Setup Response.
	ngapMsg, err := ue_context_management.InitialContextSetupResponse(ue, gnb)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending Initial Context Setup Response: ", err)
	}

	// Send Initial Context Setup Response.
	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][AMF] Error sending Initial Context Setup Response: ", err)
	}
}

func SendUeContextReleaseRequest(ue *context.GNBUe) {
	log.Info("[GNB] Initiating UE Context Release Request")

	// send UE Context Release Complete
	ngapMsg, err := ue_context_management.UeContextReleaseRequest(ue)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending UE Context Release Request: ", err)
	}

	// Send UE Context Release Complete
	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][AMF] Error sending UE Context Release Request: ", err)
	}
}

func SendUeContextReleaseComplete(ue *context.GNBUe) {
	log.Info("[GNB] Initiating UE Context Complete")

	// send UE Context Release Complete
	ngapMsg, err := ue_context_management.UeContextReleaseComplete(ue)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending UE Context Complete: ", err)
	}

	// Send UE Context Release Complete
	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][AMF] Error sending UE Context Complete: ", err)
	}
}

func SendEllaConfigurationUpdateAcknowledge(ella *context.GNBElla) {
	log.Info("[GNB] Initiating AMF Configuration Update Acknowledge")

	// send AMF Configure Update Acknowledge
	ngapMsg, err := interface_management.EllaConfigurationUpdateAcknowledge()
	if err != nil {
		log.Warn("[GNB][NGAP] Error sending AMF Configuration Update Acknowledge: ", err)
	}

	// Send AMF Configure Update Acknowledge
	conn := ella.GetSCTPConn()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Warn("[GNB][NGAP] Error sending AMF Configuration Update Acknowledge: ", err)
	}
}

func SendNgSetupRequest(gnb *context.GNBContext, ella *context.GNBElla) {
	log.Info("[GNB] Initiating NG Setup Request")

	// send NG setup response.
	ngapMsg, err := interface_management.NGSetupRequest(gnb, "PacketRusher")
	if err != nil {
		log.Info("[GNB][NGAP] Error sending NG Setup Request: ", err)
	}

	conn := ella.GetSCTPConn()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Info("[GNB][AMF] Error sending NG Setup Request: ", err)
	}
}

func SendPathSwitchRequest(gnb *context.GNBContext, ue *context.GNBUe) {
	log.Info("[GNB] Initiating Path Switch Request")

	// send NG setup response.
	ngapMsg, err := ue_mobility_management.PathSwitchRequest(gnb, ue)
	if err != nil {
		log.Info("[GNB][NGAP] Error sending Path Switch Request ", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending Path Switch Request: ", err)
	}
}

func SendHandoverRequestAcknowledge(gnb *context.GNBContext, ue *context.GNBUe) {
	log.Info("[GNB] Initiating Handover Request Acknowledge")

	// send NG setup response.
	ngapMsg, err := ue_mobility_management.HandoverRequestAcknowledge(gnb, ue)
	if err != nil {
		log.Info("[GNB][NGAP] Error sending Handover Request Acknowledge: ", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending Handover Request Acknowledge: ", err)
	}
}

func SendHandoverNotify(gnb *context.GNBContext, ue *context.GNBUe) {
	log.Info("[GNB] Initiating Handover Notify")

	// send NG setup response.
	ngapMsg, err := ue_mobility_management.HandoverNotify(gnb, ue)
	if err != nil {
		log.Info("[GNB][NGAP] Error sending Handover Notify: ", err)
	}

	conn := ue.GetSCTP()
	err = sender.SendToElla(ngapMsg, conn)
	if err != nil {
		log.Fatal("[GNB][NGAP] Error sending Handover Notify: ", err)
	}
}
