/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package ngap

import (
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func Dispatch(amf *context.GNBAmf, gnb *context.GNBContext, message []byte) {
	if message == nil {
		logger.GnbLog.Info("NGAP message is nil")
	}

	// decode NGAP message.
	ngapMsg, err := ngap.Decoder(message)
	if err != nil {
		logger.GnbLog.Error("Error decoding NGAP message in ", gnb.GetGnbId(), " GNB", ": ", err)
	}

	// check RanUeId and get UE.

	// handle NGAP message.
	switch ngapMsg.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:

		switch ngapMsg.InitiatingMessage.ProcedureCode.Value {
		case ngapType.ProcedureCodeDownlinkNASTransport:
			// handler NGAP Downlink NAS Transport.
			logger.GnbLog.Info("Receive Downlink NAS Transport")
			HandlerDownlinkNasTransport(gnb, ngapMsg)

		case ngapType.ProcedureCodeInitialContextSetup:
			// handler NGAP Initial Context Setup Request.
			logger.GnbLog.Info("Receive Initial Context Setup Request")
			HandlerInitialContextSetupRequest(gnb, ngapMsg)

		case ngapType.ProcedureCodePDUSessionResourceSetup:
			// handler NGAP PDU Session Resource Setup Request.
			logger.GnbLog.Info("Receive PDU Session Resource Setup Request")
			HandlerPduSessionResourceSetupRequest(gnb, ngapMsg)

		case ngapType.ProcedureCodePDUSessionResourceRelease:
			// handler NGAP PDU Session Resource Release
			logger.GnbLog.Info("Receive PDU Session Release Command")
			HandlerPduSessionReleaseCommand(gnb, ngapMsg)

		case ngapType.ProcedureCodeUEContextRelease:
			// handler NGAP UE Context Release
			logger.GnbLog.Info("Receive UE Context Release Command")
			HandlerUeContextReleaseCommand(gnb, ngapMsg)

		case ngapType.ProcedureCodeAMFConfigurationUpdate:
			// handler NGAP AMF Configuration Update
			logger.GnbLog.Info("Receive AMF Configuration Update")
			HandlerAmfConfigurationUpdate(amf, gnb, ngapMsg)
		case ngapType.ProcedureCodeAMFStatusIndication:
			logger.GnbLog.Info("Receive AMF Status Indication")
			HandlerAmfStatusIndication(amf, gnb, ngapMsg)
		case ngapType.ProcedureCodeHandoverResourceAllocation:
			// handler NGAP Handover Request
			logger.GnbLog.Info("Receive Handover Request")
			HandlerHandoverRequest(amf, gnb, ngapMsg)

		case ngapType.ProcedureCodePaging:
			// handler NGAP Paging
			logger.GnbLog.Info("Receive Paging")
			HandlerPaging(gnb, ngapMsg)

		case ngapType.ProcedureCodeErrorIndication:
			// handler Error Indicator
			logger.GnbLog.Error("Receive Error Indication")
			HandlerErrorIndication(gnb, ngapMsg)

		default:
			logger.GnbLog.Warnf("Received unknown NGAP message 0x%x", ngapMsg.InitiatingMessage.ProcedureCode.Value)
		}

	case ngapType.NGAPPDUPresentSuccessfulOutcome:

		switch ngapMsg.SuccessfulOutcome.ProcedureCode.Value {
		case ngapType.ProcedureCodeNGSetup:
			// handler NGAP Setup Response.
			logger.GnbLog.Info("Receive NG Setup Response")
			HandlerNgSetupResponse(amf, gnb, ngapMsg)

		case ngapType.ProcedureCodePathSwitchRequest:
			// handler PathSwitchRequestAcknowledge
			logger.GnbLog.Info("Receive PathSwitchRequestAcknowledge")
			HandlerPathSwitchRequestAcknowledge(gnb, ngapMsg)

		case ngapType.ProcedureCodeHandoverPreparation:
			// handler NGAP AMF Handover Command
			logger.GnbLog.Info("Receive Handover Command")
			HandlerHandoverCommand(amf, gnb, ngapMsg)

		default:
			logger.GnbLog.Warnf("Received unknown NGAP message 0x%x", ngapMsg.SuccessfulOutcome.ProcedureCode.Value)
		}

	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		switch ngapMsg.UnsuccessfulOutcome.ProcedureCode.Value {
		case ngapType.ProcedureCodeNGSetup:
			// handler NGAP Setup Failure.
			logger.GnbLog.Info("Receive Ng Setup Failure")
			HandlerNgSetupFailure(amf, gnb, ngapMsg)

		default:
			logger.GnbLog.Warnf("Received unknown NGAP message 0x%x", ngapMsg.UnsuccessfulOutcome.ProcedureCode.Value)
		}
	}
}
