/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 * © Copyright 2024 Valentin D'Emmanuele
 */
package ue_context_management

import (
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/pdu_session_management"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type InitialContextSetupResponseBuilder struct {
	pdu ngapType.NGAPPDU
	ies *ngapType.ProtocolIEContainerInitialContextSetupResponseIEs
}

func InitialContextSetupResponse(ue *context.GNBUe, gnb *context.GNBContext) ([]byte, error) {
	return NewInitialContextSetupResponseBuilder().
		SetAmfUeNgapId(ue.GetAmfUeId()).SetRanUeNgapId(ue.GetRanUeId()).
		SetPDUSessionResourceSetupListCxtRes(gnb, ue.GetPduSessions()).
		Build()
}

func NewInitialContextSetupResponseBuilder() *InitialContextSetupResponseBuilder {
	pdu := ngapType.NGAPPDU{}

	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentInitialContextSetupResponse
	successfulOutcome.Value.InitialContextSetupResponse = new(ngapType.InitialContextSetupResponse)

	initialContextSetupResponse := successfulOutcome.Value.InitialContextSetupResponse
	initialContextSetupResponseIEs := &initialContextSetupResponse.ProtocolIEs

	return &InitialContextSetupResponseBuilder{pdu, initialContextSetupResponseIEs}
}

func (builder *InitialContextSetupResponseBuilder) SetAmfUeNgapId(amfUeNgapID int64) *InitialContextSetupResponseBuilder {
	// AMF UE NGAP ID
	ie := ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	builder.ies.List = append(builder.ies.List, ie)

	return builder
}

func (builder *InitialContextSetupResponseBuilder) SetRanUeNgapId(ranUeNgapID int64) *InitialContextSetupResponseBuilder {
	// RAN UE NGAP ID
	ie := ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	builder.ies.List = append(builder.ies.List, ie)

	return builder
}

func (builder *InitialContextSetupResponseBuilder) SetPDUSessionResourceSetupListCxtRes(gnb *context.GNBContext, pduSessions [16]*context.GnbPDUSession) *InitialContextSetupResponseBuilder {
	// PDU Session Resource Setup List Cxt Res
	ie := ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtRes
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialContextSetupResponseIEsPresentPDUSessionResourceSetupListCxtRes
	ie.Value.PDUSessionResourceSetupListCxtRes = new(ngapType.PDUSessionResourceSetupListCxtRes)

	PDUSessionResourceSetupListCxtRes := ie.Value.PDUSessionResourceSetupListCxtRes
	for _, pduSession := range pduSessions {
		if pduSession == nil {
			continue
		}
		pDUSessionResourceSetupItemCxtRes := ngapType.PDUSessionResourceSetupItemCxtRes{}

		pDUSessionResourceSetupItemCxtRes.PDUSessionID.Value = pduSession.GetPduSessionId()
		pDUSessionResourceSetupItemCxtRes.PDUSessionResourceSetupResponseTransfer = pdu_session_management.GetPDUSessionResourceSetupResponseTransfer(gnb.GetN3GnbIp(), pduSession.GetTeidDownlink(), pduSession.GetQosId())
		PDUSessionResourceSetupListCxtRes.List = append(PDUSessionResourceSetupListCxtRes.List, pDUSessionResourceSetupItemCxtRes)
	}

	if len(PDUSessionResourceSetupListCxtRes.List) == 0 {
		logger.GnbLog.Info("no PDU Session to set up in InitialContextSetupResponse.")
		return builder
	}
	builder.ies.List = append(builder.ies.List, ie)

	return builder
}

func (builder *InitialContextSetupResponseBuilder) Build() ([]byte, error) {
	return ngap.Encoder(builder.pdu)
}
