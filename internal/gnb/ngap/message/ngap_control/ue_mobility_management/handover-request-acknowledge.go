/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Valentin D'Emmanuele
 */
package ue_mobility_management

import (
	"encoding/binary"
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

type HandoverRequestAcknowledgeBuilder struct {
	pdu ngapType.NGAPPDU
	ies *ngapType.ProtocolIEContainerHandoverRequestAcknowledgeIEs
}

func HandoverRequestAcknowledge(gnb *context.GNBContext, ue *context.GNBUe) ([]byte, error) {
	pduSessionAdmittedList, err := NewHandoverRequestAcknowledgeBuilder().
		SetAmfUeNgapId(ue.GetAmfUeId()).SetRanUeNgapId(ue.GetRanUeId()).
		SetPduSessionResourceAdmittedList(gnb, ue.GetPduSessions())
	if err != nil {
		return nil, fmt.Errorf("could not set PDU Session Resource Admitted List: %w", err)
	}
	targetToSourceContainer, err := pduSessionAdmittedList.SetTargetToSourceContainer()
	if err != nil {
		return nil, fmt.Errorf("could not set TargetToSourceContainer: %w", err)
	}
	return targetToSourceContainer.Build()
}

func NewHandoverRequestAcknowledgeBuilder() *HandoverRequestAcknowledgeBuilder {
	pdu := ngapType.NGAPPDU{}

	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeHandoverResourceAllocation
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject

	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentHandoverRequestAcknowledge
	successfulOutcome.Value.HandoverRequestAcknowledge = new(ngapType.HandoverRequestAcknowledge)

	handoverRequestAcknowledge := successfulOutcome.Value.HandoverRequestAcknowledge
	ies := &handoverRequestAcknowledge.ProtocolIEs

	return &HandoverRequestAcknowledgeBuilder{pdu, ies}
}

func (builder *HandoverRequestAcknowledgeBuilder) SetAmfUeNgapId(amfUeNgapID int64) *HandoverRequestAcknowledgeBuilder {
	// AMF UE NGAP ID
	ie := ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = amfUeNgapID

	builder.ies.List = append(builder.ies.List, ie)

	return builder
}

func (builder *HandoverRequestAcknowledgeBuilder) SetRanUeNgapId(ranUeNgapID int64) *HandoverRequestAcknowledgeBuilder {
	// RAN UE NGAP ID
	ie := ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	builder.ies.List = append(builder.ies.List, ie)

	return builder
}

func (builder *HandoverRequestAcknowledgeBuilder) SetPduSessionResourceAdmittedList(gnb *context.GNBContext, pduSessions [16]*context.GnbPDUSession) (*HandoverRequestAcknowledgeBuilder, error) {
	ie := ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceAdmittedList
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceAdmittedList
	ie.Value.PDUSessionResourceAdmittedList = new(ngapType.PDUSessionResourceAdmittedList)

	pDUSessionResourceAdmittedList := ie.Value.PDUSessionResourceAdmittedList

	for _, pduSession := range pduSessions {
		if pduSession == nil {
			continue
		}
		// PDU SessionResource Admittedy Item
		pDUSessionResourceAdmittedItem := ngapType.PDUSessionResourceAdmittedItem{}
		pDUSessionResourceAdmittedItem.PDUSessionID.Value = pduSession.GetPduSessionId()
		acknowledgeTransfer, err := GetHandoverRequestAcknowledgeTransfer(gnb, pduSession)
		if err != nil {
			return nil, fmt.Errorf("could not get HandoverRequestAcknowledgeTransfer: %w", err)
		}
		pDUSessionResourceAdmittedItem.HandoverRequestAcknowledgeTransfer = acknowledgeTransfer

		pDUSessionResourceAdmittedList.List = append(pDUSessionResourceAdmittedList.List, pDUSessionResourceAdmittedItem)
	}

	if len(pDUSessionResourceAdmittedList.List) == 0 {
		logger.GnbLog.Info("No admitted PDU Session")
		return builder, nil
	}

	builder.ies.List = append(builder.ies.List, ie)

	return builder, nil
}

func (builder *HandoverRequestAcknowledgeBuilder) SetTargetToSourceContainer() (*HandoverRequestAcknowledgeBuilder, error) {
	// Target To Source TransparentContainer
	ie := ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDTargetToSourceTransparentContainer
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentTargetToSourceTransparentContainer
	ie.Value.TargetToSourceTransparentContainer = new(ngapType.TargetToSourceTransparentContainer)

	targetToSourceTransparentContainer := ie.Value.TargetToSourceTransparentContainer
	targetToSourceValue, err := GetTargetToSourceTransparentTransfer()
	if err != nil {
		return nil, fmt.Errorf("could not get TargetToSourceTransparentTransfer: %w", err)
	}
	targetToSourceTransparentContainer.Value = targetToSourceValue
	builder.ies.List = append(builder.ies.List, ie)

	return builder, nil
}

func (builder *HandoverRequestAcknowledgeBuilder) Build() ([]byte, error) {
	return ngap.Encoder(builder.pdu)
}

func GetHandoverRequestAcknowledgeTransfer(gnb *context.GNBContext, pduSession *context.GnbPDUSession) ([]byte, error) {
	data := buildHandoverRequestAcknowledgeTransfer(gnb, pduSession)
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("could not marshal HandoverRequestAcknowledgeTransfer: %w", err)
	}
	return encodeData, nil
}

func buildHandoverRequestAcknowledgeTransfer(gnb *context.GNBContext, pduSession *context.GnbPDUSession) (data ngapType.HandoverRequestAcknowledgeTransfer) {
	// DL NG-U UP TNL information
	dlTransportLayerInformation := &data.DLNGUUPTNLInformation
	dlTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	dlTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)
	downlinkTeid := make([]byte, 4)
	binary.BigEndian.PutUint32(downlinkTeid, pduSession.GetTeidDownlink())
	dlTransportLayerInformation.GTPTunnel.GTPTEID.Value = downlinkTeid
	dlTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(gnb.GetN3GnbIp().String(), "")

	// Qos Flow Setup Response List
	qosFlowSetupResponseItem := ngapType.QosFlowItemWithDataForwarding{
		QosFlowIdentifier: ngapType.QosFlowIdentifier{
			Value: 1,
		},
	}

	data.QosFlowSetupResponseList.List = append(data.QosFlowSetupResponseList.List, qosFlowSetupResponseItem)

	return data
}

func GetTargetToSourceTransparentTransfer() ([]byte, error) {
	data := buildTargetToSourceTransparentTransfer()
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("could not marshal TargetToSourceTransparentTransfer: %w", err)
	}
	return encodeData, nil
}

func buildTargetToSourceTransparentTransfer() (data ngapType.TargetNGRANNodeToSourceNGRANNodeTransparentContainer) {
	// RRC Container
	data.RRCContainer.Value = aper.OctetString("\x00\x00\x11")

	return data
}
