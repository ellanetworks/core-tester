package build

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

type InitialContextSetupResponseBuilder struct {
	pdu ngapType.NGAPPDU
	ies *ngapType.ProtocolIEContainerInitialContextSetupResponseIEs
}

type GnbPDUSession struct {
	pduSessionId int64
	downlinkTeid uint32
	qosId        int64
}

func (pduSession *GnbPDUSession) GetPduSessionId() int64 {
	return pduSession.pduSessionId
}

func (pduSession *GnbPDUSession) GetTeidDownlink() uint32 {
	return pduSession.downlinkTeid
}

func (pduSession *GnbPDUSession) GetQosId() int64 {
	return pduSession.qosId
}

type InitialContextSetupResponseOpts struct {
	AMFUENGAPID int64
	RANUENGAPID int64
	N3GnbIp     netip.Addr
	PDUSessions [16]*GnbPDUSession
}

func InitialContextSetupResponse(opts *InitialContextSetupResponseOpts) (ngapType.NGAPPDU, error) {
	return NewInitialContextSetupResponseBuilder().
		SetAmfUeNgapId(opts.AMFUENGAPID).SetRanUeNgapId(opts.RANUENGAPID).
		SetPDUSessionResourceSetupListCxtRes(opts.N3GnbIp, opts.PDUSessions).pdu, nil
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

func (builder *InitialContextSetupResponseBuilder) SetPDUSessionResourceSetupListCxtRes(gnbN3IPAddr netip.Addr, pduSessions [16]*GnbPDUSession) *InitialContextSetupResponseBuilder {
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

		transferData, err := GetPDUSessionResourceSetupResponseTransfer(gnbN3IPAddr, pduSession.GetTeidDownlink(), pduSession.GetQosId())
		if err != nil {
			fmt.Printf("failed to get PDUSessionResourceSetupResponseTransfer: %v\n", err)
			continue
		}

		pDUSessionResourceSetupItemCxtRes.PDUSessionID.Value = pduSession.GetPduSessionId()
		pDUSessionResourceSetupItemCxtRes.PDUSessionResourceSetupResponseTransfer = transferData
		PDUSessionResourceSetupListCxtRes.List = append(PDUSessionResourceSetupListCxtRes.List, pDUSessionResourceSetupItemCxtRes)
	}

	if len(PDUSessionResourceSetupListCxtRes.List) == 0 {
		return builder
	}

	builder.ies.List = append(builder.ies.List, ie)

	return builder
}

// func (builder *InitialContextSetupResponseBuilder) Build() ([]byte, error) {
// 	return ngap.Encoder(builder.pdu)
// }

func GetPDUSessionResourceSetupResponseTransfer(ipv4 netip.Addr, teid uint32, qosId int64) ([]byte, error) {
	data := buildPDUSessionResourceSetupResponseTransfer(ipv4, teid, qosId)

	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("failed to encode PDUSessionResourceSetupResponseTransfer: %v", err)
	}

	return encodeData, nil
}

type QosFlowItemExtIEsExtensionValue struct {
	Present int
}

type QosFlowItemExtIEs struct {
	Id             ngapType.ProtocolExtensionID
	Criticality    ngapType.Criticality
	ExtensionValue QosFlowItemExtIEsExtensionValue `aper:"openType,referenceFieldName:Id"`
}

type ProtocolExtensionContainerQosFlowItemExtIEs struct {
	List []QosFlowItemExtIEs `aper:"sizeLB:1,sizeUB:65535"`
}

type QosFlowItem struct {
	QosFlowIdentifier ngapType.QosFlowIdentifier
	Cause             ngapType.Cause                               `aper:"valueLB:0,valueUB:5"`
	IEExtensions      *ProtocolExtensionContainerQosFlowItemExtIEs `aper:"optional"`
}

type QosFlowList struct {
	List []QosFlowItem `aper:"valueExt,sizeLB:1,sizeUB:64"`
}

type PDUSessionResourceSetupResponseTransfer struct {
	QosFlowPerTNLInformation           ngapType.QosFlowPerTNLInformation                                                 `aper:"valueExt"`
	AdditionalQosFlowPerTNLInformation *ngapType.QosFlowPerTNLInformation                                                `aper:"valueExt,optional"`
	SecurityResult                     *ngapType.SecurityResult                                                          `aper:"valueExt,optional"`
	QosFlowFailedToSetupList           *QosFlowList                                                                      `aper:"optional"`
	IEExtensions                       *ngapType.ProtocolExtensionContainerPDUSessionResourceSetupResponseTransferExtIEs `aper:"optional"`
}

func buildPDUSessionResourceSetupResponseTransfer(ipv4 netip.Addr, teid uint32, qosId int64) (data PDUSessionResourceSetupResponseTransfer) {
	// QoS Flow per TNL Information
	qosFlowPerTNLInformation := &data.QosFlowPerTNLInformation
	qosFlowPerTNLInformation.UPTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel

	// UP Transport Layer Information in QoS Flow per TNL Information
	upTransportLayerInformation := &qosFlowPerTNLInformation.UPTransportLayerInformation
	upTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	upTransportLayerInformation.GTPTunnel = new(ngapType.GTPTunnel)

	dowlinkTeid := binary.BigEndian.AppendUint32(nil, teid)
	upTransportLayerInformation.GTPTunnel.GTPTEID.Value = dowlinkTeid
	upTransportLayerInformation.GTPTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(ipv4.String(), "")

	// Associated QoS Flow List in QoS Flow per TNL Information
	associatedQosFlowList := &qosFlowPerTNLInformation.AssociatedQosFlowList

	associatedQosFlowItem := ngapType.AssociatedQosFlowItem{}
	associatedQosFlowItem.QosFlowIdentifier.Value = qosId
	associatedQosFlowList.List = append(associatedQosFlowList.List, associatedQosFlowItem)

	return
}
