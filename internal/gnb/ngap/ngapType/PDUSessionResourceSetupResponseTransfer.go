package ngapType

import freeNgapType "github.com/free5gc/ngap/ngapType"

type PDUSessionResourceSetupResponseTransfer struct {
	QosFlowPerTNLInformation           freeNgapType.QosFlowPerTNLInformation                                                 `aper:"valueExt"`
	AdditionalQosFlowPerTNLInformation *freeNgapType.QosFlowPerTNLInformation                                                `aper:"valueExt,optional"`
	SecurityResult                     *freeNgapType.SecurityResult                                                          `aper:"valueExt,optional"`
	QosFlowFailedToSetupList           *QosFlowList                                                                          `aper:"optional"`
	IEExtensions                       *freeNgapType.ProtocolExtensionContainerPDUSessionResourceSetupResponseTransferExtIEs `aper:"optional"`
}
