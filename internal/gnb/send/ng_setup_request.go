package build

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
)

type NGSetupRequestOpts struct {
	Mcc string
	Mnc string
	Tac string
	Sst string
	Sd  string
}

func NGSetupRequest(opts *NGSetupRequestOpts) (ngapType.NGAPPDU, error) {
	if opts.Mcc == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("MCC is required to build NGSetupRequest")
	}

	if opts.Mnc == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("MNC is required to build NGSetupRequest")
	}

	plmnID, err := GetMccAndMncInOctets(opts.Mcc, opts.Mnc)
	if err != nil {
		return ngapType.NGAPPDU{}, fmt.Errorf("could not get plmnID in octets: %v", err)
	}

	if opts.Sst == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("SST is required to build NGSetupRequest")
	}

	sst, sd, err := GetSliceInBytes(opts.Sst, opts.Sd)
	if err != nil {
		return ngapType.NGAPPDU{}, fmt.Errorf("could not get slice info in bytes: %v", err)
	}

	if opts.Tac == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("TAC is required to build NGSetupRequest")
	}

	tac, err := GetTacInBytes(opts.Tac)
	if err != nil {
		return ngapType.NGAPPDU{}, fmt.Errorf("could not get tac in bytes: %v", err)
	}

	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeNGSetup
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentNGSetupRequest
	initiatingMessage.Value.NGSetupRequest = new(ngapType.NGSetupRequest)

	nGSetupRequest := initiatingMessage.Value.NGSetupRequest
	nGSetupRequestIEs := &nGSetupRequest.ProtocolIEs

	ie := ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDGlobalRANNodeID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentGlobalRANNodeID
	ie.Value.GlobalRANNodeID = new(ngapType.GlobalRANNodeID)

	globalRANNodeID := ie.Value.GlobalRANNodeID
	globalRANNodeID.Present = ngapType.GlobalRANNodeIDPresentGlobalGNBID
	globalRANNodeID.GlobalGNBID = new(ngapType.GlobalGNBID)

	globalGNBID := globalRANNodeID.GlobalGNBID
	globalGNBID.PLMNIdentity.Value = plmnID
	globalGNBID.GNBID.Present = ngapType.GNBIDPresentGNBID
	globalGNBID.GNBID.GNBID = new(aper.BitString)

	gNBID := globalGNBID.GNBID.GNBID

	*gNBID = aper.BitString{
		Bytes:     []byte{0x45, 0x46, 0x47},
		BitLength: 24,
	}

	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

	// RANNodeName
	ie = ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANNodeName
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentRANNodeName
	ie.Value.RANNodeName = new(ngapType.RANNodeName)

	rANNodeName := ie.Value.RANNodeName
	rANNodeName.Value = "Ella-Core-Tester"

	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)
	ie = ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDSupportedTAList
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentSupportedTAList
	ie.Value.SupportedTAList = new(ngapType.SupportedTAList)

	supportedTAList := ie.Value.SupportedTAList

	supportedTAItem := ngapType.SupportedTAItem{}
	supportedTAItem.TAC.Value = tac

	broadcastPLMNList := &supportedTAItem.BroadcastPLMNList
	broadcastPLMNItem := ngapType.BroadcastPLMNItem{}
	broadcastPLMNItem.PLMNIdentity.Value = plmnID

	sliceSupportList := &broadcastPLMNItem.TAISliceSupportList
	sliceSupportItem := ngapType.SliceSupportItem{}
	sliceSupportItem.SNSSAI.SST.Value = sst

	if sd != nil {
		sliceSupportItem.SNSSAI.SD = new(ngapType.SD)
		sliceSupportItem.SNSSAI.SD.Value = sd
	}

	sliceSupportList.List = append(sliceSupportList.List, sliceSupportItem)

	broadcastPLMNList.List = append(broadcastPLMNList.List, broadcastPLMNItem)

	supportedTAList.List = append(supportedTAList.List, supportedTAItem)

	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

	// PagingDRX
	ie = ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDDefaultPagingDRX
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentDefaultPagingDRX
	ie.Value.DefaultPagingDRX = new(ngapType.PagingDRX)

	pagingDRX := ie.Value.DefaultPagingDRX
	pagingDRX.Value = ngapType.PagingDRXPresentV128

	nGSetupRequestIEs.List = append(nGSetupRequestIEs.List, ie)

	return pdu, nil
}

func GetTacInBytes(tacStr string) ([]byte, error) {
	resu, err := hex.DecodeString(tacStr)
	if err != nil {
		return nil, fmt.Errorf("could not decode tac to bytes: %v", err)
	}

	return resu, nil
}

func GetSliceInBytes(sst string, sd string) ([]byte, []byte, error) {
	sstBytes, err := hex.DecodeString(sst)
	if err != nil {
		return nil, nil, fmt.Errorf("could not decode sst to bytes: %v", err)
	}

	if sd != "" {
		sdBytes, err := hex.DecodeString(sd)
		if err != nil {
			return sstBytes, nil, fmt.Errorf("could not decode sd to bytes: %v", err)
		}

		return sstBytes, sdBytes, nil
	}

	return sstBytes, nil, nil
}

func GetMccAndMncInOctets(mccStr string, mncStr string) ([]byte, error) {
	var res string

	mcc := reverse(mccStr)
	mnc := reverse(mncStr)

	if len(mnc) == 2 {
		res = fmt.Sprintf("%c%cf%c%c%c", mcc[1], mcc[2], mcc[0], mnc[0], mnc[1])
	} else {
		res = fmt.Sprintf("%c%c%c%c%c%c", mcc[1], mcc[2], mnc[2], mcc[0], mnc[0], mnc[1])
	}

	resu, err := hex.DecodeString(res)
	if err != nil {
		return nil, fmt.Errorf("could not decode mcc/mnc to octets: %v", err)
	}

	return resu, nil
}

func reverse(s string) string {
	var aux string
	for _, valor := range s {
		aux = string(valor) + aux
	}

	return aux
}
