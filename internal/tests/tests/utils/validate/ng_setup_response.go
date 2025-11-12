package validate

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/free5gc/ngap/ngapType"
)

type NGSetupResponseValidationOpts struct {
	MCC string
	MNC string
	SST int32
	SD  string
}

func NGSetupResponse(nGSetupResponse *ngapType.NGSetupResponse, opts *NGSetupResponseValidationOpts) error {
	var (
		amfName             *ngapType.AMFName
		guamiList           *ngapType.ServedGUAMIList
		relativeAMFCapacity *ngapType.RelativeAMFCapacity
		plmnSupportList     *ngapType.PLMNSupportList
	)

	for _, ie := range nGSetupResponse.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFName:
			amfName = ie.Value.AMFName
		case ngapType.ProtocolIEIDServedGUAMIList:
			guamiList = ie.Value.ServedGUAMIList
		case ngapType.ProtocolIEIDRelativeAMFCapacity:
			relativeAMFCapacity = ie.Value.RelativeAMFCapacity
		case ngapType.ProtocolIEIDPLMNSupportList:
			plmnSupportList = ie.Value.PLMNSupportList
		default:
			return fmt.Errorf("NGSetupResponse IE ID (%d) not supported", ie.Id.Value)
		}
	}

	if amfName == nil {
		return fmt.Errorf("AMF Name is missing in NGSetupResponse")
	}

	if amfName.Value != "amf" {
		return fmt.Errorf("AMF Name value is incorrect, got: %s, want: amf", amfName.Value)
	}

	if guamiList == nil {
		return fmt.Errorf("served GUAMI List is missing in NGSetupResponse")
	}

	if relativeAMFCapacity == nil {
		return fmt.Errorf("relative AMF Capacity is missing in NGSetupResponse")
	}

	if plmnSupportList == nil {
		return fmt.Errorf("PLMN Support List is missing in NGSetupResponse")
	}

	// check plmnSupportList has exactly one item
	if len(plmnSupportList.List) != 1 {
		return fmt.Errorf("PLMN Support List should have exactly one item, got: %d", len(plmnSupportList.List))
	}

	mcc, mnc := plmnIDToString(plmnSupportList.List[0].PLMNIdentity)
	if mcc != opts.MCC {
		return fmt.Errorf("PLMN Identity MCC is incorrect, got: %s, want: %s", mcc, opts.MCC)
	}

	if mnc != opts.MNC {
		return fmt.Errorf("PLMN Identity MNC is incorrect, got: %s, want: %s", mnc, opts.MNC)
	}

	if len(plmnSupportList.List[0].SliceSupportList.List) != 1 {
		return fmt.Errorf("slice support list should have exactly one item, got: %d", len(plmnSupportList.List[0].SliceSupportList.List))
	}

	sst, sd := snssaiToString(plmnSupportList.List[0].SliceSupportList.List[0].SNSSAI)
	if sst != opts.SST {
		return fmt.Errorf("SST is incorrect, got: %v, want: %v", sst, opts.SST)
	}

	if sd != opts.SD {
		return fmt.Errorf("SD is incorrect, got: %s, want: %s", sd, opts.SD)
	}

	return nil
}

func plmnIDToString(ngapPlmnID ngapType.PLMNIdentity) (string, string) {
	value := ngapPlmnID.Value
	hexString := strings.Split(hex.EncodeToString(value), "")
	mcc := hexString[1] + hexString[0] + hexString[3]

	var mnc string

	if hexString[2] == "f" {
		mnc = hexString[5] + hexString[4]
	} else {
		mnc = hexString[2] + hexString[5] + hexString[4]
	}

	return mcc, mnc
}

func snssaiToString(ngapSnssai ngapType.SNSSAI) (int32, string) {
	sst := int32(ngapSnssai.SST.Value[0])
	sd := ""

	if ngapSnssai.SD != nil {
		sd = hex.EncodeToString(ngapSnssai.SD.Value)
	}

	return sst, sd
}
