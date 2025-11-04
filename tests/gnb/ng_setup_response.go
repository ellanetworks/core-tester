package gnb

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/gnb/build"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type NGSetupResponse struct{}

func (NGSetupResponse) Meta() engine.Meta {
	return engine.Meta{
		ID:      "gnb/ngap/setup_response",
		Summary: "NGSetup request/response test validating the NGSetupResponse message contents",
	}
}

func (t NGSetupResponse) Run(env engine.Env) error {
	gNodeB, err := gnb.Start(env.CoreN2Address, env.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer func() {
		err := gNodeB.Close()
		if err != nil {
			fmt.Printf("error closing gNB: %v\n", err)
		}
	}()

	opts := &build.NGSetupRequestOpts{
		Mcc: "001",
		Mnc: "01",
		Sst: "01",
		Tac: "000001",
	}

	err = gNodeB.SendNGSetupRequest(opts)
	if err != nil {
		return fmt.Errorf("could not send NGSetupRequest: %v", err)
	}

	timeout := 30 * time.Second

	fr, err := gNodeB.ReceiveFrame(timeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 0)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(fr.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.SuccessfulOutcome == nil {
		return fmt.Errorf("NGAP PDU is not a SuccessfulOutcome")
	}

	if pdu.SuccessfulOutcome.ProcedureCode.Value != ngapType.ProcedureCodeNGSetup {
		return fmt.Errorf("NGAP ProcedureCode is not NGSetup (%d)", ngapType.ProcedureCodeNGSetup)
	}

	nGSetupResponse := pdu.SuccessfulOutcome.Value.NGSetupResponse
	if nGSetupResponse == nil {
		return fmt.Errorf("NGSetupResponse is nil")
	}

	err = validateNGSetupResponse(nGSetupResponse)
	if err != nil {
		return fmt.Errorf("NGSetupResponse validation failed: %v", err)
	}

	return nil
}

func validateNGSetupResponse(nGSetupResponse *ngapType.NGSetupResponse) error {
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
	if mcc != "001" {
		return fmt.Errorf("PLMN Identity MCC is incorrect, got: %s, want: 001", mcc)
	}

	if mnc != "01" {
		return fmt.Errorf("PLMN Identity MNC is incorrect, got: %s, want: 01", mnc)
	}

	if len(plmnSupportList.List[0].SliceSupportList.List) != 1 {
		return fmt.Errorf("slice support list should have exactly one item, got: %d", len(plmnSupportList.List[0].SliceSupportList.List))
	}

	sst, sd := snssaiToString(plmnSupportList.List[0].SliceSupportList.List[0].SNSSAI)
	if sst != 1 {
		return fmt.Errorf("SST is incorrect, got: %v, want: 1", sst)
	}

	if sd != "102030" {
		return fmt.Errorf("SD is incorrect, got: %s, want: 102030", sd)
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
