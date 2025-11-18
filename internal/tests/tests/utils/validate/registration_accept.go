package validate

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
)

type RegistrationAcceptOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
	Sst    int32
	Sd     string
	Mcc    string
	Mnc    string
}

func RegistrationAccept(opts *RegistrationAcceptOpts) error {
	if opts.NASPDU == nil {
		return fmt.Errorf("NAS PDU is nil")
	}

	msg, err := opts.UE.DecodeNAS(opts.NASPDU.Value)
	if err != nil {
		return fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeRegistrationAccept {
		return fmt.Errorf("NAS message type is not Registration Accept (%d), got (%d)", nas.MsgTypeRegistrationAccept, msg.GmmMessage.GetMessageType())
	}

	if msg.RegistrationAccept == nil {
		return fmt.Errorf("NAS Registration Accept message is nil")
	}

	if reflect.ValueOf(msg.RegistrationAccept.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.RegistrationAccept.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.RegistrationAccept.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if msg.RegistrationAccept.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.RegistrationAccept.RegistrationAcceptMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if msg.RegistrationAcceptMessageIdentity.GetMessageType() != 66 {
		return fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(msg.RegistrationAccept.RegistrationResult5GS).IsZero() {
		return fmt.Errorf("registration result 5GS is missing")
	}

	if msg.GetRegistrationResultValue5GS() != 1 {
		return fmt.Errorf("registration result 5GS not the expected value")
	}

	if msg.RegistrationAccept.GUTI5G == nil {
		return fmt.Errorf("GUTI5G is nil")
	}

	guti5GStr := buildGUTI5G(*msg.RegistrationAccept.GUTI5G)

	prefix := fmt.Sprintf("%s%scafe", opts.Mcc, opts.Mnc)
	if !strings.HasPrefix(guti5GStr, prefix) {
		return fmt.Errorf("GUTI5G MCC/MNC/AMF ID not the expected value, got: %s, want prefix: %s", guti5GStr, prefix)
	}

	snssai := msg.RegistrationAccept.AllowedNSSAI.GetSNSSAIValue()

	if len(snssai) == 0 {
		return fmt.Errorf("allowed NSSAI is missing")
	}

	sst := int32(snssai[1])
	sd := fmt.Sprintf("%x%x%x", snssai[2], snssai[3], snssai[4])

	if sst != opts.Sst {
		return fmt.Errorf("allowed NSSAI SST not the expected value, got: %d, want: %d", sst, opts.Sst)
	}

	if sd != opts.Sd {
		return fmt.Errorf("allowed NSSAI SD not the expected value, got: %s, want: %s", sd, opts.Sd)
	}

	if msg.T3512Value == nil {
		return fmt.Errorf("T3512 value is nil")
	}

	timerInSeconds := utils.NasToGPRSTimer3(msg.T3512Value.Octet)
	if timerInSeconds != 3600 {
		return fmt.Errorf("T3512 timer in seconds not the expected value, got: %d, want: 3600", timerInSeconds)
	}

	return nil
}

func buildGUTI5G(gutiNas nasType.GUTI5G) string {
	mcc1 := gutiNas.GetMCCDigit1()
	mcc2 := gutiNas.GetMCCDigit2()
	mcc3 := gutiNas.GetMCCDigit3()
	mnc1 := gutiNas.GetMNCDigit1()
	mnc2 := gutiNas.GetMNCDigit2()
	mnc3 := gutiNas.GetMNCDigit3()

	amfRegionID := gutiNas.GetAMFRegionID()
	amfSetID := gutiNas.GetAMFSetID()
	amfPointer := gutiNas.GetAMFPointer()
	amfID := nasToAmfId(amfRegionID, amfSetID, amfPointer)

	tmsi := hex.EncodeToString(gutiNas.Octet[7:11])

	if mnc3 == 0x0F {
		return fmt.Sprintf("%d%d%d%d%d%s%s", mcc1, mcc2, mcc3, mnc1, mnc2, amfID, tmsi)
	}

	return fmt.Sprintf("%d%d%d%d%d%d%s%s", mcc1, mcc2, mcc3, mnc1, mnc2, mnc3, amfID, tmsi)
}

func nasToAmfId(regionID uint8, setID uint16, pointer uint8) string {
	setID &= 0x03FF // 10 bits
	pointer &= 0x3F // 6 bits

	b0 := regionID
	b1 := uint8(setID >> 2)
	b2 := uint8((setID&0x3)<<6) | (pointer & 0x3F)

	return fmt.Sprintf("%02x%02x%02x", b0, b1, b2)
}
