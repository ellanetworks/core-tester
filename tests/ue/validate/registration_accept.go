package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
)

func RegistrationAcceptInitialContextSetupRequest(nasPDU *ngapType.NASPDU, ueIns *ue.UE) (*nasType.GUTI5G, error) {
	if nasPDU == nil {
		return nil, fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ueIns.DecodeNAS(nasPDU.Value)
	if err != nil {
		return nil, fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return nil, fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return nil, fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeRegistrationAccept {
		return nil, fmt.Errorf("NAS message type is not Registration Accept (%d), got (%d)", nas.MsgTypeRegistrationAccept, msg.GmmMessage.GetMessageType())
	}

	if msg.RegistrationAccept == nil {
		return nil, fmt.Errorf("NAS Registration Accept message is nil")
	}

	if reflect.ValueOf(msg.RegistrationAccept.ExtendedProtocolDiscriminator).IsZero() {
		return nil, fmt.Errorf("extended protocol is missing")
	}

	if msg.RegistrationAccept.GetExtendedProtocolDiscriminator() != 126 {
		return nil, fmt.Errorf("extended protocol not the expected value")
	}

	if msg.RegistrationAccept.GetSpareHalfOctet() != 0 {
		return nil, fmt.Errorf("spare half octet not the expected value")
	}

	if msg.RegistrationAccept.GetSecurityHeaderType() != 0 {
		return nil, fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.RegistrationAccept.RegistrationAcceptMessageIdentity).IsZero() {
		return nil, fmt.Errorf("message type is missing")
	}

	if msg.RegistrationAcceptMessageIdentity.GetMessageType() != 66 {
		return nil, fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(msg.RegistrationAccept.RegistrationResult5GS).IsZero() {
		return nil, fmt.Errorf("registration result 5GS is missing")
	}

	if msg.GetRegistrationResultValue5GS() != 1 {
		return nil, fmt.Errorf("registration result 5GS not the expected value")
	}

	if msg.RegistrationAccept.GUTI5G == nil {
		return nil, fmt.Errorf("GUTI5G is nil")
	}

	snssai := msg.RegistrationAccept.AllowedNSSAI.GetSNSSAIValue()

	if len(snssai) == 0 {
		return nil, fmt.Errorf("allowed NSSAI is missing")
	}

	sst := int32(snssai[1])
	sd := fmt.Sprintf("%x%x%x", snssai[2], snssai[3], snssai[4])

	if sst != ueIns.Snssai.Sst {
		return nil, fmt.Errorf("allowed NSSAI SST not the expected value, got: %d, want: %d", sst, ueIns.Snssai.Sst)
	}

	if sd != ueIns.Snssai.Sd {
		return nil, fmt.Errorf("allowed NSSAI SD not the expected value, got: %s, want: %s", sd, ueIns.Snssai.Sd)
	}

	if msg.T3512Value == nil {
		return nil, fmt.Errorf("T3512 value is nil")
	}

	timerInSeconds := utils.NasToGPRSTimer3(msg.T3512Value.Octet)
	if timerInSeconds != 3600 {
		return nil, fmt.Errorf("T3512 timer in seconds not the expected value, got: %d, want: 3600", timerInSeconds)
	}

	return msg.RegistrationAccept.GUTI5G, nil
}
