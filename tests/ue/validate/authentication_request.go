package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

func AuthenticationRequest(nasPDU *ngapType.NASPDU, ueIns *ue.UE) ([16]uint8, [16]uint8, error) {
	if nasPDU == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ueIns.DecodeNAS(nasPDU.Value)
	if err != nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeAuthenticationRequest {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS message type is not Authentication Request (%d), got (%d)", nas.MsgTypeAuthenticationRequest, msg.GmmMessage.GetMessageType())
	}

	if msg.AuthenticationRequest == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS Authentication Request message is nil")
	}

	if msg.AuthenticationParameterRAND == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("NAS Authentication Request RAND is nil")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.ExtendedProtocolDiscriminator).IsZero() {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("extended protocol is missing")
	}

	if msg.AuthenticationRequest.GetExtendedProtocolDiscriminator() != 126 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("extended protocol not the expected value")
	}

	if msg.AuthenticationRequest.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("spare half octet not the expected value")
	}

	if msg.AuthenticationRequest.GetSecurityHeaderType() != 0 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.AuthenticationRequestMessageIdentity).IsZero() {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("message type is missing")
	}

	if msg.AuthenticationRequest.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("spare half octet not the expected value")
	}

	if msg.AuthenticationRequest.GetNasKeySetIdentifiler() == 7 {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.ABBA).IsZero() {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("ABBA is missing")
	}

	if msg.AuthenticationRequest.GetABBAContents() == nil {
		return [16]uint8{}, [16]uint8{}, fmt.Errorf("ABBA content is missing")
	}

	rand := msg.GetRANDValue()
	autn := msg.GetAUTN()

	return rand, autn, nil
}
