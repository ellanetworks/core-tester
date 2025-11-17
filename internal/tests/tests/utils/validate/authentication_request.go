package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

type AuthenticationRequestOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
}

func AuthenticationRequest(opts *AuthenticationRequestOpts) error {
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

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeAuthenticationRequest {
		return fmt.Errorf("NAS message type is not Authentication Request (%d), got (%d)", nas.MsgTypeAuthenticationRequest, msg.GmmMessage.GetMessageType())
	}

	if msg.AuthenticationRequest == nil {
		return fmt.Errorf("NAS Authentication Request message is nil")
	}

	if msg.AuthenticationParameterRAND == nil {
		return fmt.Errorf("NAS Authentication Request RAND is nil")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.AuthenticationRequest.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.AuthenticationRequest.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if msg.AuthenticationRequest.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.AuthenticationRequestMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if msg.AuthenticationRequest.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if msg.AuthenticationRequest.GetNasKeySetIdentifiler() == 7 {
		return fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(msg.AuthenticationRequest.ABBA).IsZero() {
		return fmt.Errorf("ABBA is missing")
	}

	if msg.AuthenticationRequest.GetABBAContents() == nil {
		return fmt.Errorf("ABBA content is missing")
	}

	return nil
}
