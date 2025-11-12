package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

type AuthenticationRejectOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
}

func AuthenticationReject(opts *AuthenticationRejectOpts) error {
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

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeAuthenticationReject {
		return fmt.Errorf("NAS message type is not Authentication Reject (%d), got (%d)", nas.MsgTypeAuthenticationReject, msg.GmmMessage.GetMessageType())
	}

	if reflect.ValueOf(msg.AuthenticationReject.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.AuthenticationReject.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.AuthenticationReject.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if msg.AuthenticationReject.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if reflect.ValueOf(msg.AuthenticationReject.AuthenticationRejectMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	return nil
}
