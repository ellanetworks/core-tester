package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

type ServiceAcceptOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
}

func ServiceAccept(opts *ServiceAcceptOpts) error {
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

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeServiceAccept {
		return fmt.Errorf("NAS message type is not Service Accept (%d), got (%d)", nas.MsgTypeServiceAccept, msg.GmmMessage.GetMessageType())
	}

	if msg.ServiceAccept == nil {
		return fmt.Errorf("NAS Service Accept message is nil")
	}

	if reflect.ValueOf(msg.ServiceAccept.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.ServiceAccept.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.ServiceAccept.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if msg.ServiceAccept.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.ServiceAccept.ServiceAcceptMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if msg.ServiceAcceptMessageIdentity.GetMessageType() != nas.MsgTypeServiceAccept {
		return fmt.Errorf("message type not the expected value")
	}

	return nil
}
