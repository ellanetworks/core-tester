package validate

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

type RegistrationRejectOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
	Cause  uint8
}

func RegistrationReject(opts *RegistrationRejectOpts) error {
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

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeRegistrationReject {
		return fmt.Errorf("NAS message type is not Registration Reject (%d), got (%d)", nas.MsgTypeRegistrationReject, msg.GmmMessage.GetMessageType())
	}

	if msg.RegistrationReject == nil {
		return fmt.Errorf("NAS Registration Reject message is nil")
	}

	if msg.RegistrationReject.GetCauseValue() != opts.Cause {
		return fmt.Errorf("NAS Registration Reject Cause is not Unknown UE (%x), received (%x)", opts.Cause, msg.RegistrationReject.GetCauseValue())
	}

	return nil
}
