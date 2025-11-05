package validate

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
)

func RegistrationReject(nasPDU *ngapType.NASPDU, ueIns *ue.UE) error {
	if nasPDU == nil {
		return fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ueIns.DecodeNAS(nasPDU.Value)
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

	if msg.RegistrationReject.GetCauseValue() != nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork {
		return fmt.Errorf("NAS Registration Reject Cause is not Unknown UE (%x), received (%x)", nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork, msg.RegistrationReject.GetCauseValue())
	}

	return nil
}
