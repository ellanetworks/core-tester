package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

type SecurityModeCommandOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
}

func SecurityModeCommand(opts *SecurityModeCommandOpts) error {
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

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeSecurityModeCommand {
		return fmt.Errorf("NAS message type is not Security Mode Command (%d), got (%d)", nas.MsgTypeSecurityModeCommand, msg.GmmMessage.GetMessageType())
	}

	if reflect.ValueOf(msg.SecurityModeCommand.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.SecurityModeCommand.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.SecurityModeCommand.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if msg.SecurityModeCommand.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.SecurityModeCommandMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.SelectedNASSecurityAlgorithms).IsZero() {
		return fmt.Errorf("nas security algorithms is missing")
	}

	if msg.SecurityModeCommand.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if msg.SecurityModeCommand.GetNasKeySetIdentifiler() == 7 {
		return fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.ReplayedUESecurityCapabilities).IsZero() {
		return fmt.Errorf("replayed ue security capabilities is missing")
	}

	if msg.IMEISVRequest == nil {
		return fmt.Errorf("imeisv request is missing")
	}

	return nil
}
