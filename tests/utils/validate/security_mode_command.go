package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
)

type SecurityModeCommandOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
}

func SecurityModeCommand(opts *SecurityModeCommandOpts) (int32, models.ScType, error) {
	if opts.NASPDU == nil {
		return 0, "", fmt.Errorf("NAS PDU is nil")
	}

	msg, err := opts.UE.DecodeNAS(opts.NASPDU.Value)
	if err != nil {
		return 0, "", fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return 0, "", fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return 0, "", fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeSecurityModeCommand {
		return 0, "", fmt.Errorf("NAS message type is not Security Mode Command (%d), got (%d)", nas.MsgTypeSecurityModeCommand, msg.GmmMessage.GetMessageType())
	}

	if reflect.ValueOf(msg.SecurityModeCommand.ExtendedProtocolDiscriminator).IsZero() {
		return 0, "", fmt.Errorf("extended protocol is missing")
	}

	if msg.SecurityModeCommand.GetExtendedProtocolDiscriminator() != 126 {
		return 0, "", fmt.Errorf("extended protocol not the expected value")
	}

	if msg.SecurityModeCommand.GetSecurityHeaderType() != 0 {
		return 0, "", fmt.Errorf("security header type not the expected value")
	}

	if msg.SecurityModeCommand.SpareHalfOctetAndSecurityHeaderType.GetSpareHalfOctet() != 0 {
		return 0, "", fmt.Errorf("spare half octet not the expected value")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.SecurityModeCommandMessageIdentity).IsZero() {
		return 0, "", fmt.Errorf("message type is missing")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.SelectedNASSecurityAlgorithms).IsZero() {
		return 0, "", fmt.Errorf("nas security algorithms is missing")
	}

	if msg.SecurityModeCommand.SpareHalfOctetAndNgksi.GetSpareHalfOctet() != 0 {
		return 0, "", fmt.Errorf("spare half octet not the expected value")
	}

	if msg.SecurityModeCommand.GetNasKeySetIdentifiler() == 7 {
		return 0, "", fmt.Errorf("ngKSI not the expected value")
	}

	if reflect.ValueOf(msg.SecurityModeCommand.ReplayedUESecurityCapabilities).IsZero() {
		return 0, "", fmt.Errorf("replayed ue security capabilities is missing")
	}

	if msg.IMEISVRequest == nil {
		return 0, "", fmt.Errorf("imeisv request is missing")
	}

	ksi := int32(msg.SecurityModeCommand.GetNasKeySetIdentifiler())

	var tsc models.ScType

	switch msg.SecurityModeCommand.GetTSC() {
	case nasMessage.TypeOfSecurityContextFlagNative:
		tsc = models.ScType_NATIVE
	case nasMessage.TypeOfSecurityContextFlagMapped:
		tsc = models.ScType_MAPPED
	}

	return ksi, tsc, nil
}
