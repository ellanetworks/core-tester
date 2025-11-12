package validate

import (
	"fmt"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/ngap/ngapType"
)

type IdentityRequestOpts struct {
	NASPDU *ngapType.NASPDU
	UE     *ue.UE
}

func IdentityRequest(opts *IdentityRequestOpts) error {
	if opts.NASPDU == nil {
		return fmt.Errorf("NAS PDU is nil")
	}

	msg, err := opts.UE.DecodeNAS(opts.NASPDU.Value)
	if err != nil {
		return fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if reflect.ValueOf(msg.IdentityRequest.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.IdentityRequest.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.IdentityRequest.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if msg.IdentityRequest.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.IdentityRequest.IdentityRequestMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if msg.IdentityRequestMessageIdentity.GetMessageType() != 91 {
		return fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(msg.IdentityRequest.SpareHalfOctetAndIdentityType).IsZero() {
		return fmt.Errorf("spare half octet and identity type is missing")
	}

	return nil
}
