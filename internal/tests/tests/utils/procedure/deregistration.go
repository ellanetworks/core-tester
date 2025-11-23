package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/ue"
)

type DeregistrationOpts struct {
	UE          *ue.UE
	AMFUENGAPID int64
	RANUENGAPID int64
}

func Deregistration(opts *DeregistrationOpts) error {
	err := opts.UE.SendDeregistrationRequest(opts.AMFUENGAPID, opts.RANUENGAPID)
	if err != nil {
		return fmt.Errorf("could not build Deregistration Request NAS PDU: %v", err)
	}

	// _, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentUEContextReleaseCommand, 1*time.Second)
	// if err != nil {
	// 	return fmt.Errorf("failed to wait for UE Context Release Command: %v", err)
	// }

	err = opts.UE.WaitForRRCRelease(1 * time.Second)
	if err != nil {
		return fmt.Errorf("could not receive RRC Release: %v", err)
	}

	return nil
}
