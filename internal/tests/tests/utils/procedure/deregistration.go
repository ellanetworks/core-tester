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

	err = opts.UE.WaitForRRCRelease(1 * time.Second)
	if err != nil {
		return fmt.Errorf("could not receive RRC Release: %v", err)
	}

	return nil
}
