package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/ngap/ngapType"
)

type DeregistrationOpts struct {
	GnodeB      *gnb.GnodeB
	UE          *ue.UE
	AMFUENGAPID int64
	RANUENGAPID int64
}

func Deregistration(opts *DeregistrationOpts) error {
	err := opts.UE.SendDeregistrationRequest(opts.AMFUENGAPID, opts.RANUENGAPID)
	if err != nil {
		return fmt.Errorf("could not build Deregistration Request NAS PDU: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentUEContextReleaseCommand, 1*time.Second)
	if err != nil {
		return fmt.Errorf("failed to wait for UE Context Release Command: %v", err)
	}

	return nil
}
