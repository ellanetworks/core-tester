package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/free5gc/ngap/ngapType"
)

type UEContextReleaseOpts struct {
	AMFUENGAPID   int64
	RANUENGAPID   int64
	GnodeB        *gnb.GnodeB
	PDUSessionIDs [16]bool
}

func UEContextRelease(opts *UEContextReleaseOpts) error {
	err := opts.GnodeB.SendUEContextReleaseRequest(&gnb.UEContextReleaseRequestOpts{
		AMFUENGAPID:   opts.AMFUENGAPID,
		RANUENGAPID:   opts.RANUENGAPID,
		PDUSessionIDs: opts.PDUSessionIDs,
		Cause:         ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason,
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentUEContextReleaseCommand, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	return nil
}
