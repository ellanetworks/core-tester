package procedure

import (
	"context"
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/ngap/ngapType"
)

type UEContextReleaseOpts struct {
	AMFUENGAPID int64
	RANUENGAPID int64
	GnodeB      *gnb.GnodeB
}

func UEContextRelease(ctx context.Context, opts *UEContextReleaseOpts) error {
	err := opts.GnodeB.SendUEContextReleaseRequest(&gnb.UEContextReleaseRequestOpts{
		AMFUENGAPID: opts.AMFUENGAPID,
		RANUENGAPID: opts.RANUENGAPID,
		PDUSessionIDs: [16]bool{
			true, false, false, false, false, false, false, false,
			false, false, false, false, false, false, false, false,
		},
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	fr, err := opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = validate.UEContextReleaseCommand(&validate.UEContextReleaseCommandOpts{
		Frame: fr,
		Cause: &ngapType.Cause{
			Present: ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentUserInactivity,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("UEContextRelease validation failed: %v", err)
	}

	err = opts.GnodeB.SendUEContextReleaseComplete(&gnb.UEContextReleaseCompleteOpts{
		AMFUENGAPID: opts.AMFUENGAPID,
		RANUENGAPID: opts.RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	return nil
}
