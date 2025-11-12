package procedure

import (
	"context"
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type UEContextReleaseOpts struct {
	AMFUENGAPID   int64
	RANUENGAPID   int64
	GnodeB        *gnb.GnodeB
	PDUSessionIDs [16]bool
}

func UEContextRelease(ctx context.Context, opts *UEContextReleaseOpts) error {
	err := opts.GnodeB.SendUEContextReleaseRequest(&gnb.UEContextReleaseRequestOpts{
		AMFUENGAPID:   opts.AMFUENGAPID,
		RANUENGAPID:   opts.RANUENGAPID,
		PDUSessionIDs: opts.PDUSessionIDs,
		Cause:         ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason,
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	logger.Logger.Debug(
		"Sent UE Context Release Request",
		zap.Int64("AMF UE NGAP ID", opts.AMFUENGAPID),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
		zap.String("Cause", "ReleaseDueToNgranGeneratedReason"),
	)

	fr, err := opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = validate.UEContextReleaseCommand(&validate.UEContextReleaseCommandOpts{
		Frame: fr,
		Cause: &ngapType.Cause{
			Present: ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("UEContextRelease validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Received UE Context Release Command",
		zap.Int64("AMF UE NGAP ID", opts.AMFUENGAPID),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
		zap.String("Cause", "ReleaseDueToNgranGeneratedReason"),
	)

	err = opts.GnodeB.SendUEContextReleaseComplete(&gnb.UEContextReleaseCompleteOpts{
		AMFUENGAPID: opts.AMFUENGAPID,
		RANUENGAPID: opts.RANUENGAPID,
		// PDUSessionIDs: opts.PDUSessionIDs,
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	logger.Logger.Debug(
		"Sent UE Context Release Complete",
		zap.Int64("AMF UE NGAP ID", opts.AMFUENGAPID),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	return nil
}
