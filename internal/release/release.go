package release

import (
	"context"
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/procedure"
	"go.uber.org/zap"
)

const (
	RANUENGAPID  = 1
	PDUSessionID = 1
)

type ReleaseConfig struct {
	AMFUENGAPID       int64
	GnbN2Address      string
	EllaCoreN2Address string
}

func Release(ctx context.Context, cfg ReleaseConfig) error {
	gNodeB, err := gnb.Start(cfg.EllaCoreN2Address, cfg.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	pduSessionStatus := [16]bool{}
	pduSessionStatus[PDUSessionID] = true

	err = procedure.UEContextRelease(ctx, &procedure.UEContextReleaseOpts{
		AMFUENGAPID:   cfg.AMFUENGAPID,
		RANUENGAPID:   RANUENGAPID,
		GnodeB:        gNodeB,
		PDUSessionIDs: pduSessionStatus,
	})
	if err != nil {
		return fmt.Errorf("UEContextReleaseProcedure failed: %v", err)
	}

	logger.Logger.Info(
		"Completed UE Context Release Procedure",
		zap.String("AMF UE NGAP ID", fmt.Sprintf("%d", cfg.AMFUENGAPID)),
		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
	)

	select {}
}
