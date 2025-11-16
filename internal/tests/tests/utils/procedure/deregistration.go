package procedure

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/validate"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type DeregistrationOpts struct {
	GnodeB      *gnb.GnodeB
	UE          *ue.UE
	AMFUENGAPID int64
	RANUENGAPID int64
	MCC         string
	MNC         string
	GNBID       string
	TAC         string
}

func Deregistration(ctx context.Context, opts *DeregistrationOpts) error {
	deregBytes, err := ue.BuildDeregistrationRequest(&ue.DeregistrationRequestOpts{
		Guti: opts.UE.UeSecurity.Guti,
		Ksi:  opts.UE.UeSecurity.NgKsi.Ksi,
	})
	if err != nil {
		return fmt.Errorf("could not build Deregistration Request NAS PDU: %v", err)
	}

	encodedPdu, err := opts.UE.EncodeNasPduWithSecurity(deregBytes, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Deregistration Msg", opts.UE.UeSecurity.Supi)
	}

	err = opts.GnodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: opts.AMFUENGAPID,
		RANUeNgapID: opts.RANUENGAPID,
		Mcc:         opts.MCC,
		Mnc:         opts.MNC,
		GnbID:       opts.GNBID,
		Tac:         opts.TAC,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.Logger.Debug(
		"Sent Uplink NAS Transport with Deregistration Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.String("GNB ID", opts.GNBID),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	fr, err := opts.GnodeB.WaitForNextFrame(500 * time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = validate.UEContextReleaseCommand(&validate.UEContextReleaseCommandOpts{
		Frame: fr,
		Cause: &ngapType.Cause{
			Present: ngapType.CausePresentNas,
			Nas: &ngapType.CauseNas{
				Value: ngapType.CauseNasPresentDeregister,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("UEContextRelease validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Received UE Context Release Command",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	err = opts.GnodeB.SendUEContextReleaseComplete(&gnb.UEContextReleaseCompleteOpts{
		AMFUENGAPID: opts.AMFUENGAPID,
		RANUENGAPID: opts.RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	logger.Logger.Debug(
		"Sent UE Context Release Complete",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	return nil
}
