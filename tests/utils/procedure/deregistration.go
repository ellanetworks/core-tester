package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

type DeregistrationOpts struct {
	GnodeB           *gnb.GnodeB
	UE               *ue.UE
	AMFUENGAPID      int64
	RANUENGAPID      int64
	MCC              string
	MNC              string
	GNBID            string
	TAC              string
	NGAPFrameTimeout time.Duration
}

func Deregistration(opts *DeregistrationOpts) error {
	deregBytes, err := ue.BuildDeregistrationRequest(&ue.DeregistrationRequestOpts{
		Guti: opts.UE.UeSecurity.Guti,
		Ksi:  opts.UE.UeSecurity.NgKsi.Ksi,
	})
	if err != nil {
		return fmt.Errorf("could not build Deregistration Request NAS PDU: %v", err)
	}

	encodedPdu, err := opts.UE.EncodeNasPduWithSecurity(deregBytes, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
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

	fr, err := opts.GnodeB.ReceiveFrame(opts.NGAPFrameTimeout)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = validate.UEContextRelease(&validate.UEContextReleaseOpts{
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

	err = opts.GnodeB.SendUEContextReleaseComplete(&gnb.UEContextReleaseCompleteOpts{
		AMFUENGAPID: opts.AMFUENGAPID,
		RANUENGAPID: opts.RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("could not send UEContextReleaseComplete: %v", err)
	}

	return nil
}
