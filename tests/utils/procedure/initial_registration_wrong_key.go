package procedure

import (
	"context"
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type AuthenticationResponseWrongKeysOpts struct {
	Mcc         string
	Mnc         string
	Tac         string
	GNBID       string
	RANUENGAPID int64
	UE          *ue.UE
	GnodeB      *gnb.GnodeB
}

func AuthenticationResponseWrongKeys(ctx context.Context, opts *AuthenticationResponseWrongKeysOpts) error {
	nasPDU, err := ue.BuildRegistrationRequest(&ue.RegistrationRequestOpts{
		RegistrationType:  nasMessage.RegistrationType5GSInitialRegistration,
		RequestedNSSAI:    nil,
		UplinkDataStatus:  nil,
		IncludeCapability: false,
		UESecurity:        opts.UE.UeSecurity,
	})
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	err = opts.GnodeB.SendInitialUEMessage(&gnb.InitialUEMessageOpts{
		Mcc:                   opts.Mcc,
		Mnc:                   opts.Mnc,
		GnbID:                 opts.GNBID,
		Tac:                   opts.Tac,
		RanUENGAPID:           opts.RANUENGAPID,
		NasPDU:                nasPDU,
		Guti5g:                opts.UE.UeSecurity.Guti,
		RRCEstablishmentCause: ngapType.RRCEstablishmentCausePresentMoSignalling,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	logger.Logger.Debug(
		"Sent Initial UE Message for Registration Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
		zap.Any("GUTI", opts.UE.UeSecurity.Guti),
	)

	fr, err := opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err := validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	amfUENGAPID := utils.GetAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport)
	if amfUENGAPID == nil {
		return fmt.Errorf("could not get AMF UE NGAP ID from DownlinkNASTransport: %v", err)
	}

	_, _, err = validate.AuthenticationRequest(&validate.AuthenticationRequestOpts{
		NASPDU: utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport),
		UE:     opts.UE,
	})
	if err != nil {
		return fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Received Authentication Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	paramAutn := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	} // Wrong key for test

	authResp, err := ue.BuildAuthenticationResponse(&ue.AuthenticationResponseOpts{
		AuthenticationResponseParam: paramAutn,
		EapMsg:                      "",
	})
	if err != nil {
		return fmt.Errorf("could not build authentication response: %v", err)
	}

	err = opts.GnodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: opts.RANUENGAPID,
		Mcc:         opts.Mcc,
		Mnc:         opts.Mnc,
		GnbID:       opts.GNBID,
		Tac:         opts.Tac,
		NasPDU:      authResp,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.Logger.Debug(
		"Sent Uplink NAS Transport with Authentication Response (wrong key)",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	fr, err = opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err = validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	err = validate.AuthenticationReject(&validate.AuthenticationRejectOpts{
		NASPDU: utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport),
		UE:     opts.UE,
	})
	if err != nil {
		return fmt.Errorf("could not validate Authentication Reject: %v", err)
	}

	logger.Logger.Debug(
		"Received Authentication Reject as expected due to wrong key",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	return nil
}
