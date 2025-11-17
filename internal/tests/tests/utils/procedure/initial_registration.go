package procedure

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/validate"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas/nasMessage"
)

type InitialRegistrationOpts struct {
	Mcc          string
	Mnc          string
	Sst          int32
	Sd           string
	Tac          string
	DNN          string
	GNBID        string
	RANUENGAPID  int64
	PDUSessionID uint8
	UE           *ue.UE
	GnodeB       *gnb.GnodeB
}

type InitialRegistrationResp struct {
	AMFUENGAPID                    int64
	PDUSessionResourceSetupRequest *validate.PDUSessionResourceSetupRequestResult
}

func InitialRegistration(ctx context.Context, opts *InitialRegistrationOpts) (*InitialRegistrationResp, error) {
	initialRegistrationResp := &InitialRegistrationResp{}

	err := opts.UE.SendRegistrationRequest(opts.RANUENGAPID, nasMessage.RegistrationType5GSInitialRegistration)
	if err != nil {
		return nil, fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	fr, err := opts.GnodeB.WaitForNextFrame(500 * time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err := validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return nil, fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	amfUENGAPID := utils.GetAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport)
	if amfUENGAPID == nil {
		return nil, fmt.Errorf("could not get AMF UE NGAP ID from DownlinkNASTransport: %v", err)
	}

	initialRegistrationResp.AMFUENGAPID = amfUENGAPID.Value

	err = validate.AuthenticationRequest(&validate.AuthenticationRequestOpts{
		NASPDU: utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport),
		UE:     opts.UE,
	})
	if err != nil {
		return nil, fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	fr, err = opts.GnodeB.WaitForNextFrame(200 * time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err = validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return nil, fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	err = validate.SecurityModeCommand(&validate.SecurityModeCommandOpts{
		NASPDU: utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport),
		UE:     opts.UE,
	})
	if err != nil {
		return nil, fmt.Errorf("could not validate NAS PDU Security Mode Command: %v", err)
	}

	fr, err = opts.GnodeB.WaitForNextFrame(200 * time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	req, err := validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return nil, fmt.Errorf("initial context setup request validation failed: %v", err)
	}

	err = validate.RegistrationAccept(&validate.RegistrationAcceptOpts{
		NASPDU: req.NASPDU,
		UE:     opts.UE,
		Sst:    opts.Sst,
		Sd:     opts.Sd,
		Mcc:    opts.Mcc,
		Mnc:    opts.Mnc,
	})
	if err != nil {
		return nil, fmt.Errorf("validation failed for registration accept: %v", err)
	}

	fr, err = opts.GnodeB.WaitForNextFrame(500 * time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	network, err := netip.ParsePrefix("10.45.0.0/16")
	if err != nil {
		return nil, fmt.Errorf("failed to parse UE IP subnet: %v", err)
	}

	resp, err := validate.PDUSessionResourceSetupRequest(&validate.PDUSessionResourceSetupRequestOpts{
		Frame:                fr,
		ExpectedPDUSessionID: opts.PDUSessionID,
		ExpectedSST:          opts.Sst,
		ExpectedSD:           opts.Sd,
		UEIns:                opts.UE,
		ExpectedPDUSessionEstablishmentAccept: &validate.ExpectedPDUSessionEstablishmentAccept{
			PDUSessionID: opts.PDUSessionID,
			UeIPSubnet:   network,
			Dnn:          opts.DNN,
			Sst:          opts.Sst,
			Sd:           opts.Sd,
			Qfi:          1,
			FiveQI:       9,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("PDUSessionResourceSetupRequest validation failed: %v", err)
	}

	initialRegistrationResp.PDUSessionResourceSetupRequest = resp

	return initialRegistrationResp, nil
}
