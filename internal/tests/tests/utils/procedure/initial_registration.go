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
	"github.com/free5gc/ngap/ngapType"
)

type InitialRegistrationOpts struct {
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

	fr, err := opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not find downlink NAS transport message 1: %v", err)
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

	fr, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not find downlink NAS transport message 2: %v", err)
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

	fr, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentInitialContextSetupRequest, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not find initial context setup request message: %v", err)
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
		Sst:    opts.GnodeB.SST,
		Sd:     opts.GnodeB.SD,
		Mcc:    opts.GnodeB.MCC,
		Mnc:    opts.GnodeB.MNC,
	})
	if err != nil {
		return nil, fmt.Errorf("validation failed for registration accept: %v", err)
	}

	fr, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest, 500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("could not find PDU session resource setup request message: %v", err)
	}

	network, err := netip.ParsePrefix("10.45.0.0/16")
	if err != nil {
		return nil, fmt.Errorf("failed to parse UE IP subnet: %v", err)
	}

	resp, err := validate.PDUSessionResourceSetupRequest(&validate.PDUSessionResourceSetupRequestOpts{
		Frame:                fr,
		ExpectedPDUSessionID: opts.PDUSessionID,
		ExpectedSST:          opts.GnodeB.SST,
		ExpectedSD:           opts.GnodeB.SD,
		UEIns:                opts.UE,
		ExpectedPDUSessionEstablishmentAccept: &validate.ExpectedPDUSessionEstablishmentAccept{
			PDUSessionID: opts.PDUSessionID,
			UeIPSubnet:   network,
			Dnn:          opts.GnodeB.DNN,
			Sst:          opts.GnodeB.SST,
			Sd:           opts.GnodeB.SD,
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
