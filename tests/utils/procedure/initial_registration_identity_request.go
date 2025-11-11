package procedure

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
)

type InitialRegistrationWithIdentityRequestOpts struct {
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

type InitialRegistration2Resp struct {
	AMFUENGAPID int64
}

func InitialRegistrationWithIdentityRequest(ctx context.Context, opts *InitialRegistrationWithIdentityRequestOpts) (*InitialRegistration2Resp, error) { //nolint: gocognit
	initialRegistrationResp := &InitialRegistration2Resp{}

	nasPDU, err := ue.BuildRegistrationRequest(&ue.RegistrationRequestOpts{
		RegistrationType:  nasMessage.RegistrationType5GSInitialRegistration,
		RequestedNSSAI:    nil,
		UplinkDataStatus:  nil,
		IncludeCapability: false,
		UESecurity:        opts.UE.UeSecurity,
	})
	if err != nil {
		return nil, fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
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
		return nil, fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	fr, err := opts.GnodeB.ReceiveFrame(ctx)
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

	err = validate.IdentityRequest(&validate.IdentityRequestOpts{
		NASPDU: utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport),
		UE:     opts.UE,
	})
	if err != nil {
		return nil, fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	identityResp, err := ue.BuildIdentityResponse(&ue.IdentityResponseOpts{
		Suci: opts.UE.GetSuci(),
	})
	if err != nil {
		return nil, fmt.Errorf("could not build Identity Response NAS PDU: %v", err)
	}

	err = opts.GnodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: opts.RANUENGAPID,
		Mcc:         opts.Mcc,
		Mnc:         opts.Mnc,
		GnbID:       opts.GNBID,
		Tac:         opts.Tac,
		NasPDU:      identityResp,
	})
	if err != nil {
		return nil, fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	fr, err = opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err = validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return nil, fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	rand, autn, err := validate.AuthenticationRequest(&validate.AuthenticationRequestOpts{
		NASPDU: utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport),
		UE:     opts.UE,
	})
	if err != nil {
		return nil, fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	paramAutn, err := opts.UE.DeriveRESstarAndSetKey(opts.UE.UeSecurity.AuthenticationSubs, rand[:], opts.UE.UeSecurity.Snn, autn[:])
	if err != nil {
		return nil, fmt.Errorf("could not derive RES* and set key: %v", err)
	}

	authResp, err := ue.BuildAuthenticationResponse(&ue.AuthenticationResponseOpts{
		AuthenticationResponseParam: paramAutn,
		EapMsg:                      "",
	})
	if err != nil {
		return nil, fmt.Errorf("could not build authentication response: %v", err)
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
		return nil, fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	fr, err = opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err = validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return nil, fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	ksi, tsc, err := validate.SecurityModeCommand(&validate.SecurityModeCommandOpts{
		NASPDU: utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport),
		UE:     opts.UE,
	})
	if err != nil {
		return nil, fmt.Errorf("could not validate NAS PDU Security Mode Command: %v", err)
	}

	opts.UE.UeSecurity.NgKsi.Ksi = ksi
	opts.UE.UeSecurity.NgKsi.Tsc = tsc

	securityModeComplete, err := ue.BuildSecurityModeComplete(&ue.SecurityModeCompleteOpts{
		UESecurity: opts.UE.UeSecurity,
		IMEISV:     opts.UE.IMEISV,
	})
	if err != nil {
		return nil, fmt.Errorf("error sending Security Mode Complete: %w", err)
	}

	encodedPdu, err := opts.UE.EncodeNasPduWithSecurity(securityModeComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", opts.UE.UeSecurity.Supi, err)
	}

	err = opts.GnodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: opts.RANUENGAPID,
		Mcc:         opts.Mcc,
		Mnc:         opts.Mnc,
		GnbID:       opts.GNBID,
		Tac:         opts.Tac,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return nil, fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	fr, err = opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	initialContextSetupRequest, err := validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return nil, fmt.Errorf("initial context setup request validation failed: %v", err)
	}

	err = opts.GnodeB.SendInitialContextSetupResponse(&gnb.InitialContextSetupResponseOpts{
		AMFUENGAPID: amfUENGAPID.Value,
		RANUENGAPID: opts.RANUENGAPID,
	})
	if err != nil {
		return nil, fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	guti5g, err := validate.RegistrationAccept(&validate.RegistrationAcceptOpts{
		NASPDU: utils.GetNASPDUFromInitialContextSetupRequest(initialContextSetupRequest),
		UE:     opts.UE,
		Sst:    opts.Sst,
		Sd:     opts.Sd,
	})
	if err != nil {
		return nil, fmt.Errorf("validation failed for registration accept: %v", err)
	}

	opts.UE.Set5gGuti(guti5g)

	regComplete, err := ue.BuildRegistrationComplete(&ue.RegistrationCompleteOpts{
		SORTransparentContainer: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("could not build Registration Complete NAS PDU: %v", err)
	}

	encodedPdu, err = opts.UE.EncodeNasPduWithSecurity(regComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE NAS Registration Complete Msg", opts.UE.UeSecurity.Supi)
	}

	err = opts.GnodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: opts.RANUENGAPID,
		Mcc:         opts.Mcc,
		Mnc:         opts.Mnc,
		GnbID:       opts.GNBID,
		Tac:         opts.Tac,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return nil, fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	pduReq, err := ue.BuildPduSessionEstablishmentRequest(&ue.PduSessionEstablishmentRequestOpts{
		PDUSessionID: opts.PDUSessionID,
	})
	if err != nil {
		return nil, fmt.Errorf("could not build PDU Session Establishment Request: %v", err)
	}

	pduUplink, err := ue.BuildUplinkNasTransport(&ue.UplinkNasTransportOpts{
		PDUSessionID:     opts.PDUSessionID,
		PayloadContainer: pduReq,
		DNN:              opts.UE.DNN,
		SNSSAI:           opts.UE.Snssai,
	})
	if err != nil {
		return nil, fmt.Errorf("could not build Uplink NAS Transport for PDU Session: %v", err)
	}

	encodedPdu, err = opts.UE.EncodeNasPduWithSecurity(pduUplink, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE NAS Uplink NAS Transport for PDU Session Msg", opts.UE.UeSecurity.Supi)
	}

	err = opts.GnodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID.Value,
		RANUeNgapID: opts.RANUENGAPID,
		Mcc:         opts.Mcc,
		Mnc:         opts.Mnc,
		GnbID:       opts.GNBID,
		Tac:         opts.Tac,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return nil, fmt.Errorf("could not send UplinkNASTransport for PDU Session Establishment: %v", err)
	}

	fr, err = opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not receive NGAP frame: %v", err)
	}

	network, err := netip.ParsePrefix("10.45.0.0/16")
	if err != nil {
		return nil, fmt.Errorf("failed to parse UE IP subnet: %v", err)
	}

	_, err = validate.PDUSessionResourceSetupRequest(&validate.PDUSessionResourceSetupRequestOpts{
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

	n3GnbIP, err := netip.ParseAddr("1.2.3.4")
	if err != nil {
		return nil, fmt.Errorf("failed to parse N3 GNB IP address: %v", err)
	}

	err = opts.GnodeB.SendPDUSessionResourceSetupResponse(&gnb.PDUSessionResourceSetupResponseOpts{
		AMFUENGAPID: amfUENGAPID.Value,
		RANUENGAPID: opts.RANUENGAPID,
		N3GnbIp:     n3GnbIP,
		PDUSessions: [16]*gnb.GnbPDUSession{
			{
				PDUSessionId: 1,
				DownlinkTeid: 100,
				QFI:          1,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send PDUSessionResourceSetupResponse: %v", err)
	}

	return initialRegistrationResp, nil
}
