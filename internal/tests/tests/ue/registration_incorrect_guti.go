package ue

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/core"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/procedure"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/validate"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
)

type RegistrationIncorrectGUTI struct{}

func (RegistrationIncorrectGUTI) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration/incorrect_guti",
		Summary: "UE registration test validating the Registration Request procedure with incorrect GUTI",
		Timeout: 2 * time.Second,
	}
}

func (t RegistrationIncorrectGUTI) Run(ctx context.Context, env engine.Env) error {
	ellaCoreEnv := core.NewEllaCoreEnv(env.EllaCoreClient, core.EllaCoreConfig{
		Operator: core.OperatorConfig{
			ID: core.OperatorID{
				MCC: env.Config.EllaCore.MCC,
				MNC: env.Config.EllaCore.MNC,
			},
			Slice: core.OperatorSlice{
				SST: env.Config.EllaCore.SST,
				SD:  env.Config.EllaCore.SD,
			},
			Tracking: core.OperatorTracking{
				SupportedTACs: []string{env.Config.EllaCore.TAC},
			},
		},
		DataNetworks: []core.DataNetworkConfig{
			{
				Name:   env.Config.EllaCore.DNN,
				IPPool: "10.45.0.0/16",
				DNS:    "8.8.8.8",
				Mtu:    1500,
			},
		},
		Policies: []core.PolicyConfig{
			{
				Name:            env.Config.Subscriber.PolicyName,
				BitrateUplink:   "100 Mbps",
				BitrateDownlink: "100 Mbps",
				Var5qi:          9,
				Arp:             15,
				DataNetworkName: env.Config.EllaCore.DNN,
			},
		},
		Subscribers: []core.SubscriberConfig{
			{
				Imsi:           env.Config.Subscriber.IMSI,
				Key:            env.Config.Subscriber.Key,
				SequenceNumber: env.Config.Subscriber.SequenceNumber,
				OPc:            env.Config.Subscriber.OPC,
				PolicyName:     env.Config.Subscriber.PolicyName,
			},
		},
	})

	err := ellaCoreEnv.Create(ctx)
	if err != nil {
		return fmt.Errorf("could not create EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Created EllaCore environment")

	gNodeB, err := gnb.Start(
		GNBID,
		env.Config.EllaCore.MCC,
		env.Config.EllaCore.MNC,
		env.Config.EllaCore.SST,
		env.Config.EllaCore.SD,
		env.Config.EllaCore.DNN,
		env.Config.EllaCore.TAC,
		"Ella-Core-Tester",
		env.Config.EllaCore.N2Address,
		env.Config.Gnb.N2Address,
		env.Config.Gnb.N3Address,
	)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	_, err = gNodeB.WaitForMessage(ngapType.NGAPPDUPresentSuccessfulOutcome, ngapType.SuccessfulOutcomePresentNGSetupResponse, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	// Create a random GUTI
	guti := &nasType.GUTI5G{}
	guti.SetAMFRegionID(205)
	guti.SetAMFSetID(1018)
	guti.SetAMFPointer(1)
	guti.SetTMSI5G([4]uint8{0x21, 0x43, 0x65, 0x84})
	guti.SetLen(11)
	guti.SetTypeOfIdentity(nasMessage.MobileIdentity5GSType5gGuti)
	guti.SetIei(nasMessage.RegistrationAcceptGUTI5GType)

	newUE, err := ue.NewUE(&ue.UEOpts{
		GnodeB:       gNodeB,
		PDUSessionID: PDUSessionID,
		Guti:         guti,
		Msin:         env.Config.Subscriber.IMSI[5:],
		K:            env.Config.Subscriber.Key,
		OpC:          env.Config.Subscriber.OPC,
		Amf:          "80000000000000000000000000000000",
		Sqn:          env.Config.Subscriber.SequenceNumber,
		Mcc:          env.Config.EllaCore.MCC,
		Mnc:          env.Config.EllaCore.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              env.Config.EllaCore.DNN,
		Sst:              env.Config.EllaCore.SST,
		Sd:               env.Config.EllaCore.SD,
		IMEISV:           "3569380356438091",
		UeSecurityCapability: utils.GetUESecurityCapability(&utils.UeSecurityCapability{
			Integrity: utils.IntegrityAlgorithms{
				Nia2: true,
			},
			Ciphering: utils.CipheringAlgorithms{
				Nea0: true,
				Nea2: true,
			},
		}),
	})
	if err != nil {
		return fmt.Errorf("could not create UE: %v", err)
	}

	gNodeB.AddUE(RANUENGAPID, newUE)

	err = runInitialRegistrationWithIdentityRequest(&InitialRegistrationWithIdentityRequestOpts{
		Mcc:          env.Config.EllaCore.MCC,
		Mnc:          env.Config.EllaCore.MNC,
		Sst:          env.Config.EllaCore.SST,
		Sd:           env.Config.EllaCore.SD,
		DNN:          env.Config.EllaCore.DNN,
		RANUENGAPID:  RANUENGAPID,
		PDUSessionID: PDUSessionID,
		UE:           newUE,
		GnodeB:       gNodeB,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	// Cleanup
	err = procedure.Deregistration(&procedure.DeregistrationOpts{
		GnodeB:      gNodeB,
		UE:          newUE,
		AMFUENGAPID: gNodeB.GetAMFUENGAPID(RANUENGAPID),
		RANUENGAPID: RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("DeregistrationProcedure failed: %v", err)
	}

	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	return nil
}

type InitialRegistrationWithIdentityRequestOpts struct {
	Mcc          string
	Mnc          string
	Sst          int32
	Sd           string
	DNN          string
	RANUENGAPID  int64
	PDUSessionID uint8
	UE           *ue.UE
	GnodeB       *gnb.GnodeB
}

func runInitialRegistrationWithIdentityRequest(opts *InitialRegistrationWithIdentityRequestOpts) error {
	err := opts.UE.SendRegistrationRequest(opts.RANUENGAPID, nasMessage.RegistrationType5GSInitialRegistration)
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	fr, err := opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	downlinkNASTransport, err := validate.DownlinkNASTransport(&validate.DownlinkNASTransportOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("DownlinkNASTransport validation failed: %v", err)
	}

	err = validateIdentityRequest(utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport), opts.UE)
	if err != nil {
		return fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	fr, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentInitialContextSetupRequest, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	req, err := validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("initial context setup request validation failed: %v", err)
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
		return fmt.Errorf("validation failed for registration accept: %v", err)
	}

	err = opts.UE.SendPDUSessionEstablishmentRequest(opts.GnodeB.GetAMFUENGAPID(opts.RANUENGAPID), opts.RANUENGAPID)
	if err != nil {
		return fmt.Errorf("could not build PDU Session Establishment Request NAS PDU: %v", err)
	}

	fr, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	network, err := netip.ParsePrefix("10.45.0.0/16")
	if err != nil {
		return fmt.Errorf("failed to parse UE IP subnet: %v", err)
	}

	err = validate.PDUSessionResourceSetupRequest(&validate.PDUSessionResourceSetupRequestOpts{
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
		return fmt.Errorf("PDUSessionResourceSetupRequest validation failed: %v", err)
	}

	return nil
}

func validateIdentityRequest(nasPDU *ngapType.NASPDU, ue *ue.UE) error {
	if nasPDU == nil {
		return fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ue.DecodeNAS(nasPDU.Value)
	if err != nil {
		return fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if reflect.ValueOf(msg.IdentityRequest.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if msg.IdentityRequest.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if msg.IdentityRequest.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if msg.IdentityRequest.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if reflect.ValueOf(msg.IdentityRequest.IdentityRequestMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	if msg.IdentityRequestMessageIdentity.GetMessageType() != 91 {
		return fmt.Errorf("message type not the expected value")
	}

	if reflect.ValueOf(msg.IdentityRequest.SpareHalfOctetAndIdentityType).IsZero() {
		return fmt.Errorf("spare half octet and identity type is missing")
	}

	return nil
}
