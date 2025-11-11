package ue

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/core"
	"github.com/ellanetworks/core-tester/tests/utils/procedure"
	"github.com/ellanetworks/core-tester/tests/utils/validate"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
)

type ServiceRequestData struct{}

func (ServiceRequestData) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/service_request/data",
		Summary: "UE service request test validating the Service Request procedure for data",
		Timeout: 2 * time.Second,
	}
}

func (t ServiceRequestData) Run(ctx context.Context, env engine.Env) error {
	ellaCoreEnv := core.NewEllaCoreEnv(env.EllaCoreClient, core.EllaCoreConfig{
		Policies: []core.PolicyConfig{
			{
				Name:            PolicyName,
				BitrateUplink:   "100 Mbps",
				BitrateDownlink: "100 Mbps",
				Var5qi:          9,
				Arp:             15,
				DataNetworkName: env.CoreConfig.DNN,
			},
		},
		Subscribers: []core.SubscriberConfig{
			{
				Imsi:           IMSI,
				Key:            Key,
				SequenceNumber: SQN,
				OPc:            OPC,
				PolicyName:     PolicyName,
			},
		},
	})

	err := ellaCoreEnv.Create(ctx)
	if err != nil {
		return fmt.Errorf("could not create EllaCore environment: %v", err)
	}

	gNodeB, err := gnb.Start(env.CoreConfig.N2Address, env.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = procedure.NGSetup(ctx, &procedure.NGSetupOpts{
		Mcc:    env.CoreConfig.MCC,
		Mnc:    env.CoreConfig.MNC,
		Sst:    env.CoreConfig.SST,
		Tac:    env.CoreConfig.TAC,
		GnodeB: gNodeB,
	})
	if err != nil {
		return fmt.Errorf("NGSetupProcedure failed: %v", err)
	}

	newUE, err := ue.NewUE(&ue.UEOpts{
		Msin: IMSI[5:],
		K:    Key,
		OpC:  OPC,
		Amf:  "80000000000000000000000000000000",
		Sqn:  SQN,
		Mcc:  env.CoreConfig.MCC,
		Mnc:  env.CoreConfig.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              env.CoreConfig.DNN,
		Sst:              env.CoreConfig.SST,
		Sd:               env.CoreConfig.SD,
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

	gnbN3Address, err := netip.ParseAddr(env.GnbN3Address)
	if err != nil {
		return fmt.Errorf("could not parse gNB N3 address: %v", err)
	}

	resp, err := procedure.InitialRegistration(ctx, &procedure.InitialRegistrationOpts{
		Mcc:          env.CoreConfig.MCC,
		Mnc:          env.CoreConfig.MNC,
		Sst:          env.CoreConfig.SST,
		Sd:           env.CoreConfig.SD,
		Tac:          env.CoreConfig.TAC,
		DNN:          env.CoreConfig.DNN,
		GNBID:        GNBID,
		RANUENGAPID:  RANUENGAPID,
		PDUSessionID: PDUSessionID,
		UE:           newUE,
		N3GNBAddress: gnbN3Address,
		GnodeB:       gNodeB,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	pduSessionStatus := [16]bool{}
	pduSessionStatus[PDUSessionID] = true

	err = procedure.UEContextRelease(ctx, &procedure.UEContextReleaseOpts{
		AMFUENGAPID:   resp.AMFUENGAPID,
		RANUENGAPID:   RANUENGAPID,
		GnodeB:        gNodeB,
		PDUSessionIDs: pduSessionStatus,
	})
	if err != nil {
		return fmt.Errorf("UEContextReleaseProcedure failed: %v", err)
	}

	serviceRequest, err := ue.BuildServiceRequest(&ue.ServiceRequestOpts{
		ServiceType:      nasMessage.ServiceTypeData,
		AMFSetID:         newUE.GetAmfSetId(),
		AMFPointer:       newUE.GetAmfPointer(),
		TMSI5G:           newUE.GetTMSI5G(),
		PDUSessionStatus: &pduSessionStatus,
		UESecurity:       newUE.UeSecurity,
	})
	if err != nil {
		return fmt.Errorf("could not build Service Request NAS PDU: %v", err)
	}

	encodedPdu, err := newUE.EncodeNasPduWithSecurity(serviceRequest, nas.SecurityHeaderTypeIntegrityProtected)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", newUE.UeSecurity.Supi, err)
	}

	err = gNodeB.SendInitialUEMessage(&gnb.InitialUEMessageOpts{
		Mcc:                   env.CoreConfig.MCC,
		Mnc:                   env.CoreConfig.MNC,
		GnbID:                 GNBID,
		Tac:                   env.CoreConfig.TAC,
		RanUENGAPID:           RANUENGAPID,
		NasPDU:                encodedPdu,
		Guti5g:                newUE.UeSecurity.Guti,
		RRCEstablishmentCause: ngapType.RRCEstablishmentCausePresentMoData,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	fr, err := gNodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	initialContextSetupRequest, err := validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("InitialContextSetupRequest validation failed: %v", err)
	}

	err = validate.ServiceAccept(&validate.ServiceAcceptOpts{
		NASPDU: utils.GetNASPDUFromInitialContextSetupRequest(initialContextSetupRequest),
		UE:     newUE,
	})
	if err != nil {
		return fmt.Errorf("validation failed for registration accept: %v", err)
	}

	err = gNodeB.SendInitialContextSetupResponse(&gnb.InitialContextSetupResponseOpts{
		AMFUENGAPID: resp.AMFUENGAPID,
		RANUENGAPID: RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	// Cleanup
	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	return nil
}
