package ue

import (
	"context"
	"fmt"
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

type RegistrationPeriodicUpdateSignalling struct{}

func (RegistrationPeriodicUpdateSignalling) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration/periodic/signalling",
		Summary: "UE registration periodic test validating the Registration Request procedure for periodic update",
		Timeout: 2 * time.Second,
	}
}

func (t RegistrationPeriodicUpdateSignalling) Run(ctx context.Context, env engine.Env) error {
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
		GnodeB:       gNodeB,
	})
	if err != nil {
		return fmt.Errorf("InitialRegistrationProcedure failed: %v", err)
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

	nasPDU, err := ue.BuildRegistrationRequest(&ue.RegistrationRequestOpts{
		RegistrationType:  nasMessage.RegistrationType5GSPeriodicRegistrationUpdating,
		RequestedNSSAI:    nil,
		UplinkDataStatus:  nil,
		IncludeCapability: false,
		UESecurity:        newUE.UeSecurity,
		PDUSessionStatus:  &pduSessionStatus,
	})
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	encodedPdu, err := newUE.EncodeNasPduWithSecurity(nasPDU, nas.SecurityHeaderTypeIntegrityProtected)
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
		RRCEstablishmentCause: ngapType.RRCEstablishmentCausePresentMoSignalling,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	fr, err := gNodeB.ReceiveFrame(ctx)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 1)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	_, err = validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("initial context setup request validation failed: %v", err)
	}

	err = gNodeB.SendInitialContextSetupResponse(&gnb.InitialContextSetupResponseOpts{
		AMFUENGAPID: resp.AMFUENGAPID,
		RANUENGAPID: RANUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	regComplete, err := ue.BuildRegistrationComplete(&ue.RegistrationCompleteOpts{
		SORTransparentContainer: nil,
	})
	if err != nil {
		return fmt.Errorf("could not build Registration Complete NAS PDU: %v", err)
	}

	encodedPdu, err = newUE.EncodeNasPduWithSecurity(regComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Registration Complete Msg: %v", newUE.UeSecurity.Supi, err)
	}

	err = gNodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
		AMFUeNgapID: resp.AMFUENGAPID,
		RANUeNgapID: RANUENGAPID,
		Mcc:         env.CoreConfig.MCC,
		Mnc:         env.CoreConfig.MNC,
		GnbID:       GNBID,
		Tac:         env.CoreConfig.TAC,
		NasPDU:      encodedPdu,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	// Cleanup
	err = procedure.Deregistration(ctx, &procedure.DeregistrationOpts{
		GnodeB:      gNodeB,
		UE:          newUE,
		AMFUENGAPID: resp.AMFUENGAPID,
		RANUENGAPID: RANUENGAPID,
		MCC:         env.CoreConfig.MCC,
		MNC:         env.CoreConfig.MNC,
		GNBID:       GNBID,
		TAC:         env.CoreConfig.TAC,
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
