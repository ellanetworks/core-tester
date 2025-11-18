package ue

import (
	"context"
	"fmt"
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
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
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
		DownlinkTEID,
	)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	_, err = gNodeB.WaitForMessage(ngapType.NGAPPDUPresentSuccessfulOutcome, ngapType.SuccessfulOutcomePresentNGSetupResponse, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	newUE, err := ue.NewUE(&ue.UEOpts{
		GnodeB:       gNodeB,
		PDUSessionID: PDUSessionID,
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

	err = procedure.InitialRegistration(&procedure.InitialRegistrationOpts{
		RANUENGAPID: RANUENGAPID,
		UE:          newUE,
		GnodeB:      gNodeB,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	pduSessionStatus := [16]bool{}
	pduSessionStatus[PDUSessionID] = true

	err = procedure.UEContextRelease(&procedure.UEContextReleaseOpts{
		AMFUENGAPID:   gNodeB.GetAMFUENGAPID(RANUENGAPID),
		RANUENGAPID:   RANUENGAPID,
		GnodeB:        gNodeB,
		PDUSessionIDs: pduSessionStatus,
	})
	if err != nil {
		return fmt.Errorf("UEContextReleaseProcedure failed: %v", err)
	}

	err = ServiceRequest(&ServiceRequestOpts{
		PDUSessionStatus: pduSessionStatus,
		SST:              env.Config.EllaCore.SST,
		SD:               env.Config.EllaCore.SD,
		RANUENGAPID:      RANUENGAPID,
		UE:               newUE,
		GnodeB:           gNodeB,
	})
	if err != nil {
		return fmt.Errorf("service request procedure failed: %v", err)
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

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}

type ServiceRequestOpts struct {
	PDUSessionStatus [16]bool
	SST              int32
	SD               string
	RANUENGAPID      int64
	UE               *ue.UE
	GnodeB           *gnb.GnodeB
}

func ServiceRequest(opts *ServiceRequestOpts) error {
	err := opts.UE.SendServiceRequest(opts.RANUENGAPID, opts.PDUSessionStatus)
	if err != nil {
		return fmt.Errorf("could not send Service Request NAS message: %v", err)
	}

	fr, err := opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentInitialContextSetupRequest, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	initialContextSetupReq, err := validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return fmt.Errorf("InitialContextSetupRequest validation failed: %v", err)
	}

	if initialContextSetupReq.PDUSessionResourceSetupListCxtReq == nil {
		return fmt.Errorf("PDUSessionResourceSetupListCxtReq is nil in Initial Context Setup Request")
	}

	err = validate.PDUSessionResourceSetupListCxtReq(initialContextSetupReq.PDUSessionResourceSetupListCxtReq, 1, opts.SST, opts.SD)
	if err != nil {
		return fmt.Errorf("PDUSessionResourceSetupListCxtReq validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Validated PDUSessionResourceSetupListCxtReq in Initial Context Setup Request for Service Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	return nil
}
