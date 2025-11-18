package ue

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/core"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/procedure"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/gtp"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

const (
	GTPInterfaceName = "ellatester0"
	GTPUPort         = 2152
	PingDestination  = "10.6.0.3"
)

type Connectivity struct{}

func (Connectivity) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/connectivity",
		Summary: "UE connectivity test validating the connectivity after registration, and after UE Context Release",
		Timeout: 10 * time.Second,
	}
}

func (t Connectivity) Run(ctx context.Context, env engine.Env) error {
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

	logger.Logger.Debug(
		"Completed Initial Registration Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
		zap.Int64("AMF UE NGAP ID", gNodeB.GetAMFUENGAPID(RANUENGAPID)),
	)

	ueIP := newUE.GetPDUSession().UEIP + "/16"

	pduSessionInformation := gNodeB.GetPDUSession(RANUENGAPID)

	tun, err := gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             ueIP,
		GnbIP:            env.Config.Gnb.N3Address,
		UpfIP:            pduSessionInformation.UpfAddress,
		GTPUPort:         GTPUPort,
		TunInterfaceName: GTPInterfaceName,
		Lteid:            pduSessionInformation.ULTeid,
		Rteid:            pduSessionInformation.DLTeid,
	})
	if err != nil {
		return fmt.Errorf("failed to create GTP tunnel: %v", err)
	}

	logger.Logger.Debug(
		"Created GTP tunnel",
		zap.String("interface", GTPInterfaceName),
		zap.String("UE IP", ueIP),
		zap.String("gNB IP", env.Config.Gnb.N3Address),
		zap.String("UPF IP", pduSessionInformation.UpfAddress),
		zap.Uint32("LTEID", pduSessionInformation.ULTeid),
		zap.Uint32("RTEID", pduSessionInformation.DLTeid),
		zap.Uint16("GTPU Port", GTPUPort),
	)

	cmd := exec.Command("ping", "-I", GTPInterfaceName, PingDestination, "-c", "3", "-W", "1")

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("could not ping destination %s: %v", PingDestination, err)
	}

	logger.Logger.Debug(
		"Ping successful",
		zap.String("interface", GTPInterfaceName),
		zap.String("destination", PingDestination),
	)

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

	logger.Logger.Debug(
		"Completed UE Context Release Procedure",
		zap.Int64("AMF UE NGAP ID", gNodeB.GetAMFUENGAPID(RANUENGAPID)),
		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
	)

	cmd = exec.Command("ping", "-I", GTPInterfaceName, PingDestination, "-c", "3", "-W", "1")

	err = cmd.Run()
	if err == nil {
		return fmt.Errorf("ping to destination %s succeeded, but should have failed after UE Context Release", PingDestination)
	}

	logger.Logger.Debug(
		"Ping failed as expected after UE Context Release",
		zap.String("interface", GTPInterfaceName),
		zap.String("destination", PingDestination),
	)

	err = procedure.ServiceRequest(&procedure.ServiceRequestOpts{
		PDUSessionStatus: pduSessionStatus,
		RANUENGAPID:      RANUENGAPID,
		UE:               newUE,
		GnodeB:           gNodeB,
	})
	if err != nil {
		return fmt.Errorf("service request procedure failed: %v", err)
	}

	tun.Close()

	pduSession := gNodeB.GetPDUSession(RANUENGAPID)

	newTun, err := gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             ueIP, // re-using the same UE IP, we may need to change this to fetch the IP from the Service Request response in the future
		GnbIP:            env.Config.Gnb.N3Address,
		UpfIP:            pduSession.UpfAddress,
		GTPUPort:         GTPUPort,
		TunInterfaceName: GTPInterfaceName,
		Lteid:            pduSession.ULTeid,
		Rteid:            pduSession.DLTeid,
	})
	if err != nil {
		return fmt.Errorf("failed to recreate GTP tunnel after Service Request: %v", err)
	}

	logger.Logger.Debug(
		"Completed Service Request Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
		zap.Int64("AMF UE NGAP ID", gNodeB.GetAMFUENGAPID(RANUENGAPID)),
	)

	cmd = exec.Command("ping", "-I", GTPInterfaceName, PingDestination, "-c", "3", "-W", "1")

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("could not ping destination %s after Service Request: %v", PingDestination, err)
	}

	logger.Logger.Debug(
		"Ping successful after Service Request",
		zap.String("interface", GTPInterfaceName),
		zap.String("destination", PingDestination),
	)

	// Cleanup
	newTun.Close()

	logger.Logger.Debug("Closed GTP tunnel",
		zap.String("interface", GTPInterfaceName),
	)

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
