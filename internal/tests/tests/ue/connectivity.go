package ue

import (
	"context"
	"fmt"
	"net/netip"
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
		env.Config.EllaCore.TAC,
		"Ella-Core-Tester",
		env.Config.EllaCore.N2Address,
		env.Config.Gnb.N2Address,
	)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = gNodeB.WaitForNGSetupComplete(100 * time.Millisecond)
	if err != nil {
		return fmt.Errorf("timeout waiting for NGSetupComplete: %v", err)
	}

	newUE, err := ue.NewUE(&ue.UEOpts{
		Msin: env.Config.Subscriber.IMSI[5:],
		K:    env.Config.Subscriber.Key,
		OpC:  env.Config.Subscriber.OPC,
		Amf:  "80000000000000000000000000000000",
		Sqn:  env.Config.Subscriber.SequenceNumber,
		Mcc:  env.Config.EllaCore.MCC,
		Mnc:  env.Config.EllaCore.MNC,
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

	gnbN3Address, err := netip.ParseAddr(env.Config.Gnb.N3Address)
	if err != nil {
		return fmt.Errorf("could not parse gNB N3 address: %v", err)
	}

	resp, err := procedure.InitialRegistration(ctx, &procedure.InitialRegistrationOpts{
		Mcc:          env.Config.EllaCore.MCC,
		Mnc:          env.Config.EllaCore.MNC,
		Sst:          env.Config.EllaCore.SST,
		Sd:           env.Config.EllaCore.SD,
		Tac:          env.Config.EllaCore.TAC,
		DNN:          env.Config.EllaCore.DNN,
		GNBID:        GNBID,
		RANUENGAPID:  RANUENGAPID,
		PDUSessionID: PDUSessionID,
		UE:           newUE,
		N3GNBAddress: gnbN3Address,
		GnodeB:       gNodeB,
		DownlinkTEID: DownlinkTEID,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	logger.Logger.Debug(
		"Completed Initial Registration Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
		zap.Int64("AMF UE NGAP ID", resp.AMFUENGAPID),
	)

	ueIP := resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.UEIP.String() + "/16"

	tun, err := gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             ueIP,
		GnbIP:            env.Config.Gnb.N3Address,
		UpfIP:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.UpfAddress,
		GTPUPort:         GTPUPort,
		TunInterfaceName: GTPInterfaceName,
		Lteid:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.ULTeid,
		Rteid:            DownlinkTEID,
	})
	if err != nil {
		return fmt.Errorf("failed to create GTP tunnel: %v", err)
	}

	logger.Logger.Debug(
		"Created GTP tunnel",
		zap.String("interface", GTPInterfaceName),
		zap.String("UE IP", ueIP),
		zap.String("gNB IP", env.Config.Gnb.N3Address),
		zap.String("UPF IP", resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.UpfAddress),
		zap.Uint32("LTEID", resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.ULTeid),
		zap.Uint32("RTEID", DownlinkTEID),
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

	err = procedure.UEContextRelease(ctx, &procedure.UEContextReleaseOpts{
		AMFUENGAPID:   resp.AMFUENGAPID,
		RANUENGAPID:   RANUENGAPID,
		GnodeB:        gNodeB,
		PDUSessionIDs: pduSessionStatus,
	})
	if err != nil {
		return fmt.Errorf("UEContextReleaseProcedure failed: %v", err)
	}

	logger.Logger.Debug(
		"Completed UE Context Release Procedure",
		zap.String("AMF UE NGAP ID", fmt.Sprintf("%d", resp.AMFUENGAPID)),
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

	srvReqRsp, err := procedure.ServiceRequest(ctx, &procedure.ServiceRequestOpts{
		Mcc:              env.Config.EllaCore.MCC,
		Mnc:              env.Config.EllaCore.MNC,
		PDUSessionStatus: pduSessionStatus,
		Tac:              env.Config.EllaCore.TAC,
		GNBID:            GNBID,
		SST:              env.Config.EllaCore.SST,
		SD:               env.Config.EllaCore.SD,
		AMFUENGAPID:      resp.AMFUENGAPID,
		RANUENGAPID:      RANUENGAPID,
		UE:               newUE,
		GnodeB:           gNodeB,
		GnodebN3Address:  gnbN3Address,
		DownlinkTEID:     DownlinkTEID,
	})
	if err != nil {
		return fmt.Errorf("service request procedure failed: %v", err)
	}

	tun.Close()

	newTun, err := gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             ueIP, // re-using the same UE IP, we may need to change this to fetch the IP from the Service Request response in the future
		GnbIP:            env.Config.Gnb.N3Address,
		UpfIP:            srvReqRsp.UPFAddress,
		GTPUPort:         GTPUPort,
		TunInterfaceName: GTPInterfaceName,
		Lteid:            srvReqRsp.ULTEID,
		Rteid:            DownlinkTEID,
	})
	if err != nil {
		return fmt.Errorf("failed to recreate GTP tunnel after Service Request: %v", err)
	}

	logger.Logger.Debug(
		"Completed Service Request Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
		zap.Int64("AMF UE NGAP ID", resp.AMFUENGAPID),
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

	err = procedure.Deregistration(ctx, &procedure.DeregistrationOpts{
		GnodeB:      gNodeB,
		UE:          newUE,
		AMFUENGAPID: resp.AMFUENGAPID,
		RANUENGAPID: RANUENGAPID,
		MCC:         env.Config.EllaCore.MCC,
		MNC:         env.Config.EllaCore.MNC,
		GNBID:       GNBID,
		TAC:         env.Config.EllaCore.TAC,
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
