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
	"golang.org/x/sync/errgroup"
)

const (
	GTPInterfaceNamePrefix  = "ellatester"
	GTPUPortInit            = 2152
	PingDestination         = "10.6.0.3"
	NumConnectivityParallel = 5
)

type Connectivity struct{}

func (Connectivity) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/connectivity",
		Summary: "UE connectivity test validating the connectivity of 5 UE's in parallel after registration, and after UE Context Release",
		Timeout: 10 * time.Second,
	}
}

func (t Connectivity) Run(ctx context.Context, env engine.Env) error {
	subs, err := buildSubscriberConfig(NumConnectivityParallel, testStartIMSI)
	if err != nil {
		return fmt.Errorf("could not build subscriber config: %v", err)
	}

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
		Subscribers: subs,
	})

	err = ellaCoreEnv.Create(ctx)
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

	eg := errgroup.Group{}

	for i := range NumConnectivityParallel {
		func() {
			eg.Go(func() error {
				ranUENGAPID := RANUENGAPID + int64(i)
				tunInterfaceName := fmt.Sprintf(GTPInterfaceNamePrefix+"%d", i)
				gtpuPort := GTPUPortInit + i

				return runConnectivityTest(
					env,
					ranUENGAPID,
					gNodeB,
					subs[i],
					tunInterfaceName,
					gtpuPort,
				)
			})
		}()
	}

	err = eg.Wait()
	if err != nil {
		return fmt.Errorf("error during UE registrations: %v", err)
	}

	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}

func runConnectivityTest(
	env engine.Env,
	ranUENGAPID int64,
	gNodeB *gnb.GnodeB,
	subscriber core.SubscriberConfig,
	tunInterfaceName string,
	gtpuPort int,
) error {
	newUE, err := ue.NewUE(&ue.UEOpts{
		GnodeB:       gNodeB,
		PDUSessionID: PDUSessionID,
		Msin:         subscriber.Imsi[5:],
		K:            subscriber.Key,
		OpC:          subscriber.OPc,
		Amf:          "80000000000000000000000000000000",
		Sqn:          subscriber.SequenceNumber,
		Mcc:          env.Config.EllaCore.MCC,
		Mnc:          env.Config.EllaCore.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: sidf.NullScheme,
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

	gNodeB.AddUE(ranUENGAPID, newUE)

	err = procedure.InitialRegistration(&procedure.InitialRegistrationOpts{
		RANUENGAPID: ranUENGAPID,
		UE:          newUE,
		GnodeB:      gNodeB,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	logger.Logger.Debug(
		"Completed Initial Registration Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
		zap.Int64("AMF UE NGAP ID", gNodeB.GetAMFUENGAPID(ranUENGAPID)),
	)

	ueIP := newUE.GetPDUSession().UEIP + "/16"

	pduSessionInformation := gNodeB.GetPDUSession(ranUENGAPID)

	tun, err := gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             ueIP,
		GnbIP:            env.Config.Gnb.N3Address,
		UpfIP:            pduSessionInformation.UpfAddress,
		GTPUPort:         gtpuPort,
		TunInterfaceName: tunInterfaceName,
		Lteid:            pduSessionInformation.ULTeid,
		Rteid:            pduSessionInformation.DLTeid,
	})
	if err != nil {
		return fmt.Errorf("failed to create GTP tunnel: %v", err)
	}

	logger.Logger.Debug(
		"Created GTP tunnel",
		zap.String("interface", tunInterfaceName),
		zap.String("UE IP", ueIP),
		zap.String("gNB IP", env.Config.Gnb.N3Address),
		zap.String("UPF IP", pduSessionInformation.UpfAddress),
		zap.Uint32("LTEID", pduSessionInformation.ULTeid),
		zap.Uint32("RTEID", pduSessionInformation.DLTeid),
		zap.Int("GTPU Port", gtpuPort),
	)

	cmd := exec.Command("ping", "-I", tunInterfaceName, PingDestination, "-c", "3", "-W", "1")

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("could not ping destination %s: %v", PingDestination, err)
	}

	logger.Logger.Debug(
		"Ping successful",
		zap.String("interface", tunInterfaceName),
		zap.String("destination", PingDestination),
	)

	pduSessionStatus := [16]bool{}
	pduSessionStatus[PDUSessionID] = true

	err = procedure.UEContextRelease(&procedure.UEContextReleaseOpts{
		AMFUENGAPID:   gNodeB.GetAMFUENGAPID(ranUENGAPID),
		RANUENGAPID:   ranUENGAPID,
		GnodeB:        gNodeB,
		PDUSessionIDs: pduSessionStatus,
	})
	if err != nil {
		return fmt.Errorf("UEContextReleaseProcedure failed: %v", err)
	}

	logger.Logger.Debug(
		"Completed UE Context Release Procedure",
		zap.Int64("AMF UE NGAP ID", gNodeB.GetAMFUENGAPID(ranUENGAPID)),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
	)

	cmd = exec.Command("ping", "-I", tunInterfaceName, PingDestination, "-c", "3", "-W", "1")

	err = cmd.Run()
	if err == nil {
		return fmt.Errorf("ping to destination %s succeeded, but should have failed after UE Context Release", PingDestination)
	}

	logger.Logger.Debug(
		"Ping failed as expected after UE Context Release",
		zap.String("interface", tunInterfaceName),
		zap.String("destination", PingDestination),
	)

	err = procedure.ServiceRequest(&procedure.ServiceRequestOpts{
		PDUSessionStatus: pduSessionStatus,
		RANUENGAPID:      ranUENGAPID,
		UE:               newUE,
		GnodeB:           gNodeB,
	})
	if err != nil {
		return fmt.Errorf("service request procedure failed: %v", err)
	}

	tun.Close()

	pduSession := gNodeB.GetPDUSession(ranUENGAPID)

	newTun, err := gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             ueIP, // re-using the same UE IP, we may need to change this to fetch the IP from the Service Request response in the future
		GnbIP:            env.Config.Gnb.N3Address,
		UpfIP:            pduSession.UpfAddress,
		GTPUPort:         gtpuPort,
		TunInterfaceName: tunInterfaceName,
		Lteid:            pduSession.ULTeid,
		Rteid:            pduSession.DLTeid,
	})
	if err != nil {
		return fmt.Errorf("failed to recreate GTP tunnel after Service Request: %v", err)
	}

	logger.Logger.Debug(
		"Completed Service Request Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
		zap.Int64("AMF UE NGAP ID", gNodeB.GetAMFUENGAPID(ranUENGAPID)),
		zap.Uint32("LTEID", pduSession.ULTeid),
		zap.Uint32("RTEID", pduSession.DLTeid),
		zap.String("UPF Address", pduSession.UpfAddress),
	)

	cmd = exec.Command("ping", "-I", tunInterfaceName, PingDestination, "-c", "3", "-W", "1")

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("could not ping destination %s after Service Request: %v", PingDestination, err)
	}

	logger.Logger.Debug(
		"Ping successful after Service Request",
		zap.String("interface", tunInterfaceName),
		zap.String("destination", PingDestination),
	)

	// Cleanup
	newTun.Close()

	logger.Logger.Debug(
		"Closed GTP tunnel",
		zap.String("interface", tunInterfaceName),
	)

	err = procedure.Deregistration(&procedure.DeregistrationOpts{
		GnodeB:      gNodeB,
		UE:          newUE,
		AMFUENGAPID: gNodeB.GetAMFUENGAPID(ranUENGAPID),
		RANUENGAPID: ranUENGAPID,
	})
	if err != nil {
		return fmt.Errorf("DeregistrationProcedure failed: %v", err)
	}

	return nil
}
