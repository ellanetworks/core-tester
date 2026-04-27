package register

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

const (
	ranUENGAPID  = 1
	gnbID        = "000008"
	pduSessionID = 1
)

const (
	gtpInterfaceName = "ellatester0"
	gtpuPort         = 2152
)

// Config holds the parameters required to register a single UE and bring up
// its GTP tunnel.
type Config struct {
	IMSI              string
	Key               string
	OPC               string
	SequenceNumber    string
	ProfileName       string
	MCC               string
	MNC               string
	SST               int32
	SD                string
	TAC               string
	DNN               string
	GnbN2Address      string
	GnbN3Address      string
	EllaCoreN2Address string
}

// Run performs the full register-and-tunnel flow and blocks until ctx is
// cancelled or an interrupt signal is received.
func Run(ctx context.Context, cfg Config) error {
	if len(cfg.IMSI) < 6 {
		return fmt.Errorf("invalid IMSI %q: must be at least 6 digits", cfg.IMSI)
	}

	gNodeB, err := gnb.Start(&gnb.StartOpts{
		GnbID:         gnbID,
		MCC:           cfg.MCC,
		MNC:           cfg.MNC,
		SST:           cfg.SST,
		SD:            cfg.SD,
		DNN:           cfg.DNN,
		TAC:           cfg.TAC,
		Name:          "Ella-Core-Tester",
		CoreN2Address: cfg.EllaCoreN2Address,
		GnbN2Address:  cfg.GnbN2Address,
		GnbN3Address:  cfg.GnbN3Address,
	})
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	logger.Logger.Info("started gNodeB")

	defer func() {
		gNodeB.Close()
		logger.Logger.Info("closed gNodeB")
	}()

	_, err = gNodeB.WaitForMessage(ngapType.NGAPPDUPresentSuccessfulOutcome, ngapType.SuccessfulOutcomePresentNGSetupResponse, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("did not receive SCTP frame: %v", err)
	}

	logger.Logger.Info("received NGSetupResponse")

	newUE, err := ue.NewUE(&ue.UEOpts{
		GnodeB:         gNodeB,
		PDUSessionID:   1,
		PDUSessionType: nasMessage.PDUSessionTypeIPv4,
		Msin:           cfg.IMSI[5:],
		K:              cfg.Key,
		OpC:            cfg.OPC,
		Amf:            "80000000000000000000000000000000",
		Sqn:            cfg.SequenceNumber,
		Mcc:            cfg.MCC,
		Mnc:            cfg.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: sidf.NullScheme,
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              cfg.DNN,
		Sst:              cfg.SST,
		Sd:               cfg.SD,
		IMEISV:           "3569380356438091",
		UeSecurityCapability: getUESecurityCapability(&UeSecurityCapability{
			Integrity: IntegrityAlgorithms{
				Nia2: true,
			},
			Ciphering: CipheringAlgorithms{
				Nea0: true,
				Nea2: true,
			},
		}),
	})
	if err != nil {
		return fmt.Errorf("could not create UE: %v", err)
	}

	gNodeB.AddUE(ranUENGAPID, newUE)
	logger.Logger.Info("added new UE to gNodeB")

	_, err = initialRegistration(&initialRegistrationOpts{
		RANUENGAPID:  ranUENGAPID,
		PDUSessionID: pduSessionID,
		UE:           newUE,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	defer func() {
		err = deregistration(&deregistrationOpts{
			AMFUENGAPID: gNodeB.GetAMFUENGAPID(ranUENGAPID),
			RANUENGAPID: ranUENGAPID,
			UE:          newUE,
		})
		if err != nil {
			logger.Logger.Error("could not deregister UE", zap.Error(err))
		}

		logger.Logger.Info("deregistered UE")
	}()

	logger.Logger.Info(
		"Completed Initial Registration Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
	)

	pduSession := gNodeB.GetPDUSession(ranUENGAPID, int64(pduSessionID))

	uePduSession := newUE.GetPDUSession(pduSessionID)
	ueIP := uePduSession.UEIP + "/16"

	_, err = gNodeB.AddTunnel(&gnb.NewTunnelOpts{
		UEIP:             ueIP,
		UpfIP:            pduSession.UpfAddress,
		TunInterfaceName: gtpInterfaceName,
		ULteid:           pduSession.ULTeid,
		DLteid:           pduSession.DLTeid,
		MTU:              uePduSession.MTU,
		QFI:              uePduSession.QFI,
	})
	if err != nil {
		return fmt.Errorf("could not create GTP tunnel (name: %s, DL TEID: %d): %v", gtpInterfaceName, pduSession.DLTeid, err)
	}

	defer func() {
		err = gNodeB.CloseTunnel(pduSession.DLTeid)
		if err != nil {
			logger.Logger.Error("could not close tunnel", zap.Error(err))
		}

		logger.Logger.Info("closed tunnel")
	}()

	logger.Logger.Info(
		"Created GTP tunnel",
		zap.String("interface", gtpInterfaceName),
		zap.String("UE IP", ueIP),
		zap.String("gNB IP", cfg.GnbN3Address),
		zap.String("UPF IP", pduSession.UpfAddress),
		zap.Uint32("LTEID", pduSession.ULTeid),
		zap.Uint32("RTEID", pduSession.DLTeid),
		zap.Uint16("GTPU Port", gtpuPort),
		zap.Uint16("MTU", uePduSession.MTU),
	)

	sctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	<-sctx.Done()
	logger.Logger.Info("shutting down")

	return nil
}
