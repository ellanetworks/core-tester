package register

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/procedure"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/gtp"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

const (
	RANUENGAPID  = 1
	GNBID        = "000008"
	PDUSessionID = 1
)

const (
	GTPInterfaceName = "ellatester0"
	DownlinkTEID     = 1657545292
	GTPUPort         = 2152
)

type RegisterConfig struct {
	IMSI              string
	Key               string
	OPC               string
	SequenceNumber    string
	PolicyName        string
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

func Register(ctx context.Context, cfg RegisterConfig) error {
	gNodeB, err := gnb.Start(
		GNBID,
		cfg.MCC,
		cfg.MNC,
		cfg.SST,
		cfg.SD,
		cfg.DNN,
		cfg.TAC,
		"Ella-Core-Tester",
		cfg.EllaCoreN2Address,
		cfg.GnbN2Address,
		cfg.GnbN3Address,
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
		Msin: cfg.IMSI[5:],
		K:    cfg.Key,
		OpC:  cfg.OPC,
		Amf:  "80000000000000000000000000000000",
		Sqn:  cfg.SequenceNumber,
		Mcc:  cfg.MCC,
		Mnc:  cfg.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              cfg.DNN,
		Sst:              cfg.SST,
		Sd:               cfg.SD,
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
		RANUENGAPID:  RANUENGAPID,
		PDUSessionID: PDUSessionID,
		UE:           newUE,
		GnodeB:       gNodeB,
	})
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	logger.Logger.Info(
		"Completed Initial Registration Procedure",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
		zap.Int64("AMF UE NGAP ID", resp.AMFUENGAPID),
	)

	ueIP := resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.UEIP.String() + "/16"

	_, err = gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             ueIP,
		GnbIP:            cfg.GnbN3Address,
		UpfIP:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.UpfAddress,
		GTPUPort:         GTPUPort,
		TunInterfaceName: GTPInterfaceName,
		Lteid:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.ULTeid,
		Rteid:            DownlinkTEID,
	})
	if err != nil {
		return fmt.Errorf("failed to create GTP tunnel: %v", err)
	}

	logger.Logger.Info(
		"Created GTP tunnel",
		zap.String("interface", GTPInterfaceName),
		zap.String("UE IP", ueIP),
		zap.String("gNB IP", cfg.GnbN3Address),
		zap.String("UPF IP", resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.UpfAddress),
		zap.Uint32("LTEID", resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.ULTeid),
		zap.Uint32("RTEID", DownlinkTEID),
		zap.Uint16("GTPU Port", GTPUPort),
	)

	select {}
}
