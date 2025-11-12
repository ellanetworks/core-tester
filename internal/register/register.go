package register

import (
	"context"
	"fmt"
	"log"
	"net/netip"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/gtp"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/ellanetworks/core-tester/tests/utils"
	"github.com/ellanetworks/core-tester/tests/utils/procedure"
)

const (
	RANUENGAPID  = 1
	GNBID        = "000008"
	PDUSessionID = 1
)

const (
	GTPInterfaceName = "ellatester0"
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
	gNodeB, err := gnb.Start(cfg.EllaCoreN2Address, cfg.GnbN2Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = procedure.NGSetup(ctx, &procedure.NGSetupOpts{
		Mcc:    cfg.MCC,
		Mnc:    cfg.MNC,
		Sst:    cfg.SST,
		Tac:    cfg.TAC,
		GnodeB: gNodeB,
	})
	if err != nil {
		return fmt.Errorf("NGSetupProcedure failed: %v", err)
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

	gnbN3Address, err := netip.ParseAddr(cfg.GnbN3Address)
	if err != nil {
		log.Fatalf("could not parse gNB N3 address: %v", err)
	}

	resp, err := procedure.InitialRegistration(ctx, &procedure.InitialRegistrationOpts{
		Mcc:          cfg.MCC,
		Mnc:          cfg.MNC,
		Sst:          cfg.SST,
		Sd:           cfg.SD,
		Tac:          cfg.TAC,
		DNN:          cfg.DNN,
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

	_, err = gtp.NewTunnel(&gtp.TunnelOptions{
		UEIP:             resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.UEIP,
		GnbIP:            cfg.GnbN3Address,
		UpfIP:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.UpfAddress,
		GTPUPort:         2152,
		TunInterfaceName: GTPInterfaceName,
		Lteid:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.ULTeid,
		Rteid:            1,
	})
	if err != nil {
		return fmt.Errorf("failed to create GTP tunnel: %v", err)
	}

	log.Printf("GTP tunnel created on interface %s", GTPInterfaceName)

	select {}
}
