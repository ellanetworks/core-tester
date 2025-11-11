package register

import (
	"context"
	"fmt"
	"log"
	"net/netip"

	"github.com/ellanetworks/core-tester/internal/config"
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
	IMSI       = "001012989077253"
	Key        = "369f7bd3067faec142c47ed9132e942a"
	OPC        = "34e89843fe0683dc961873ebc05b8a35"
	SQN        = "000000000001"
	PolicyName = "default"
)

const (
	GTPInterfaceName = "ellatester0"
)

func Register(ctx context.Context, cfg config.Config) error {
	gNodeB, err := gnb.Start(cfg.Gnb.N2Address, cfg.Gnb.N3Address)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	err = procedure.NGSetup(ctx, &procedure.NGSetupOpts{
		Mcc:    cfg.EllaCore.MCC,
		Mnc:    cfg.EllaCore.MNC,
		Sst:    cfg.EllaCore.SST,
		Tac:    cfg.EllaCore.TAC,
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
		Mcc:  cfg.EllaCore.MCC,
		Mnc:  cfg.EllaCore.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              cfg.EllaCore.DNN,
		Sst:              cfg.EllaCore.SST,
		Sd:               cfg.EllaCore.SD,
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

	gnbN3Address, err := netip.ParseAddr(cfg.Gnb.N3Address)
	if err != nil {
		log.Fatalf("could not parse gNB N3 address: %v", err)
	}

	resp, err := procedure.InitialRegistration(ctx, &procedure.InitialRegistrationOpts{
		Mcc:          cfg.EllaCore.MCC,
		Mnc:          cfg.EllaCore.MNC,
		Sst:          cfg.EllaCore.SST,
		Sd:           cfg.EllaCore.SD,
		Tac:          cfg.EllaCore.TAC,
		DNN:          cfg.EllaCore.DNN,
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
		GnbIP:            cfg.Gnb.N3Address,
		UpfIP:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.UpfAddress,
		GTPUPort:         2152,
		TunInterfaceName: GTPInterfaceName,
		Lteid:            resp.PDUSessionResourceSetupRequest.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.ULTeid,
		Rteid:            1,
	})
	if err != nil {
		return fmt.Errorf("failed to create GTP tunnel: %v", err)
	}

	return nil
}
