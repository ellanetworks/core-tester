package gnb

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	serviceNas "github.com/ellanetworks/core-tester/internal/gnb/nas/service"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/trigger"
)

func InitGnb(conf config.Config) (*context.GNBContext, error) {
	// instance new gnb.
	gnb := &context.GNBContext{}

	// new gnb context.
	gnb.NewRanGnbContext(
		conf.GNodeB.PlmnList.GnbId,
		conf.GNodeB.PlmnList.Mcc,
		conf.GNodeB.PlmnList.Mnc,
		conf.GNodeB.PlmnList.Tac,
		conf.GNodeB.SliceSupportList.Sst,
		conf.GNodeB.SliceSupportList.Sd,
		conf.GNodeB.N2.AddrPort,
		conf.GNodeB.N3.AddrPort,
	)

	// start communication with Ella (server SCTP).
	// new Ella context.
	ella := conf.Ella
	amf := gnb.NewGnBAmf(ella.N2.AddrPort)

	// start communication with Ella(SCTP).
	err := ngap.InitConn(amf, gnb)
	if err != nil {
		return nil, fmt.Errorf("could not connect to SCTP: %w", err)
	}

	trigger.SendNgSetupRequest(gnb, amf)

	// start communication with UE (server UNIX sockets).
	serviceNas.InitServer(gnb)

	return gnb, nil
}
