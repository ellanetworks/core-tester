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
	gnb := &context.GNBContext{}

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

	ellaConfig := conf.Ella
	ella := gnb.NewGnbElla(ellaConfig.N2.AddrPort)

	err := ngap.InitConn(ella, gnb)
	if err != nil {
		return nil, fmt.Errorf("could not connect to SCTP: %w", err)
	}

	trigger.SendNgSetupRequest(gnb, ella)
	serviceNas.InitServer(gnb)

	return gnb, nil
}
