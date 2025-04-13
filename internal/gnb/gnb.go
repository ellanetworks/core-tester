package gnb

import (
	"os"
	"os/signal"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	serviceNas "github.com/ellanetworks/core-tester/internal/gnb/nas/service"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/trigger"
)

func InitGnb(conf config.Config, wg *sync.WaitGroup) *context.GNBContext {
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
	log.Println("Created GNB Context")

	ellaConfig := conf.Ella
	ella := gnb.NewGnbElla(ellaConfig.N2.AddrPort)

	err := ngap.InitConn(ella, gnb)
	if err != nil {
		return nil
	}

	trigger.SendNgSetupRequest(gnb, ella)
	serviceNas.InitServer(gnb)

	go func() {
		// control the signals
		sigGnb := make(chan os.Signal, 1)
		signal.Notify(sigGnb, os.Interrupt)

		// Block until a signal is received.
		<-sigGnb
		// gnb.Terminate()
		wg.Done()
	}()

	return gnb
}
