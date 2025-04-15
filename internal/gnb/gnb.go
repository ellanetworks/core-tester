/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package gnb

import (
	"os"
	"os/signal"
	"sync"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	serviceNas "github.com/ellanetworks/core-tester/internal/gnb/nas/service"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/trigger"
	log "github.com/sirupsen/logrus"
)

func InitGnb(conf config.Config, wg *sync.WaitGroup) *context.GNBContext {
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
		conf.GNodeB.ControlIF.AddrPort,
		conf.GNodeB.DataIF.AddrPort,
	)

	// start communication with AMF (server SCTP).
	for _, amfConfig := range conf.AMFs {
		// new AMF context.
		amf := gnb.NewGnBAmf(amfConfig.AddrPort)

		// start communication with AMF(SCTP).
		if err := ngap.InitConn(amf, gnb); err != nil {
			log.Fatal("Error in", err)
		} else {
			log.Info("[GNB] SCTP/NGAP service is running")
			// wg.Add(1)
		}

		trigger.SendNgSetupRequest(gnb, amf)
	}

	// start communication with UE (server UNIX sockets).
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
