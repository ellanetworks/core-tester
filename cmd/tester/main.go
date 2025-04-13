package main

import (
	"flag"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/ellanetworks/core-tester/internal/common/tools"
	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/procedures"
	log "github.com/sirupsen/logrus"
)

func main() {
	configFilePath := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()
	if *configFilePath == "" {
		log.Fatalf("No config file provided. Use `-config` to provide a config file")
	}
	cfg, err := config.Load(*configFilePath)
	if err != nil {
		log.Fatalf("Failed to load config file: %v", err)
	}
	// _, err = gnb.InitGnb(cfg)
	// if err != nil {
	// 	log.Fatalf("Failed to initialize gNB: %v", err)
	// }
	TestMultiUesInQueue(cfg)
	log.Println("gNB initialized successfully")
	select {}
}

func TestMultiUesInQueue(cfg config.Config) {
	wg := sync.WaitGroup{}

	numGnb := 1

	gnbs := tools.CreateGnbs(numGnb, cfg, &wg)

	time.Sleep(1 * time.Second)

	cfg.Ue.TunnelMode = config.TunnelDisabled

	scenarioChans := make([]chan procedures.UeTesterMessage, 1+1)

	sigStop := make(chan os.Signal, 1)
	signal.Notify(sigStop, os.Interrupt)

	ueSimCfg := tools.UESimulationConfig{
		Gnbs:                     gnbs,
		Cfg:                      cfg,
		TimeBeforeDeregistration: 0,
		TimeBeforeNgapHandover:   0,
		TimeBeforeXnHandover:     0,
		TimeBeforeIdle:           0,
		TimeBeforeReconnecting:   0,
		NumPduSessions:           1,
		RegistrationLoop:         false,
		LoopCount:                0,
		TimeBeforeReregistration: 200,
	}

	stopSignal := true
	// If CTRL-C signal has been received,
	// stop creating new UEs, else we create numUes UEs
	for ueSimCfg.UeId = 1; stopSignal && ueSimCfg.UeId <= 1; ueSimCfg.UeId++ {
		// If there is currently a coroutine handling current UE
		// kill it, before creating a new coroutine with same UE
		// Use case: Registration of N UEs in loop, when loop = true
		if scenarioChans[ueSimCfg.UeId] != nil {
			scenarioChans[ueSimCfg.UeId] <- procedures.UeTesterMessage{Type: procedures.Kill}
			close(scenarioChans[ueSimCfg.UeId])
			scenarioChans[ueSimCfg.UeId] = nil
		}
		scenarioChans[ueSimCfg.UeId] = make(chan procedures.UeTesterMessage)
		ueSimCfg.ScenarioChan = scenarioChans[ueSimCfg.UeId]

		tools.SimulateSingleUE(ueSimCfg, &wg)

		// Before creating a new UE, we wait for timeBetweenRegistration ms
		time.Sleep(time.Duration(500) * time.Millisecond)

		select {
		case <-sigStop:
			stopSignal = false
		default:
		}
	}

	if stopSignal {
		<-sigStop
	}
	for _, scenarioChan := range scenarioChans {
		if scenarioChan != nil {
			scenarioChan <- procedures.UeTesterMessage{Type: procedures.Terminate}
		}
	}

	time.Sleep(time.Second * 1)
}
