package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/ellanetworks/core-tester/internal/common/tools"
	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/procedures"
)

func main() {
	configFilePath := flag.String("config", "", "The config file to be provided to the server")
	flag.Parse()
	if *configFilePath == "" {
		fmt.Println("No config file provided. Use `-config` to provide a config file")
		os.Exit(1)
	}
	cfg, err := config.Load(*configFilePath)
	if err != nil {
		fmt.Printf("Error loading config file: %v\n", err)
		os.Exit(1)
	}
	err = logger.ConfigureLogging(cfg.LogLevel)
	if err != nil {
		logger.EllaCoreTesterLog.Errorf("Error configuring logging: %v", err)
		os.Exit(1)
	}
	testOpts := &TestOptions{
		NumUEs:                   1,
		DedicatedGnb:             false,
		Loop:                     false,
		LoopCount:                0,
		TimeBeforeReregistration: 200,
		TimeBetweenRegistration:  500,
		TimeBeforeDeregistration: 0,
		TimeBeforeNgapHandover:   0,
		TimeBeforeXnHandover:     0,
		TimeBeforeIdle:           0,
		TimeBeforeReconnecting:   1000,
		NumPduSessions:           1,
	}
	err = TestMultiUesInQueue(testOpts)
	if err != nil {
		logger.EllaCoreTesterLog.Errorf("Error running test: %v", err)
		os.Exit(1)
	}
	logger.EllaCoreTesterLog.Info("Test completed successfully")
}

type TestOptions struct {
	NumUEs                   int
	DedicatedGnb             bool
	Loop                     bool
	LoopCount                int
	TimeBeforeReregistration int
	TimeBetweenRegistration  int
	TimeBeforeDeregistration int
	TimeBeforeNgapHandover   int
	TimeBeforeXnHandover     int
	TimeBeforeIdle           int
	TimeBeforeReconnecting   int
	NumPduSessions           int
}

func TestMultiUesInQueue(opts *TestOptions) error {
	if opts.NumPduSessions > 16 {
		return fmt.Errorf("you can't have more than 16 PDU Sessions per UE as per spec")
	}

	wg := sync.WaitGroup{}

	cfg := config.GetConfig()

	var numGnb int
	if opts.DedicatedGnb {
		numGnb = opts.NumUEs
	} else {
		numGnb = 1
	}
	if numGnb <= 1 && (opts.TimeBeforeXnHandover != 0 || opts.TimeBeforeNgapHandover != 0) {
		logger.EllaCoreTesterLog.Warn("We are increasing the number of gNodeB to two for handover test cases. Make you sure you fill the requirements for having two gNodeBs.")
		numGnb++
	}
	gnbs, err := tools.CreateGnbs(numGnb, cfg, &wg)
	if err != nil {
		return fmt.Errorf("error creating gNBs: %v", err)
	}

	// Wait for gNB to be connected before registering UEs
	time.Sleep(1 * time.Second)

	scenarioChans := make([]chan procedures.UeTesterMessage, opts.NumUEs+1)

	sigStop := make(chan os.Signal, 1)
	signal.Notify(sigStop, os.Interrupt)

	ueSimCfg := tools.UESimulationConfig{
		Gnbs:                     gnbs,
		Cfg:                      cfg,
		TimeBeforeDeregistration: opts.TimeBeforeDeregistration,
		TimeBeforeNgapHandover:   opts.TimeBeforeNgapHandover,
		TimeBeforeXnHandover:     opts.TimeBeforeXnHandover,
		TimeBeforeIdle:           opts.TimeBeforeIdle,
		TimeBeforeReconnecting:   opts.TimeBeforeReconnecting,
		NumPduSessions:           opts.NumPduSessions,
		RegistrationLoop:         opts.Loop,
		LoopCount:                opts.LoopCount,
		TimeBeforeReregistration: opts.TimeBeforeReregistration,
	}

	stopSignal := true
	// If CTRL-C signal has been received,
	// stop creating new UEs, else we create numUes UEs
	for ueSimCfg.UeId = 1; stopSignal && ueSimCfg.UeId <= opts.NumUEs; ueSimCfg.UeId++ {
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
		time.Sleep(time.Duration(opts.TimeBetweenRegistration) * time.Millisecond)

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
	return nil
}
