/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package tools

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/gnb"
	gnbCxt "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/trigger"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/procedures"
	"github.com/ellanetworks/core-tester/internal/ue"
	ueCtx "github.com/ellanetworks/core-tester/internal/ue/context"
)

func CreateGnbs(count int, cfg config.Config, wg *sync.WaitGroup) (map[string]*gnbCxt.GNBContext, error) {
	gnbs := make(map[string]*gnbCxt.GNBContext)
	// Each gNB have their own IP address on both N2 and N3
	// gnb[0].n2_ip = 192.168.2.10, gnb[0].n3_ip = 192.168.3.10
	// gnb[1].n2_ip = 192.168.2.11, gnb[1].n3_ip = 192.168.3.11
	// ...
	baseGnbId := cfg.GNodeB.PlmnList.GnbId
	for i := 1; i <= count; i++ {
		gnb, err := gnb.InitGnb(cfg, wg)
		if err != nil {
			return nil, fmt.Errorf("could not create gnb: %w", err)
		}
		gnbs[cfg.GNodeB.PlmnList.GnbId] = gnb
		wg.Add(1)
		gnbID, err := gnbIdGenerator(i, baseGnbId)
		if err != nil {
			return nil, fmt.Errorf("could not generate gnbId: %w", err)
		}
		cfg.GNodeB.PlmnList.GnbId = gnbID
		cfg.GNodeB.ControlIF = cfg.GNodeB.ControlIF.WithNextAddr()
		cfg.GNodeB.DataIF = cfg.GNodeB.DataIF.WithNextAddr()
	}
	return gnbs, nil
}

func gnbIdGenerator(i int, gnbId string) (string, error) {
	gnbId_int, err := strconv.ParseInt(gnbId, 16, 0)
	if err != nil {
		return "", fmt.Errorf("given gnbId is invalid: %w", err)
	}
	base := int(gnbId_int) + i

	gnbId = fmt.Sprintf("%06X", base)
	return gnbId, nil
}

type UESimulationConfig struct {
	UeId                     int
	Gnbs                     map[string]*gnbCxt.GNBContext
	Cfg                      config.Config
	ScenarioChan             chan procedures.UeTesterMessage
	TimeBeforeDeregistration int
	TimeBeforeNgapHandover   int
	TimeBeforeXnHandover     int
	TimeBeforeIdle           int
	TimeBeforeReconnecting   int
	NumPduSessions           int
	RegistrationLoop         bool
	LoopCount                int
	TimeBeforeReregistration int
}

func SimulateSingleUE(simConfig UESimulationConfig, wg *sync.WaitGroup) {
	numGnb := len(simConfig.Gnbs)
	ueCfg := simConfig.Cfg
	msin, err := IncrementMsin(simConfig.UeId, simConfig.Cfg.Ue.Msin)
	if err != nil {
		logger.UELog.Fatal("could not generate msin: ", err)
	}
	ueCfg.Ue.Msin = msin
	logger.EllaCoreTesterLog.Info("testing registration using IMSI ", ueCfg.Ue.Msin, " UE")

	gnbIdGen := func(index int) string {
		id, err := gnbIdGenerator((simConfig.UeId+index)%numGnb, ueCfg.GNodeB.PlmnList.GnbId)
		if err != nil {
			logger.UELog.Fatal("could not generate gnbId: ", err)
		}
		return id
	}

	// Launch a coroutine to handle UE's individual scenario
	go func(scenarioChan chan procedures.UeTesterMessage, ueId int) {
		i := 0
		for {
			i++
			wg.Add(1)

			ueRx := make(chan procedures.UeTesterMessage)

			// Create a new UE coroutine
			// ue.NewUE returns context of the new UE
			ueTx, err := ue.NewUE(ueCfg, ueId, ueRx, simConfig.Gnbs[gnbIdGen(0)].GetInboundChannel(), wg)
			if err != nil {
				logger.UELog.Fatal("could not create UE: ", err)
			}

			// We tell the UE to perform a registration
			ueRx <- procedures.UeTesterMessage{Type: procedures.Registration}

			var deregistrationChannel <-chan time.Time = nil
			if simConfig.TimeBeforeDeregistration != 0 {
				deregistrationChannel = time.After(time.Duration(simConfig.TimeBeforeDeregistration) * time.Millisecond)
			}

			nextHandoverId := 0
			var ngapHandoverChannel <-chan time.Time = nil
			if simConfig.TimeBeforeNgapHandover != 0 {
				ngapHandoverChannel = time.After(time.Duration(simConfig.TimeBeforeNgapHandover) * time.Millisecond)
			}
			var xnHandoverChannel <-chan time.Time = nil
			if simConfig.TimeBeforeXnHandover != 0 {
				xnHandoverChannel = time.After(time.Duration(simConfig.TimeBeforeXnHandover) * time.Millisecond)
			}

			var idleChannel <-chan time.Time = nil
			var reconnectChannel <-chan time.Time = nil
			if simConfig.TimeBeforeIdle != 0 {
				idleChannel = time.After(time.Duration(simConfig.TimeBeforeIdle) * time.Millisecond)
			}

			loop := true
			registered := false
			state := ueCtx.MM5G_NULL
			for loop {
				select {
				case <-deregistrationChannel:
					if ueRx != nil {
						ueRx <- procedures.UeTesterMessage{Type: procedures.Terminate}
						ueRx = nil
					}
				case <-ngapHandoverChannel:
					err := trigger.TriggerNgapHandover(simConfig.Gnbs[gnbIdGen(nextHandoverId)], simConfig.Gnbs[gnbIdGen(nextHandoverId+1)], int64(ueId))
					if err != nil {
						logger.UELog.Error("could not trigger Ngap handover: ", err)
					}
					nextHandoverId++
				case <-xnHandoverChannel:
					err := trigger.TriggerXnHandover(simConfig.Gnbs[gnbIdGen(nextHandoverId)], simConfig.Gnbs[gnbIdGen(nextHandoverId+1)], int64(ueId))
					if err != nil {
						logger.UELog.Error("could not trigger Xn handover: ", err)
					}
					nextHandoverId++
				case <-idleChannel:
					if ueRx != nil {
						ueRx <- procedures.UeTesterMessage{Type: procedures.Idle}
						// Channel creation to be transformed into a task ;-)
						if simConfig.TimeBeforeReconnecting != 0 {
							reconnectChannel = time.After(time.Duration(simConfig.TimeBeforeReconnecting) * time.Millisecond)
						}
					}
				case <-reconnectChannel:
					if ueRx != nil {
						ueRx <- procedures.UeTesterMessage{Type: procedures.ServiceRequest}
					}
				case msg := <-scenarioChan:
					if ueRx != nil {
						ueRx <- msg
						if msg.Type == procedures.Terminate || msg.Type == procedures.Kill {
							ueRx = nil
						}
					}
				case msg := <-ueTx:
					logger.UELog.Info("switched from state ", state, " to state ", msg.StateChange)
					switch msg.StateChange {
					case ueCtx.MM5G_REGISTERED:
						if !registered {
							for i := 0; i < simConfig.NumPduSessions; i++ {
								ueRx <- procedures.UeTesterMessage{Type: procedures.NewPDUSession}
							}
							registered = true
						}
					case ueCtx.MM5G_NULL:
						loop = false
					}
					state = msg.StateChange
				}
			}
			if !simConfig.RegistrationLoop {
				break
			} else if simConfig.LoopCount != 0 && i == simConfig.LoopCount {
				break
			} else {
				time.Sleep(time.Duration(simConfig.TimeBeforeReregistration) * time.Millisecond)
			}
		}
	}(simConfig.ScenarioChan, simConfig.UeId)
}

func IncrementMsin(i int, msin string) (string, error) {
	msin_int, err := strconv.Atoi(msin)
	if err != nil {
		return "", fmt.Errorf("given msin is invalid: %w", err)
	}
	base := msin_int + (i - 1)

	var imsi string
	if len(msin) == 9 {
		imsi = fmt.Sprintf("%09d", base)
	} else {
		imsi = fmt.Sprintf("%010d", base)
	}
	return imsi, nil
}
