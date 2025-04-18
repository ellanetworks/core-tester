/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package ue

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/ellanetworks/core-tester/internal/config"
	gnbContext "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/procedures"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/ellanetworks/core-tester/internal/ue/gtp"
	"github.com/ellanetworks/core-tester/internal/ue/nas"
	"github.com/ellanetworks/core-tester/internal/ue/nas/service"
	"github.com/ellanetworks/core-tester/internal/ue/nas/trigger"
	"github.com/ellanetworks/core-tester/internal/ue/scenario"
)

func NewUE(conf config.Config, id int, ueMgrChannel chan procedures.UeTesterMessage, gnbInboundChannel chan gnbContext.UEMessage, wg *sync.WaitGroup) (chan scenario.ScenarioMessage, error) {
	// new UE instance.
	ue := &context.UEContext{}
	scenarioChan := make(chan scenario.ScenarioMessage)

	// new UE context
	pubKey, err := conf.GetHomeNetworkPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error while getting home network public key: %w", err)
	}
	err = ue.NewRanUeContext(
		conf.Ue.Msin,
		conf.GetUESecurityCapability(),
		conf.Ue.Key,
		conf.Ue.Opc,
		"c9e8763286b5b9ffbdf56e1297d0887b",
		conf.Ue.Amf,
		conf.Ue.Sqn,
		conf.Ue.Hplmn.Mcc,
		conf.Ue.Hplmn.Mnc,
		pubKey,
		conf.Ue.RoutingIndicator,
		conf.Ue.Dnn,
		int32(conf.Ue.Snssai.Sst),
		conf.Ue.Snssai.Sd,
		scenarioChan,
		gnbInboundChannel,
		id)
	if err != nil {
		return nil, fmt.Errorf("error while creating UE context: %w", err)
	}

	go func() {
		// starting communication with GNB and listen.
		service.InitConn(ue, ue.GetGnbInboundChannel())
		sigStop := make(chan os.Signal, 1)
		signal.Notify(sigStop, os.Interrupt)

		// Block until a signal is received.
		loop := true
		for loop {
			select {
			case msg, open := <-ue.GetGnbTx():
				if !open {
					logger.UELog.Warn("[", ue.GetMsin(), "] Stopping UE as communication with gNB was closed")
					ue.SetGnbTx(nil)
					break
				}
				err := gnbMsgHandler(msg, ue)
				if err != nil {
					logger.UELog.Error("[", ue.GetMsin(), "] Error while handling message from gNB: ", err)
				}
			case msg, open := <-ueMgrChannel:
				if !open {
					logger.UELog.Warn("[", ue.GetMsin(), "] Stopping UE as communication with scenario was closed")
					loop = false
					break
				}
				loop = ueMgrHandler(msg, ue)
			case <-ue.GetDRX():
				verifyPaging(ue)
			}
		}
		ue.Terminate()
		wg.Done()
	}()

	return scenarioChan, nil
}

func gnbMsgHandler(msg gnbContext.UEMessage, ue *context.UEContext) error {
	if msg.IsNas {
		err := nas.DispatchNas(ue, msg.Nas)
		if err != nil {
			return fmt.Errorf("could not dispatch NAS message: %w", err)
		}
	} else if msg.GNBPduSessions[0] != nil {
		// Setup PDU Session
		err := gtp.SetupGtpInterface(ue, msg)
		if err != nil {
			return fmt.Errorf("could not setup GTP interface: %w", err)
		}
	} else if msg.GNBRx != nil && msg.GNBTx != nil && msg.GNBInboundChannel != nil {
		logger.UELog.Info("gNodeB is telling us to use another gNodeB")
		previousGnbRx := ue.GetGnbRx()
		ue.SetGnbInboundChannel(msg.GNBInboundChannel)
		ue.SetGnbRx(msg.GNBRx)
		ue.SetGnbTx(msg.GNBTx)
		previousGnbRx <- gnbContext.UEMessage{ConnectionClosed: true}
		close(previousGnbRx)
	} else {
		return fmt.Errorf("unknown message from gNodeB")
	}
	return nil
}

func verifyPaging(ue *context.UEContext) {
	gnbTx := make(chan gnbContext.UEMessage, 1)

	ue.GetGnbInboundChannel() <- gnbContext.UEMessage{GNBTx: gnbTx, FetchPagedUEs: true}
	msg := <-gnbTx
	for _, pagedUE := range msg.PagedUEs {
		if ue.Get5gGuti() != nil && pagedUE.FiveGSTMSI != nil && [4]uint8(pagedUE.FiveGSTMSI.FiveGTMSI.Value) == ue.GetTMSI5G() {
			ueMgrHandler(procedures.UeTesterMessage{Type: procedures.ServiceRequest}, ue)
			return
		}
	}
}

func ueMgrHandler(msg procedures.UeTesterMessage, ue *context.UEContext) bool {
	loop := true
	switch msg.Type {
	case procedures.Registration:
		err := trigger.InitRegistration(ue)
		if err != nil {
			logger.UELog.Error("cannot register UE ", err)
		}
	case procedures.Deregistration:
		err := trigger.InitDeregistration(ue)
		if err != nil {
			logger.UELog.Error("cannot deregister UE ", err)
		}
	case procedures.NewPDUSession:
		err := trigger.InitPduSessionRequest(ue)
		if err != nil {
			logger.UELog.Error("cannot create new PDU Session ", err)
		}
	case procedures.DestroyPDUSession:
		pdu, err := ue.GetPduSession(msg.Param)
		if err != nil {
			logger.UELog.Error("cannot release unknown PDU Session ID ", msg.Param)
			return loop
		}
		err = trigger.InitPduSessionRelease(ue, pdu)
		if err != nil {
			logger.UELog.Error("cannot release PDU Session ID ", msg.Param)
		}
	case procedures.Idle:
		// We switch UE to IDLE
		ue.SetStateMM_IDLE()
		trigger.SwitchToIdle(ue)
		ue.CreateDRX(25 * time.Millisecond)
	case procedures.ServiceRequest:
		if ue.GetStateMM() == context.MM5G_IDLE {
			ue.StopDRX()

			// Since gNodeB stopped communication after switching to Idle, we need to connect back to gNodeB
			service.InitConn(ue, ue.GetGnbInboundChannel())
			if ue.Get5gGuti() != nil {
				err := trigger.InitServiceRequest(ue)
				if err != nil {
					logger.UELog.Error("cannot send Service Request ", err)
				}
			} else {
				// If AMF did not assign us a GUTI, we have to fallback to the usual Registration/Authentification process
				// PDU Sessions will still be recovered
				err := trigger.InitRegistration(ue)
				if err != nil {
					logger.UELog.Error("cannot register UE ", err)
				}
			}
		}
	case procedures.Terminate:
		logger.UELog.Info("terminating UE as requested")
		// If UE is registered
		if ue.GetStateMM() == context.MM5G_REGISTERED {
			// Release PDU Sessions
			for i := uint8(1); i <= 16; i++ {
				pduSession, _ := ue.GetPduSession(i)
				if pduSession != nil {
					err := trigger.InitPduSessionRelease(ue, pduSession)
					if err != nil {
						logger.UELog.Error("cannot release PDU Session ID ", i)
						continue
					}
					select {
					case <-pduSession.Wait:
					case <-time.After(500 * time.Millisecond):
						// If still unregistered after 500 ms, continue
					}
				}
			}
			// Initiate Deregistration
			err := trigger.InitDeregistration(ue)
			if err != nil {
				logger.UELog.Error("cannot deregister UE ", err)
			}
		}
		// Else, nothing to do
		loop = false
	case procedures.Kill:
		loop = false
	}
	return loop
}
