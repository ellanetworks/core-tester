/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 * © Copyright 2023 Valentin D'Emmanuele
 */
package service

import (
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/gnb/nas"
	"github.com/ellanetworks/core-tester/internal/gnb/nas/message/sender"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/trigger"
	"github.com/ellanetworks/core-tester/internal/logger"
)

func InitServer(gnb *context.GNBContext) {
	go gnbListen(gnb)
}

func gnbListen(gnb *context.GNBContext) {
	ln := gnb.GetInboundChannel()

	for {
		message := <-ln

		if message.FetchPagedUEs {
			if message.GNBTx != nil {
				message.GNBTx <- context.UEMessage{PagedUEs: gnb.GetPagedUEs()}
				close(message.GNBTx)
			} else {
				logger.GnbLog.Infof("unable to give PageUEs to UE, GNBTx is nil")
			}
			continue
		}

		// new instance GNB UE context
		// store UE in UE Pool
		// store UE connection
		// select AMF and get sctp association
		// make a tun interface
		ue, _ := gnb.GetGnbUeByPrUeId(message.PrUeId)
		if ue != nil && message.IsHandover {
			// We already have a context for this UE since it was sent to us by the AMF from a NGAP Handover
			// Notify the AMF that the UE has successfully been handed over to US
			ue.SetGnbRx(message.GNBRx)
			ue.SetGnbTx(message.GNBTx)

			// We enable the new PDU Session handed over to us
			msg := context.UEMessage{GNBPduSessions: ue.GetPduSessions(), GnbIp: gnb.GetN3GnbIp()}
			sender.SendMessageToUe(ue, msg)

			ue.SetStateReady()

			err := trigger.SendHandoverNotify(gnb, ue)
			if err != nil {
				logger.GnbLog.Errorf("error while sending Handover Notify: %s", err)
			}
		} else {
			var err error
			ue, err = gnb.NewGnBUe(message.GNBTx, message.GNBRx, message.PrUeId, message.Tmsi)
			if ue == nil && err != nil {
				logger.GnbLog.Errorf("ue was not created successfully: %s. Closing connection with UE.", err)
				close(message.GNBTx)
				continue
			}
			if message.UEContext != nil && message.IsHandover {
				// Xn Handover
				logger.GnbLog.Info("received incoming handover for UE from another gNodeB")
				ue.SetStateReady()
				ue.CopyFromPreviousContext(message.UEContext)
				err := trigger.SendPathSwitchRequest(gnb, ue)
				if err != nil {
					logger.GnbLog.Errorf("error while sending Path Switch Request: %s", err)
				}
			} else {
				// Usual first UE connection to a gNodeB
				logger.GnbLog.Info("received incoming connection from new UE")
				mcc, mnc := gnb.GetMccAndMnc()
				message.GNBTx <- context.UEMessage{Mcc: mcc, Mnc: mnc}
				ue.SetPduSessions(message.GNBPduSessions)
			}
		}

		if ue == nil {
			logger.GnbLog.Errorf("ue has not been created")
			continue
		}

		// accept and handle connection.
		go processingConn(ue, gnb)
	}
}

func processingConn(ue *context.GNBUe, gnb *context.GNBContext) {
	rx := ue.GetGnbRx()
	for {
		message, done := <-rx
		gnbUeContext, err := gnb.GetGnbUe(ue.GetRanUeId())
		if (gnbUeContext == nil || err != nil) && done {
			logger.GnbLog.Errorf("ignoring message from UE ", ue.GetRanUeId(), " as UE Context was cleaned as requested by AMF.")
			break
		}
		if !done {
			if gnbUeContext != nil {
				gnbUeContext.SetStateDown()
			}
			break
		}

		// send to dispatch.
		if message.ConnectionClosed {
			logger.GnbLog.Info("cleaning up context on current gNb")
			gnbUeContext.SetStateDown()
			if gnbUeContext.GetHandoverGnodeB() == nil {
				// We do not clean the context if it's a NGAP Handover, as AMF will request the context clean-up
				// Otherwise, we do clean the context
				gnb.DeleteGnBUe(ue)
			}
		} else if message.IsNas {
			nas.Dispatch(ue, message.Nas, gnb)
		} else if message.Idle {
			err := trigger.SendUeContextReleaseRequest(ue)
			if err != nil {
				logger.GnbLog.Errorf("error while sending UE Context Release Request: %s", err)
			}
		} else {
			logger.GnbLog.Error("received unknown message from UE")
		}
	}
}
