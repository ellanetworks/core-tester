/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package handler

import (
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/ngap_control/nas_transport"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/message/sender"
	"github.com/ellanetworks/core-tester/internal/logger"
)

func HandlerUeInitialized(ue *context.GNBUe, message []byte, gnb *context.GNBContext) {
	// encode NAS message in NGAP.
	ngap, err := nas_transport.SendInitialUeMessage(message, ue, gnb)
	if err != nil {
		logger.GnbLog.Errorln("error making initial UE message: ", err)
	}

	// change state of UE.
	ue.SetStateOngoing()

	// Send Initial UE Message
	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngap, conn)
	if err != nil {
		logger.GnbLog.Errorln("error sending initial UE message: ", err)
	}
}

func HandlerUeOngoing(ue *context.GNBUe, message []byte, gnb *context.GNBContext) {
	ngap, err := nas_transport.SendUplinkNasTransport(message, ue, gnb)
	if err != nil {
		logger.GnbLog.Errorln("error making Uplink Nas Transport: ", err)
	}

	// Send Uplink Nas Transport
	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngap, conn)
	if err != nil {
		logger.GnbLog.Errorln("error sending Uplink Nas Transport: ", err)
	}
}

func HandlerUeReady(ue *context.GNBUe, message []byte, gnb *context.GNBContext) {
	ngap, err := nas_transport.SendUplinkNasTransport(message, ue, gnb)
	if err != nil {
		logger.GnbLog.Errorln("error making Uplink Nas Transport: ", err)
	}

	// Send Uplink Nas Transport
	conn := ue.GetSCTP()
	err = sender.SendToAmF(ngap, conn)
	if err != nil {
		logger.GnbLog.Errorln("error sending Uplink Nas Transport: ", err)
	}
}
