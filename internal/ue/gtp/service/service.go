/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package service

import (
	"fmt"
	"time"

	gnbContext "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	log "github.com/sirupsen/logrus"
)

func SetupGtpInterface(ue *context.UEContext, msg gnbContext.UEMessage) {
	gnbPduSession := msg.GNBPduSessions[0]
	pduSession, err := ue.GetPduSession(uint8(gnbPduSession.GetPduSessionId()))
	if pduSession == nil || err != nil {
		log.Error("[GNB][GTP] Aborting the setup of PDU Session ", gnbPduSession.GetPduSessionId(), ", this PDU session was not successfully configured on the UE's side.")
		return
	}
	pduSession.GnbPduSession = gnbPduSession

	if pduSession.Id != 1 {
		log.Warn("[GNB][GTP] Only one tunnel per UE is supported for now, no tunnel will be created for second PDU Session of given UE")
		return
	}

	// get UE GNB IP.
	pduSession.SetGnbIp(msg.GnbIp)

	ueGnbIp := pduSession.GetGnbIp()
	upfIp := pduSession.GnbPduSession.GetUpfIp()
	ueIp := pduSession.GetIp()
	msin := ue.GetMsin()
	nameInf := fmt.Sprintf("val%s", msin)
	stopSignal := make(chan bool)

	if pduSession.GetStopSignal() != nil {
		close(pduSession.GetStopSignal())
		time.Sleep(time.Second)
	}

	pduSession.SetStopSignal(stopSignal)

	time.Sleep(time.Second)

	tunOpts := &TunnelOptions{
		UEIP:             ueIp + "/16", // TODO: Get netmask from UE context
		GTPUPort:         2152,
		TunInterfaceName: "ellatester0",
		GnbIP:            ueGnbIp.String(),
		UpfIP:            upfIp,
		Lteid:            gnbPduSession.GetTeidUplink(),
		Rteid:            gnbPduSession.GetTeidDownlink(),
	}
	_, err = NewTunnel(tunOpts)
	if err != nil {
		log.Fatal("[UE][DATA] Unable to create tunnel: ", err)
		return
	}

	log.Info(fmt.Sprintf("[UE][GTP] Interface %s has successfully been configured for UE %s", nameInf, ueIp))
	log.Info(fmt.Sprintf("[UE][GTP] You can do traffic for this UE by binding to IP %s, eg:", ueIp))
	log.Info(fmt.Sprintf("[UE][GTP] iperf3 -B %s -c IPERF_SERVER -p PORT -t 9000", ueIp))
}
