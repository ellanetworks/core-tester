/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package gtp

import (
	"fmt"
	"time"

	gnbContext "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
)

func SetupGtpInterface(ue *context.UEContext, msg gnbContext.UEMessage) error {
	gnbPduSession := msg.GNBPduSessions[0]
	pduSession, err := ue.GetPduSession(uint8(gnbPduSession.GetPduSessionId()))
	if err != nil {
		return fmt.Errorf("failed to get PDU session: %w", err)
	}
	if pduSession == nil {
		return fmt.Errorf("pdu session not found")
	}

	pduSession.GnbPduSession = gnbPduSession

	if pduSession.Id != 1 {
		return fmt.Errorf("pdu session id is not 1")
	}

	pduSession.SetGnbIp(msg.GnbIp)

	ueGnbIp := pduSession.GetGnbIp()
	upfIp := pduSession.GnbPduSession.GetUpfIp()
	ueIp := pduSession.GetIp()
	nameInf := "ellatester0"

	time.Sleep(time.Second)

	tunOpts := &TunnelOptions{
		UEIP:             ueIp + "/16",
		GTPUPort:         2152,
		TunInterfaceName: nameInf,
		GnbIP:            ueGnbIp.String(),
		UpfIP:            upfIp,
		Lteid:            gnbPduSession.GetTeidUplink(),
		Rteid:            gnbPduSession.GetTeidDownlink(),
	}
	_, err = NewTunnel(tunOpts)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}
	logger.UELog.Infof("created gtp-u tunnel for UE %s", ueIp)
	return nil
}
