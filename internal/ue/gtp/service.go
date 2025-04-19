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
	"github.com/vishvananda/netlink"
)

const (
	Veth0InterfaceName = "veth0"
	Veth1InterfaceName = "veth1"
)

func SetupGtpInterface(ue *context.UEContext, msg gnbContext.UEMessage, n3InterfaceName string) error {
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

	time.Sleep(time.Second)

	opts := &VethPairOptions{
		N3InterfaceName: n3InterfaceName,
		Interface0Name:  Veth0InterfaceName,
		Interface1Name:  Veth1InterfaceName,
		UEIP:            ueIp + "/16",
		GTPUPort:        2152,
		GnbIP:           ueGnbIp.String(),
		UpfIP:           upfIp,
		Rteid:           gnbPduSession.GetTeidDownlink(),
	}

	vethPair, err := NewVethPair(opts)
	if err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}
	// Close the veth pair when the function returns
	defer func() {
		if err := vethPair.Close(); err != nil {
			logger.UELog.Errorf("failed to close veth pair: %v", err)
		}
	}()

	logger.UELog.Infof("created veth pair %v and %v", opts.Interface0Name, opts.Interface1Name)

	lTEID := gnbPduSession.GetTeidUplink()

	gnbLink, err := netlink.LinkByName(n3InterfaceName)
	if err != nil {
		return fmt.Errorf("cannot read gnb link: %v", err)
	}

	ebpfOpts := &AttachebpfProgramOptions{
		IfaceName:     Veth1InterfaceName,
		GnbIPAddress:  ueGnbIp.String(),
		GnbMacAddress: gnbLink.Attrs().HardwareAddr,
		UeMacAddress:  vethPair.Veth1Link.Attrs().HardwareAddr,
		UpfIPAddress:  upfIp,
		Teid:          lTEID,
	}

	err = AttachebpfProgram(ebpfOpts)
	if err != nil {
		return fmt.Errorf("failed to attach tc program: %w", err)
	}

	logger.UELog.Infof("attached tc program for UE %s", ueIp)
	return nil
}
