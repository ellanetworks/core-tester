/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package gtp

import (
	"fmt"
	"net"
	"time"

	gnbContext "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/vishvananda/netlink"
)

const (
	NSName                = "ue"
	VethHostInterfaceName = "veth0"
	VethUEInterfaceName   = "veth1"
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

	opts := &SetupUEVethPairOpts{
		NSName:          NSName,
		UpfIP:           upfIp,
		VethHost:        VethHostInterfaceName,
		VethUE:          VethUEInterfaceName,
		HostCIDR:        "10.45.0.100/16", // This should not be hardcoded
		UECIDR:          ueIp + "/16",
		HostN3Interface: n3InterfaceName,
	}
	vethPair, err := SetupUEVethPair(opts)
	if err != nil {
		return fmt.Errorf("failed to setup veth pair: %w", err)
	}

	logger.UELog.Infof("created namespace %s and veth pair %s %s", NSName, VethHostInterfaceName, VethUEInterfaceName)

	lTEID := gnbPduSession.GetTeidUplink()

	gnbLink, err := netlink.LinkByName(n3InterfaceName)
	if err != nil {
		return fmt.Errorf("cannot read gnb link: %v", err)
	}

	upfMacStr := "52:54:00:53:75:fd" // Remove this hardcoded value

	upfHw, err := net.ParseMAC(upfMacStr)
	if err != nil {
		return fmt.Errorf("failed to parse UPF MAC address: %w", err)
	}

	ebpfOpts := &AttachEbpfProgramOptions{
		IfaceName:       VethHostInterfaceName,
		GnbIPAddress:    ueGnbIp.String(),
		GnbMacAddress:   gnbLink.Attrs().HardwareAddr,
		UpfIPAddress:    upfIp,
		Teid:            lTEID,
		UEMacAddress:    vethPair.UELink.Attrs().HardwareAddr,
		UpfMacAddress:   upfHw,
		N3InterfaceName: n3InterfaceName,
	}

	err = AttachEbpfProgram(ebpfOpts)
	if err != nil {
		return fmt.Errorf("failed to attach ebpf program: %w", err)
	}

	logger.UELog.Infof("attached tc program for UE %s", ueIp)
	return nil
}
