/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package gtp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	gnbContext "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	ebpf "github.com/ellanetworks/core-tester/internal/ue/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func SetupGtpInterface(ue *context.UEContext, msg gnbContext.UEMessage, n3Interface string, xdpAttachMode string) error {
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
	ueGnbIp := pduSession.GetGnbIp().String()
	upfIpStr := pduSession.GnbPduSession.GetUpfIp()

	// Parse and convert to network-byte-order uint32
	gnbIP := net.ParseIP(ueGnbIp).To4()
	if gnbIP == nil {
		return fmt.Errorf("invalid GNB IP: %s", ueGnbIp)
	}
	upfIP := net.ParseIP(upfIpStr).To4()
	if upfIP == nil {
		return fmt.Errorf("invalid UPF IP: %s", upfIpStr)
	}
	gnbIPVal := binary.BigEndian.Uint32(gnbIP)
	upfIPVal := binary.BigEndian.Uint32(upfIP)

	ueIp := pduSession.GetIp()
	nameInf := "ellatester0"

	time.Sleep(time.Second)

	tunOpts := &TunnelOptions{
		UEIP:             ueIp + "/16",
		GTPUPort:         2152,
		TunInterfaceName: nameInf,
		GnbIP:            ueGnbIp,
		UpfIP:            upfIpStr,
	}
	_, err = NewTunnel(tunOpts)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	logrus.Infof("Created tunnel with options: %+v", tunOpts)

	objs := ebpf.GTPObjects{}
	err = ebpf.LoadGTPObjects(&objs, nil)
	if err != nil {
		return fmt.Errorf("failed to load GTP objects: %w", err)
	}
	defer objs.Close()

	n3Iface, err := net.InterfaceByName(n3Interface)
	if err != nil {
		return fmt.Errorf("failed to lookup network iface %q: %s", n3Interface, err)
	}

	n3Link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Gtp,
		Interface: n3Iface.Index,
		Flags:     StringToXDPAttachMode(xdpAttachMode),
	})
	if err != nil {
		return fmt.Errorf("failed to attach eBPF program on n3 interface %q: %s", n3Interface, err)
	}
	defer n3Link.Close()

	var key uint32 = 0
	// Populate gnb_ip_map
	if err := objs.GTPMaps.GnbIpMap.Update(&key, &gnbIPVal, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update gnb_ip_map: %w", err)
	}

	// Populate upf_ip_map
	if err := objs.GTPMaps.UpfIpMap.Update(&key, &upfIPVal, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update upf_ip_map: %w", err)
	}

	// Populate teid_map
	teid := gnbPduSession.GetTeidUplink()
	if err := objs.GTPMaps.TeidMap.Update(&key, &teid, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update teid_map: %w", err)
	}

	logrus.Infof("Attached eBPF program to n3 interface %q", n3Interface)
	logrus.Infof("[UE][GTP] Interface %s configured for UE %s", nameInf, ueIp)
	logrus.Infof("[UE][GTP] Send traffic: iperf3 -B %s -c IPERF_SERVER -p PORT -t 9000", ueIp)

	// sleep for 5 min
	time.Sleep(5 * time.Minute)

	return nil
}

func StringToXDPAttachMode(Mode string) link.XDPAttachFlags {
	switch Mode {
	case "generic":
		return link.XDPGenericMode
	case "native":
		return link.XDPDriverMode
	case "offload":
		return link.XDPOffloadMode
	default:
		return link.XDPGenericMode
	}
}

type Tunnel struct {
	Name    string
	gtpConn *net.UDPConn
	tunIF   *water.Interface
}

type TunnelOptions struct {
	UEIP             string
	GnbIP            string
	UpfIP            string
	GTPUPort         int
	TunInterfaceName string
}

func NewTunnel(opts *TunnelOptions) (*Tunnel, error) {
	laddr := &net.UDPAddr{
		IP:   net.ParseIP(opts.GnbIP),
		Port: opts.GTPUPort,
	}
	raddr := &net.UDPAddr{
		IP:   net.ParseIP(opts.UpfIP),
		Port: opts.GTPUPort,
	}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to UPF: %v", err)
	}

	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = opts.TunInterfaceName
	ifce, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("could not open TUN interface: %v", err)
	}

	eth, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %v", err)
	}

	ueAddr, err := netlink.ParseAddr(opts.UEIP)
	if err != nil {
		return nil, fmt.Errorf("could not parse UE address: %v", err)
	}

	err = netlink.AddrAdd(eth, ueAddr)
	if err != nil {
		return nil, fmt.Errorf("could not assign UE address to TUN interface: %v", err)
	}

	err = netlink.LinkSetUp(eth)
	if err != nil {
		return nil, fmt.Errorf("could not set TUN interface UP: %v", err)
	}

	go gtpToTun(conn, ifce)

	return &Tunnel{
		Name:    ifce.Name(),
		gtpConn: conn,
		tunIF:   ifce,
	}, nil
}

func (t *Tunnel) Close() error {
	var err error
	errG := t.gtpConn.Close()
	if errG != nil {
		err = fmt.Errorf("could not close GTP connection: %v", errG)
	}
	errT := t.tunIF.Close()
	if errT != nil {
		err = fmt.Errorf("%v; could not close TUN interface: %v", err, errT)
	}
	return err
}

func gtpToTun(conn *net.UDPConn, ifce *water.Interface) {
	var payloadStart int
	packet := make([]byte, 2000)
	for {
		// Read a packet from UDP
		// Currently ignores the address
		n, _, err := conn.ReadFrom(packet)
		if err != nil {
			log.Printf("error reading from GTP: %v", err)
		}
		// Ignore packets that are not a GTP-U v1 T-PDU packet
		if packet[0]&0x30 != 0x30 || packet[1] != 0xFF {
			continue
		}
		// Write the packet to the TUN interface
		// ignoring the GTP header
		payloadStart = 8
		if packet[0]&0x07 > 0 {
			payloadStart = payloadStart + 3
		}
		if packet[0]&0x04 > 0 {
			// Next Header extension present
			for {
				if packet[payloadStart] == 0x00 {
					payloadStart = payloadStart + 1
					break
				}
				payloadStart = payloadStart + (int(packet[payloadStart+1]) * 4)
			}
		}
		_, err = ifce.Write(packet[payloadStart:n])
		if err != nil {
			log.Printf("error writing to tun interface: %v", err)
			continue
		}
	}
}
