// Copyright 2025 Ghislain Bourgeois
// SPDX-License-Identifier: GPL-3.0-or-later

package gtpu

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

const gtpuPort = 2152

var (
	teidUPF uint32 = 0x000000001
	teidRAN uint32 = 0x000000010
)

const (
	ueIPAddress = "10.45.0.10/24"
)

type Tunnel struct {
	Name    string
	gtpConn *net.UDPConn
	tunIF   *water.Interface
	lteid   uint32
	rteid   uint32
}

func NewTunnel(gnbIP string, upfIP string) (*Tunnel, error) {
	laddr := &net.UDPAddr{
		IP:   net.ParseIP(gnbIP),
		Port: gtpuPort,
	}
	raddr := &net.UDPAddr{
		IP:   net.ParseIP(upfIP),
		Port: gtpuPort,
	}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to UPF: %v", err)
	}

	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "uproot0"
	ifce, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("could not open TUN interface: %v", err)
	}

	eth, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %v", err)
	}

	ueAddr, err := netlink.ParseAddr(ueIPAddress)
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

	go tunToGtp(conn, ifce)
	go gtpToTun(conn, ifce)

	return &Tunnel{
		Name:    ifce.Name(),
		gtpConn: conn,
		tunIF:   ifce,
		lteid:   teidRAN,
		rteid:   teidUPF,
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

func tunToGtp(conn *net.UDPConn, ifce *water.Interface) {
	packet := make([]byte, 2000)
	packet[0] = 0x30                                 // Version 1, Protocol type GTP
	packet[1] = 0xFF                                 // Message type T-PDU
	binary.BigEndian.PutUint16(packet[2:4], 0)       // Length
	binary.BigEndian.PutUint32(packet[4:8], teidRAN) // TEID
	for {
		n, err := ifce.Read(packet[8:])
		if err != nil {
			log.Printf("error reading from tun interface: %v", err)
			continue
		}
		if n == 0 {
			log.Println("read 0 bytes")
			continue
		}
		binary.BigEndian.PutUint16(packet[2:4], uint16(n))
		_, err = conn.Write(packet[:n+8])
		if err != nil {
			log.Printf("error writing to GTP: %v", err)
			continue
		}
	}
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
