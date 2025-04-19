// Copyright 2025 Ghislain Bourgeois
// SPDX-License-Identifier: GPL-3.0-or-later

package gtp

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

type VethPairOptions struct {
	Interface0Name string
	Interface1Name string
	UEIP           string
	GnbIP          string
	UpfIP          string
	GTPUPort       int
	Rteid          uint32
}

func NewVethPair(opts *VethPairOptions) error {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  opts.Interface0Name,
			MTU:   1500,
			Flags: net.FlagUp,
		},
		PeerName: opts.Interface1Name,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("could not create veth pair: %v", err)
	}

	link0, err := netlink.LinkByName(opts.Interface0Name)
	if err != nil {
		return fmt.Errorf("cannot read TUN interface: %v", err)
	}

	if err := netlink.LinkSetUp(link0); err != nil {
		return fmt.Errorf("could not set TUN interface up: %v", err)
	}

	link1, err := netlink.LinkByName(opts.Interface1Name)
	if err != nil {
		return fmt.Errorf("cannot read TUN interface: %v", err)
	}

	if err := netlink.LinkSetUp(link1); err != nil {
		return fmt.Errorf("could not set TUN interface up: %v", err)
	}

	addr, err := netlink.ParseAddr(opts.UEIP)
	if err != nil {
		return fmt.Errorf("could not parse UE address: %v", err)
	}

	err = netlink.AddrAdd(link0, addr)
	if err != nil {
		return fmt.Errorf("could not assign UE address to TUN interface: %v", err)
	}

	// go tunToGtp(conn, ifce, opts.Lteid)
	// go gtpToTun(conn, ifce)

	return nil
}

// func (t *Tunnel) Close() error {
// 	var err error
// 	errG := t.gtpConn.Close()
// 	if errG != nil {
// 		err = fmt.Errorf("could not close GTP connection: %v", errG)
// 	}
// 	errT := t.tunIF.Close()
// 	if errT != nil {
// 		err = fmt.Errorf("%v; could not close TUN interface: %v", err, errT)
// 	}
// 	return err
// }

// func tunToGtp(conn *net.UDPConn, ifce *water.Interface, lteid uint32) {
// 	packet := make([]byte, 2000)
// 	packet[0] = 0x30                               // Version 1, Protocol type GTP
// 	packet[1] = 0xFF                               // Message type T-PDU
// 	binary.BigEndian.PutUint16(packet[2:4], 0)     // Length
// 	binary.BigEndian.PutUint32(packet[4:8], lteid) // TEID
// 	for {
// 		n, err := ifce.Read(packet[8:])
// 		if err != nil {
// 			log.Printf("error reading from tun interface: %v", err)
// 			continue
// 		}
// 		if n == 0 {
// 			log.Println("read 0 bytes")
// 			continue
// 		}
// 		binary.BigEndian.PutUint16(packet[2:4], uint16(n))
// 		_, err = conn.Write(packet[:n+8])
// 		if err != nil {
// 			log.Printf("error writing to GTP: %v", err)
// 			continue
// 		}
// 	}
// }

// func gtpToTun(conn *net.UDPConn, ifce *water.Interface) {
// 	var payloadStart int
// 	packet := make([]byte, 2000)
// 	for {
// 		// Read a packet from UDP
// 		// Currently ignores the address
// 		n, _, err := conn.ReadFrom(packet)
// 		if err != nil {
// 			log.Printf("error reading from GTP: %v", err)
// 		}
// 		// Ignore packets that are not a GTP-U v1 T-PDU packet
// 		if packet[0]&0x30 != 0x30 || packet[1] != 0xFF {
// 			continue
// 		}
// 		// Write the packet to the TUN interface
// 		// ignoring the GTP header
// 		payloadStart = 8
// 		if packet[0]&0x07 > 0 {
// 			payloadStart = payloadStart + 3
// 		}
// 		if packet[0]&0x04 > 0 {
// 			// Next Header extension present
// 			for {
// 				if packet[payloadStart] == 0x00 {
// 					payloadStart = payloadStart + 1
// 					break
// 				}
// 				payloadStart = payloadStart + (int(packet[payloadStart+1]) * 4)
// 			}
// 		}
// 		_, err = ifce.Write(packet[payloadStart:n])
// 		if err != nil {
// 			log.Printf("error writing to tun interface: %v", err)
// 			continue
// 		}
// 	}
// }
