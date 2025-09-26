// Copyright 2025 Ghislain Bourgeois
// SPDX-License-Identifier: GPL-3.0-or-later

package gtp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"runtime"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

type Tunnel struct {
	Name    string
	gtpConn *net.UDPConn
	tunIF   *water.Interface
	lteid   uint32
	rteid   uint32
}

type TunnelOptions struct {
	UEIP             string
	GnbIP            string
	UpfIP            string
	GTPUPort         int
	TunInterfaceName string
	Lteid            uint32
	Rteid            uint32
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
		PlatformSpecificParams: water.PlatformSpecificParams{
			MultiQueue: true,
		},
	}
	config.Name = opts.TunInterfaceName

	var tuns []*water.Interface
	queues := runtime.NumCPU() / 2 // or 4–8; tune
	if queues < 2 {
		queues = 2
	}

	for i := 0; i < queues; i++ {
		ifce, err := water.New(config) // same Name, MultiQueue true
		if err != nil {
			return nil, fmt.Errorf("open TUN mq: %w", err)
		}
		tuns = append(tuns, ifce)
	}

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

	go tunToGtp(conn, opts.Lteid, ifce)
	go gtpToTun(conn, ifce)

	return &Tunnel{
		Name:    ifce.Name(),
		gtpConn: conn,
		tunIF:   ifce,
		lteid:   opts.Lteid,
		rteid:   opts.Rteid,
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

func tunToGtp(conn *net.UDPConn, lteid uint32, tuns ...*water.Interface) {
	// packet := make([]byte, 2000)
	// packet[0] = 0x30                               // Version 1, Protocol type GTP
	// packet[1] = 0xFF                               // Message type T-PDU
	// binary.BigEndian.PutUint16(packet[2:4], 0)     // Length
	// binary.BigEndian.PutUint32(packet[4:8], lteid) // TEID
	// for {
	// 	n, err := ifce.Read(packet[8:])
	// 	if err != nil {
	// 		log.Printf("error reading from tun interface: %v", err)
	// 		continue
	// 	}
	// 	if n == 0 {
	// 		log.Println("read 0 bytes")
	// 		continue
	// 	}
	// 	binary.BigEndian.PutUint16(packet[2:4], uint16(n))
	// 	_, err = conn.Write(packet[:n+8])
	// 	if err != nil {
	// 		log.Printf("error writing to GTP: %v", err)
	// 		continue
	// 	}
	// }
	for i := range tuns {
		go func(ifce *water.Interface) {
			// optionally: runtime.LockOSThread()
			buf := make([]byte, 2048)
			hdr := make([]byte, 8) // fixed GTP header
			hdr[0] = 0x30
			hdr[1] = 0xFF

			for {
				n, err := ifce.Read(buf) // IP packet from UE
				if err != nil {
					log.Printf("tun read: %v", err)
					continue
				}
				binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
				binary.BigEndian.PutUint32(hdr[4:8], lteid)

				// write header+payload in one go (avoid two writes)
				// use a single contiguous slice backed by a scratch buffer
				pkt := append(hdr[:8], buf[:n]...)
				if _, err := conn.Write(pkt); err != nil {
					log.Printf("udp write: %v", err)
				}
			}
		}(tuns[i])
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
