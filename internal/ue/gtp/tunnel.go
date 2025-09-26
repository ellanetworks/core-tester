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
	tuns    []*water.Interface
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
		ifce, err := water.New(config) // same Name, MultiQueue: true
		if err != nil {
			return nil, fmt.Errorf("open TUN mq: %w", err)
		}
		tuns = append(tuns, ifce)
	}

	// netlink setup once on the device
	eth, err := netlink.LinkByName(tuns[0].Name())
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %w", err)
	}
	ueAddr, _ := netlink.ParseAddr(opts.UEIP)
	if err := netlink.AddrAdd(eth, ueAddr); err != nil {
		return nil, fmt.Errorf("addr add: %w", err)
	}
	if err := netlink.LinkSetUp(eth); err != nil {
		return nil, fmt.Errorf("link up: %w", err)
	}

	// IMPORTANT: pass *all* queues to the workers
	go tunToGtp(conn, opts.Lteid, tuns...)
	go gtpToTun(conn, tuns...) // see change below to accept variadic

	return &Tunnel{
		Name:    tuns[0].Name(),
		gtpConn: conn,
		tuns:    tuns,
		lteid:   opts.Lteid,
		rteid:   opts.Rteid,
	}, nil

}

func (t *Tunnel) Close() error {
	var firstErr error
	if err := t.gtpConn.Close(); err != nil {
		firstErr = err
	}
	for _, q := range t.tuns {
		if err := q.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func tunToGtp(conn *net.UDPConn, lteid uint32, tuns ...*water.Interface) {
	for _, ifce := range tuns {
		go func(ifce *water.Interface) {
			buf := make([]byte, 2048)
			hdr := []byte{0x30, 0xFF, 0, 0, 0, 0, 0, 0}
			for {
				n, err := ifce.Read(buf)
				if err != nil {
					log.Printf("tun read: %v", err)
					continue
				}
				binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
				binary.BigEndian.PutUint32(hdr[4:8], lteid)
				pkt := append(append([]byte{}, hdr...), buf[:n]...)
				if _, err := conn.Write(pkt); err != nil {
					log.Printf("udp write: %v", err)
				}
			}
		}(ifce)
	}
}

func gtpToTun(conn *net.UDPConn, tuns ...*water.Interface) {
	// simple fan-out: round-robin into the queues
	var i int
	pkt := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFrom(pkt)
		if err != nil {
			log.Printf("GTP read: %v", err)
			continue
		}
		if n < 8 || (pkt[0]&0x30) != 0x30 || pkt[1] != 0xFF {
			continue
		}

		payloadStart := 8
		if (pkt[0] & 0x07) != 0 {
			payloadStart += 4
		} // E/S/PN → +4
		if (pkt[0] & 0x04) != 0 {
			// walk ext hdrs
			off := payloadStart
			for {
				if pkt[off] == 0x00 {
					off++
					payloadStart = off
					break
				}
				off += int(pkt[off+1]) * 4
			}
		}

		if len(tuns) == 0 {
			continue
		}
		ifce := tuns[i%len(tuns)]
		i++
		if _, err := ifce.Write(pkt[payloadStart:n]); err != nil {
			log.Printf("tun write: %v", err)
		}
	}
}
