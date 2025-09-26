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
	tuns    []*water.Interface // multiple queues for RX only
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
	laddr := &net.UDPAddr{IP: net.ParseIP(opts.GnbIP), Port: opts.GTPUPort}
	raddr := &net.UDPAddr{IP: net.ParseIP(opts.UpfIP), Port: opts.GTPUPort}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to UPF: %v", err)
	}

	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = opts.TunInterfaceName
	cfg.MultiQueue = true

	nq := runtime.NumCPU() / 2
	if nq < 2 {
		nq = 2
	}

	tuns := make([]*water.Interface, 0, nq)
	for i := 0; i < nq; i++ {
		ifce, err := water.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("open TUN (mq): %w", err)
		}
		tuns = append(tuns, ifce)
	}

	// Netlink config once on the device (use the first fd)
	link, err := netlink.LinkByName(tuns[0].Name())
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %w", err)
	}
	ueAddr, err := netlink.ParseAddr(opts.UEIP)
	if err != nil {
		return nil, fmt.Errorf("could not parse UE address: %w", err)
	}
	if err := netlink.AddrAdd(link, ueAddr); err != nil {
		return nil, fmt.Errorf("addr add: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("link up: %w", err)
	}

	go tunToGtp(conn, tuns[0], opts.Lteid)

	go gtpToTunFanout(conn, tuns)

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

// === Unchanged TX path (single-queue) ===
func tunToGtp(conn *net.UDPConn, ifce *water.Interface, lteid uint32) {
	buf := make([]byte, 2000)
	hdr := [8]byte{0x30, 0xFF, 0, 0, 0, 0, 0, 0}
	for {
		n, err := ifce.Read(buf)
		if err != nil {
			log.Printf("tun read: %v", err)
			continue
		}
		if n == 0 {
			continue
		}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		binary.BigEndian.PutUint32(hdr[4:8], lteid)
		pkt := append(hdr[:], buf[:n]...)
		if _, err := conn.Write(pkt); err != nil {
			log.Printf("udp write: %v", err)
		}
	}
}

// === RX path with fan-out across TUN queues ===
func gtpToTunFanout(conn *net.UDPConn, queues []*water.Interface) {
	if len(queues) == 0 {
		return
	}
	buf := make([]byte, 1<<15) // 32 KiB
	var rr int

	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("udp read: %v", err)
			continue
		}
		if n < 8 {
			continue
		}

		// GTPv1 (version=1, PT=1) and T-PDU (0xFF)
		if (buf[0]&0x30) != 0x30 || buf[1] != 0xFF {
			continue
		}

		l := int(binary.BigEndian.Uint16(buf[2:4])) // bytes after first 8
		// Sanity: l must be <= n-8
		if l < 0 || l > n-8 {
			continue
		}

		payloadStart := n - l // 8 + opt + exts
		if payloadStart < 8 { // should never happen after check above
			continue
		}

		ifce := queues[rr%len(queues)]
		rr++
		if _, err := ifce.Write(buf[payloadStart:n]); err != nil {
			log.Printf("tun write: %v", err)
		}
	}
}
