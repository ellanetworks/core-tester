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
	laddr := &net.UDPAddr{IP: net.ParseIP(opts.GnbIP), Port: opts.GTPUPort}
	raddr := &net.UDPAddr{IP: net.ParseIP(opts.UpfIP), Port: opts.GTPUPort}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to UPF: %w", err)
	}
	// Big UDP buffers help under load
	_ = conn.SetReadBuffer(64 * 1024 * 1024)
	_ = conn.SetWriteBuffer(64 * 1024 * 1024)

	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			MultiQueue: true, // this is the correct place for MQ on Linux
		},
	}
	cfg.Name = opts.TunInterfaceName

	// Open multiple fds on the same TUN name (one per queue)
	q := runtime.NumCPU() / 2
	if q < 2 {
		q = 2
	}
	tuns := make([]*water.Interface, 0, q)
	for i := 0; i < q; i++ {
		ifce, err := water.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("open TUN MQ: %w", err)
		}
		tuns = append(tuns, ifce)
	}

	// Netlink setup once
	link, err := netlink.LinkByName(tuns[0].Name())
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %w", err)
	}
	ueAddr, err := netlink.ParseAddr(opts.UEIP)
	if err != nil {
		return nil, fmt.Errorf("could not parse UE address: %w", err)
	}
	if err := netlink.AddrAdd(link, ueAddr); err != nil {
		return nil, fmt.Errorf("assign UE address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("set TUN UP: %w", err)
	}

	// Uplink: read from every queue → GTP-U
	go tunToGtp(conn, opts.Lteid, tuns...)

	// Downlink: keep simple first → write only to queue 0
	go gtpToTunSingleQueue(conn, tuns[0])

	return &Tunnel{
		Name:    tuns[0].Name(),
		gtpConn: conn,
		tuns:    tuns,
		lteid:   opts.Lteid,
		rteid:   opts.Rteid,
	}, nil
}

func (t *Tunnel) Close() error {
	var first error
	if err := t.gtpConn.Close(); err != nil && first == nil {
		first = err
	}
	for _, ifce := range t.tuns {
		if err := ifce.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Uplink: from each TUN queue → GTP-U (connected UDP)
func tunToGtp(conn *net.UDPConn, lteid uint32, tuns ...*water.Interface) {
	for _, ifce := range tuns {
		go func(ifce *water.Interface) {
			payload := make([]byte, 2048)
			hdr := [8]byte{0x30, 0xFF, 0, 0, 0, 0, 0, 0} // v1/PT, T-PDU
			buf := make([]byte, 2048+8)
			for {
				n, err := ifce.Read(payload)
				if err != nil {
					log.Printf("tun read: %v", err)
					continue
				}
				binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
				binary.BigEndian.PutUint32(hdr[4:8], lteid)
				copy(buf[:8], hdr[:])
				copy(buf[8:8+n], payload[:n])
				if _, err := conn.Write(buf[:8+n]); err != nil {
					log.Printf("udp write: %v", err)
				}
			}
		}(ifce)
	}
}

// Downlink: GTP-U → a single TUN queue (use Read, not ReadFrom)
func gtpToTunSingleQueue(conn *net.UDPConn, ifce *water.Interface) {
	pkt := make([]byte, 2048)
	for {
		n, err := conn.Read(pkt)
		if err != nil {
			log.Printf("GTP read: %v", err)
			continue
		}
		if n < 8 || (pkt[0]&0x30) != 0x30 || pkt[1] != 0xFF {
			continue // not GTP-U v1 T-PDU
		}

		payloadStart := 8
		// If any of E/S/PN present → +4 bytes (seq(2)+npdu(1)+next_ext(1))
		if (pkt[0] & 0x07) != 0 {
			payloadStart += 4
		}
		// Extension headers if E bit set
		if (pkt[0] & 0x04) != 0 {
			off := payloadStart
			for {
				if off >= n {
					break
				}
				if pkt[off] == 0x00 { // no more extensions
					off++
					payloadStart = off
					break
				}
				if off+1 >= n {
					break
				}
				off += int(pkt[off+1]) * 4 // len field in 4-byte units
			}
		}
		if payloadStart >= n {
			continue
		}
		if _, err := ifce.Write(pkt[payloadStart:n]); err != nil {
			log.Printf("tun write: %v", err)
		}
	}
}
