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
		PlatformSpecificParams: water.PlatformSpecificParams{
			MultiQueue: true, // IMPORTANT: multiqueue must be here
		},
	}
	cfg.Name = opts.TunInterfaceName

	// Open N TUN file descriptors (same name), used only for RX fan-out
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

	// TX path: keep single-queue behavior (use the first fd only)
	go tunToGtp(conn, tuns[0], opts.Lteid)

	// RX path: single UDP reader → fan out across multiple TUN queues
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
	hdr := [8]byte{0x30, 0xFF, 0, 0, 0, 0, 0, 0} // GTPv1, T-PDU
	for {
		n, err := ifce.Read(buf)
		if err != nil {
			log.Printf("tun read: %v", err)
			continue
		}
		if n == 0 {
			continue
		}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n)) // payload length
		binary.BigEndian.PutUint32(hdr[4:8], lteid)     // TEID
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
		// GTPv1, T-PDU
		if (buf[0]&0x30) != 0x30 || buf[1] != 0xFF {
			continue
		}

		payloadStart := 8

		// Optional 4-byte field when any of E/S/PN set
		flags := buf[0]
		if (flags & 0x07) != 0 { // E(0x04) S(0x02) PN(0x01)
			if n < payloadStart+4 {
				continue
			}
			// Next Extension Header Type is the last byte of this 4-byte block
			next := buf[payloadStart+3]
			payloadStart += 4

			// If E was set, walk extension headers
			if (flags & 0x04) != 0 {
				for next != 0x00 {
					// Each ext: Type(1) Length(1) Content(Length*4 bytes) …last byte is NextExtType
					if n < payloadStart+2 {
						next = 0x00
						break
					}
					extLenUnits := int(buf[payloadStart+1]) // in 4-byte units
					block := 2 + extLenUnits*4
					end := payloadStart + block
					if end > n {
						next = 0x00
						break
					}
					// NextExtType is the last byte of the ext block
					next = buf[end-1]
					payloadStart = end
				}
			}
		}

		if payloadStart >= n {
			continue
		}

		ifce := queues[rr%len(queues)]
		rr++
		if _, err := ifce.Write(buf[payloadStart:n]); err != nil {
			log.Printf("tun write: %v", err)
		}
	}
}
