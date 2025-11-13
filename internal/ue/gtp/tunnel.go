// Copyright 2025 Ghislain Bourgeois
// SPDX-License-Identifier: GPL-3.0-or-later

package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
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

	go tunToGtp(conn, ifce, opts.Lteid)
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

func tunToGtp(conn *net.UDPConn, ifce *water.Interface, lteid uint32) {
	packet := make([]byte, 2000)
	packet[0] = 0x30                               // Version 1, Protocol type GTP
	packet[1] = 0xFF                               // Message type T-PDU
	binary.BigEndian.PutUint16(packet[2:4], 0)     // Length
	binary.BigEndian.PutUint32(packet[4:8], lteid) // TEID

	for {
		n, err := ifce.Read(packet[8:])
		if err != nil {
			if isClosedErr(err) {
				// normal shutdown — exit goroutine
				return
			}

			logger.Logger.Error("error reading from tun interface", zap.Error(err))

			continue
		}

		if n == 0 {
			logger.Logger.Info("read 0 bytes")
			continue
		}

		binary.BigEndian.PutUint16(packet[2:4], uint16(n))

		_, err = conn.Write(packet[:n+8])
		if err != nil {
			logger.Logger.Error("error writing to GTP", zap.Error(err))
			continue
		}

		logger.Logger.Debug("Sent packet to GTP", zap.Int("length", n))
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
			if isClosedErr(err) {
				// normal shutdown — exit goroutine
				return
			}

			logger.Logger.Error("error reading from tun interface", zap.Error(err))

			continue
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
			logger.Logger.Error("error writing to tun interface", zap.Error(err))
			continue
		}

		logger.Logger.Debug("Sent packet to TUN", zap.Int("length", n-payloadStart))
	}
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}

	s := err.Error()

	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "file already closed")
}
