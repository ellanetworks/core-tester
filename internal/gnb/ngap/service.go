/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package ngap

import (
	"net/netip"

	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ishidawataru/sctp"
	log "github.com/sirupsen/logrus"
)

var ConnCount int

func InitConn(ella *context.GNBElla, gnb *context.GNBContext) error {
	remote := ella.GetEllaIpPort().String()
	gnbAddrPort := gnb.GetGnbIpPort()
	local := netip.AddrPortFrom(gnbAddrPort.Addr(), gnbAddrPort.Port()+uint16(ConnCount)).String()
	ConnCount++

	rem, err := sctp.ResolveSCTPAddr("sctp", remote)
	if err != nil {
		return err
	}
	loc, err := sctp.ResolveSCTPAddr("sctp", local)
	if err != nil {
		return err
	}

	conn, err := sctp.DialSCTPExt(
		"sctp",
		loc,
		rem,
		sctp.InitMsg{NumOstreams: 2, MaxInstreams: 2})
	if err != nil {
		ella.SetSCTPConn(nil)
		return err
	}

	ella.SetSCTPConn(conn)
	gnb.SetN2(conn)

	err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	if err != nil {
		log.Errorf("[GNB][SCTP] Error in subscribing SCTP events for %v AMF\n", ella.GetEllaId())
	}

	go GnbListen(ella, gnb)

	return nil
}

func GnbListen(ella *context.GNBElla, gnb *context.GNBContext) {
	buf := make([]byte, 65535)
	conn := ella.GetSCTPConn()

	for {
		n, info, err := conn.SCTPRead(buf[:])
		if err != nil {
			break
		}

		log.Info("[GNB][SCTP] Receive message in ", info.Stream, " stream\n")

		forwardData := make([]byte, n)
		copy(forwardData, buf[:n])

		// handling NGAP message.
		go Dispatch(ella, gnb, forwardData)
	}
}
