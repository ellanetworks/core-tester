/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package ngap

import (
	"my5G-RANTester/internal/control_test_engine/gnb/context"
	"net/netip"

	"github.com/ellanetworks/core-tester/internal/control_test_engine/gnb/context"
	"github.com/ishidawataru/sctp"
	log "github.com/sirupsen/logrus"
)

var ConnCount int

func InitConn(amf *context.GNBAmf, gnb *context.GNBContext) error {
	// check AMF IP and AMF port.
	remote := amf.GetAmfIpPort().String()
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

	// streams := amf.GetTNLAStreams()

	conn, err := sctp.DialSCTPExt(
		"sctp",
		loc,
		rem,
		sctp.InitMsg{NumOstreams: 2, MaxInstreams: 2})
	if err != nil {
		amf.SetSCTPConn(nil)
		return err
	}

	// set streams and other information about TNLA

	// successful established SCTP (TNLA - N2)
	amf.SetSCTPConn(conn)
	gnb.SetN2(conn)

	err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	if err != nil {
		log.Error("[GNB][SCTP] Error in subscribing SCTP events")
	}

	go GnbListen(amf, gnb)

	return nil
}

func GnbListen(amf *context.GNBAmf, gnb *context.GNBContext) {
	buf := make([]byte, 65535)
	conn := amf.GetSCTPConn()

	for {

		n, info, err := conn.SCTPRead(buf[:])
		if err != nil {
			break
		}

		log.Info("[GNB][SCTP] Receive message in ", info.Stream, " stream\n")

		forwardData := make([]byte, n)
		copy(forwardData, buf[:n])

		// handling NGAP message.
		go Dispatch(amf, gnb, forwardData)
	}

}
