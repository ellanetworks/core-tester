package gnb

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb/build"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/ishidawataru/sctp"
)

type NGAPProcedure string

const (
	// Non-UE associated NGAP procedures
	NGAPProcedureNGSetupRequest NGAPProcedure = "NGSetupRequest"

	// UE-associated NGAP procedures
	NGAPProcedureInitialUEMessage            NGAPProcedure = "InitialUEMessage"
	NGAPProcedureUplinkNASTransport          NGAPProcedure = "UplinkNASTransport"
	NGAPProcedureInitialContextSetupResponse NGAPProcedure = "InitialContextSetupResponse"
)

func getSCTPStreamID(msgType NGAPProcedure) (uint16, error) {
	switch msgType {
	// Non-UE procedures
	case NGAPProcedureNGSetupRequest:
		return 0, nil

	// UE-associated procedures
	case NGAPProcedureInitialUEMessage, NGAPProcedureUplinkNASTransport,
		NGAPProcedureInitialContextSetupResponse:
		return 1, nil
	default:
		return 0, fmt.Errorf("NGAP message type (%s) not supported", msgType)
	}
}

func (g *GnodeB) SendNGSetupRequest(opts *build.NGSetupRequestOpts) error {
	pdu, err := build.NGSetupRequest(opts)
	if err != nil {
		return fmt.Errorf("couldn't build NGSetupRequest: %s", err.Error())
	}

	return g.SendMessage(pdu, NGAPProcedureNGSetupRequest)
}

func (g *GnodeB) SendInitialUEMessage(opts *build.InitialUEMessageOpts) error {
	pdu, err := build.InitialUEMessage(opts)
	if err != nil {
		return fmt.Errorf("couldn't build InitialUEMessage: %s", err.Error())
	}

	return g.SendMessage(pdu, NGAPProcedureInitialUEMessage)
}

func (g *GnodeB) SendUplinkNASTransport(opts *build.UplinkNasTransportOpts) error {
	pdu, err := build.UplinkNasTransport(opts)
	if err != nil {
		return fmt.Errorf("couldn't build UplinkNasTransport: %s", err.Error())
	}

	return g.SendMessage(pdu, NGAPProcedureUplinkNASTransport)
}

func (g *GnodeB) SendInitialContextSetupResponse(opts *build.InitialContextSetupResponseOpts) error {
	pdu, err := build.InitialContextSetupResponse(opts)
	if err != nil {
		return fmt.Errorf("couldn't build InitialContextSetupResponse: %s", err.Error())
	}

	return g.SendMessage(pdu, NGAPProcedureInitialContextSetupResponse)
}

func (g *GnodeB) SendMessage(pdu ngapType.NGAPPDU, procedure NGAPProcedure) error {
	bytes, err := ngap.Encoder(pdu)
	if err != nil {
		return fmt.Errorf("couldn't encode message for procedure %s: %s", procedure, err.Error())
	}

	err = g.SendToRan(bytes, procedure)
	if err != nil {
		return fmt.Errorf("couldn't send packet to ran: %s", err.Error())
	}

	return nil
}

func (g *GnodeB) SendToRan(packet []byte, msgType NGAPProcedure) error {
	if g.Conn == nil {
		return fmt.Errorf("ran conn is nil")
	}

	if g.Conn.RemoteAddr() == nil {
		return fmt.Errorf("ran address is nil")
	}

	sid, err := getSCTPStreamID(msgType)
	if err != nil {
		return fmt.Errorf("could not determine SCTP stream ID from NGAP message type (%s): %s", msgType, err.Error())
	}

	defer func() {
		err := recover()
		if err != nil {
			fmt.Printf("panic recovered: %s\n", err)
		}
	}()

	if len(packet) == 0 {
		return fmt.Errorf("packet len is 0")
	}

	info := sctp.SndRcvInfo{
		Stream: sid,
		PPID:   ngap.PPID,
	}
	if _, err := g.Conn.SCTPWrite(packet, &info); err != nil {
		return fmt.Errorf("send write to sctp connection: %s", err.Error())
	}

	return nil
}
