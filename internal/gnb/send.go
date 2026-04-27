package gnb

import (
	"fmt"

	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/ishidawataru/sctp"
)

type NGAPProcedure string

const (
	// Non-UE associated NGAP procedures
	NGAPProcedureNGSetupRequest NGAPProcedure = "NGSetupRequest"

	// UE-associated NGAP procedures
	NGAPProcedureInitialUEMessage                NGAPProcedure = "InitialUEMessage"
	NGAPProcedureUplinkNASTransport              NGAPProcedure = "UplinkNASTransport"
	NGAPProcedureInitialContextSetupResponse     NGAPProcedure = "InitialContextSetupResponse"
	NGAPProcedurePDUSessionResourceSetupResponse NGAPProcedure = "PDUSessionResourceSetupResponse"
	NGAPProcedureUEContextReleaseComplete        NGAPProcedure = "UEContextReleaseComplete"
)

func getSCTPStreamID(msgType NGAPProcedure) (uint16, error) {
	switch msgType {
	// Non-UE procedures
	case NGAPProcedureNGSetupRequest:
		return 0, nil

	// UE-associated procedures
	case NGAPProcedureInitialUEMessage, NGAPProcedureUplinkNASTransport,
		NGAPProcedureInitialContextSetupResponse, NGAPProcedurePDUSessionResourceSetupResponse,
		NGAPProcedureUEContextReleaseComplete:
		return 1, nil
	default:
		return 0, fmt.Errorf("NGAP message type (%s) not supported", msgType)
	}
}

func (g *GnodeB) SendNGSetupRequest(opts *NGSetupRequestOpts) error {
	pdu, err := BuildNGSetupRequest(opts)
	if err != nil {
		return fmt.Errorf("couldn't build NGSetupRequest: %w", err)
	}

	return g.SendMessage(pdu, NGAPProcedureNGSetupRequest)
}

func (g *GnodeB) SendUplinkNASTransport(opts *UplinkNasTransportOpts) error {
	pdu, err := BuildUplinkNasTransport(opts)
	if err != nil {
		return fmt.Errorf("couldn't build UplinkNasTransport: %w", err)
	}

	return g.SendMessage(pdu, NGAPProcedureUplinkNASTransport)
}

func (g *GnodeB) SendInitialContextSetupResponse(opts *InitialContextSetupResponseOpts) error {
	pdu, err := BuildInitialContextSetupResponse(opts)
	if err != nil {
		return fmt.Errorf("couldn't build InitialContextSetupResponse: %w", err)
	}

	return g.SendMessage(pdu, NGAPProcedureInitialContextSetupResponse)
}

func (g *GnodeB) SendPDUSessionResourceSetupResponse(opts *PDUSessionResourceSetupResponseOpts) error {
	pdu, err := BuildPDUSessionResourceSetupResponse(opts)
	if err != nil {
		return fmt.Errorf("couldn't build PDUSessionResourceSetupResponse: %w", err)
	}

	return g.SendMessage(pdu, NGAPProcedurePDUSessionResourceSetupResponse)
}

func (g *GnodeB) SendUEContextReleaseComplete(opts *UEContextReleaseCompleteOpts) error {
	pdu, err := BuildUEContextReleaseComplete(opts)
	if err != nil {
		return fmt.Errorf("couldn't build UEContextReleaseComplete: %w", err)
	}

	err = g.SendMessage(pdu, NGAPProcedureUEContextReleaseComplete)
	if err != nil {
		return fmt.Errorf("couldn't send UEContextReleaseComplete: %w", err)
	}

	return nil
}

func (g *GnodeB) SendMessage(pdu ngapType.NGAPPDU, procedure NGAPProcedure) error {
	bytes, err := ngap.Encoder(pdu)
	if err != nil {
		return fmt.Errorf("couldn't encode message for procedure %s: %w", procedure, err)
	}

	err = g.SendToRan(bytes, procedure)
	if err != nil {
		return fmt.Errorf("couldn't send packet to ran: %w", err)
	}

	return nil
}

func (g *GnodeB) SendToRan(packet []byte, msgType NGAPProcedure) error {
	if g.N2Conn == nil {
		return fmt.Errorf("ran conn is nil")
	}

	if g.N2Conn.RemoteAddr() == nil {
		return fmt.Errorf("ran address is nil")
	}

	sid, err := getSCTPStreamID(msgType)
	if err != nil {
		return fmt.Errorf("could not determine SCTP stream ID from NGAP message type (%s): %w", msgType, err)
	}

	if len(packet) == 0 {
		return fmt.Errorf("packet len is 0")
	}

	info := sctp.SndRcvInfo{
		Stream: sid,
		PPID:   ngap.PPID,
	}
	if _, err := g.N2Conn.SCTPWrite(packet, &info); err != nil {
		return fmt.Errorf("send write to sctp connection: %w", err)
	}

	return nil
}
