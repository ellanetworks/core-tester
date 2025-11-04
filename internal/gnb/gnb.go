package gnb

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/ishidawataru/sctp"
)

func Start(coreN2Address string, gnbN2Address string) error {
	rem, err := sctp.ResolveSCTPAddr("sctp", coreN2Address)
	if err != nil {
		return err
	}

	loc, err := sctp.ResolveSCTPAddr("sctp", gnbN2Address)
	if err != nil {
		return err
	}

	conn, err := sctp.DialSCTPExt(
		"sctp",
		loc,
		rem,
		sctp.InitMsg{NumOstreams: 2, MaxInstreams: 2})
	if err != nil {
		return fmt.Errorf("could not dial SCTP: %w", err)
	}

	err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	if err != nil {
		return fmt.Errorf("could not subscribe SCTP events: %w", err)
	}

	go Listen(conn)

	return nil
}

func Listen(conn *sctp.SCTPConn) {
	buf := make([]byte, 65535)

	for {
		n, info, err := conn.SCTPRead(buf[:])
		if err != nil {
			break
		}

		logger.GnbLog.Info("receive message in ", info.Stream, " stream\n")

		forwardData := make([]byte, n)

		copy(forwardData, buf[:n])

		go Dispatch(forwardData)
	}
}

func Dispatch(message []byte) {
	if message == nil {
		logger.GnbLog.Info("NGAP message is nil")
	}

	ngapMsg, err := ngap.Decoder(message)
	if err != nil {
		logger.GnbLog.Error("Error decoding NGAP message:", err)
	}

	switch ngapMsg.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		switch ngapMsg.InitiatingMessage.ProcedureCode.Value {
		default:
			logger.GnbLog.Warnf("Received unhandled initiating NGAP message 0x%x", ngapMsg.InitiatingMessage.ProcedureCode.Value)
		}
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		switch ngapMsg.SuccessfulOutcome.ProcedureCode.Value {
		default:
			logger.GnbLog.Warnf("Received unhandled successful NGAP message 0x%x", ngapMsg.SuccessfulOutcome.ProcedureCode.Value)
		}

	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		switch ngapMsg.UnsuccessfulOutcome.ProcedureCode.Value {
		default:
			logger.GnbLog.Warnf("Received unhandled unsuccessful NGAP message 0x%x", ngapMsg.UnsuccessfulOutcome.ProcedureCode.Value)
		}
	}
}
