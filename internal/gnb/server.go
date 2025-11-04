package gnb

import (
	"fmt"
	"time"

	"github.com/ishidawataru/sctp"
)

type GnodeB struct {
	Conn *sctp.SCTPConn
}

type SCTPFrame struct {
	Data []byte
	Info *sctp.SndRcvInfo
}

func Start(coreN2Address string, gnbN2Address string) (*GnodeB, error) {
	rem, err := sctp.ResolveSCTPAddr("sctp", coreN2Address)
	if err != nil {
		return nil, err
	}

	loc, err := sctp.ResolveSCTPAddr("sctp", gnbN2Address)
	if err != nil {
		return nil, err
	}

	conn, err := sctp.DialSCTPExt(
		"sctp",
		loc,
		rem,
		sctp.InitMsg{NumOstreams: 2, MaxInstreams: 2})
	if err != nil {
		return nil, fmt.Errorf("could not dial SCTP: %w", err)
	}

	err = conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	if err != nil {
		return nil, fmt.Errorf("could not subscribe SCTP events: %w", err)
	}

	return &GnodeB{Conn: conn}, nil
}

func (g *GnodeB) ReceiveFrame(timeout time.Duration) (SCTPFrame, error) {
	if g.Conn == nil {
		return SCTPFrame{}, fmt.Errorf("SCTP connection is nil")
	}

	buf := make([]byte, 65535)

	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			return SCTPFrame{}, fmt.Errorf("timeout after %s", timeout)
		}

		n, info, err := g.Conn.SCTPRead(buf)
		if err != nil {
			return SCTPFrame{}, fmt.Errorf("could not read SCTP frame: %w", err)
		}

		if n == 0 {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		return SCTPFrame{Data: data, Info: info}, nil
	}
}

func (g *GnodeB) Close() error {
	if g.Conn != nil {
		err := g.Conn.Close()
		if err != nil {
			return fmt.Errorf("could not close SCTP connection: %w", err)
		}
	}

	return nil
}
