package gnb

import (
	"context"
	"fmt"
	"net"

	"github.com/ishidawataru/sctp"
)

const (
	SCTPReadBufferSize = 65535
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
		return nil, fmt.Errorf("could not resolve Ella Core SCTP address: %w", err)
	}

	localAddr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{
			{IP: net.ParseIP(gnbN2Address)},
		},
	}

	conn, err := sctp.DialSCTPExt(
		"sctp",
		localAddr,
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

func (g *GnodeB) ReceiveFrame(ctx context.Context) (SCTPFrame, error) {
	if g.Conn == nil {
		return SCTPFrame{}, fmt.Errorf("SCTP connection is nil")
	}

	type res struct {
		data []byte
		info *sctp.SndRcvInfo
		err  error
	}

	ch := make(chan res, 1)

	go func() {
		buf := make([]byte, SCTPReadBufferSize)

		n, info, err := g.Conn.SCTPRead(buf)
		if err != nil {
			ch <- res{err: fmt.Errorf("could not read SCTP frame: %w", err)}
			return
		}

		if n == 0 {
			ch <- res{err: fmt.Errorf("empty SCTP read")}
			return
		}

		cp := append([]byte(nil), buf[:n]...) // copy to isolate from buffer reuse
		ch <- res{data: cp, info: info, err: nil}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return SCTPFrame{}, r.err
		}

		return SCTPFrame{Data: r.data, Info: r.info}, nil
	case <-ctx.Done():
		return SCTPFrame{}, ctx.Err()
	}
}

func (g *GnodeB) Close() {
	if g.Conn != nil {
		err := g.Conn.Close()
		if err != nil {
			fmt.Println("could not close SCTP connection:", err)
		}
	}
}
