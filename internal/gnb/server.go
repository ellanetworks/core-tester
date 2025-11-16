package gnb

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ishidawataru/sctp"
	"go.uber.org/zap"
)

const (
	SCTPReadBufferSize = 65535
)

type GnodeB struct {
	Conn           *sctp.SCTPConn
	receivedFrames []SCTPFrame
}

func (g *GnodeB) GetReceivedFrames() []SCTPFrame {
	return g.receivedFrames
}

func (g *GnodeB) FlushReceivedFrames() {
	g.receivedFrames = nil
}

func (g *GnodeB) WaitForNextFrame(timeout time.Duration) (SCTPFrame, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if len(g.receivedFrames) > 0 {
			frame := g.receivedFrames[0]
			g.receivedFrames = g.receivedFrames[1:]

			return frame, nil
		}

		time.Sleep(1 * time.Millisecond)
	}

	return SCTPFrame{}, fmt.Errorf("timeout waiting for next SCTP frame")
}

type SCTPFrame struct {
	Data []byte
	Info *sctp.SndRcvInfo
}

func Start(
	coreN2Address string,
	gnbN2Address string,
) (*GnodeB, error) {
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

	gnodeB := &GnodeB{
		Conn: conn,
	}
	gnodeB.listenAndServe(conn)

	return gnodeB, nil
}

func (g *GnodeB) listenAndServe(conn *sctp.SCTPConn) {
	if conn == nil {
		logger.Logger.Error("SCTP connection is nil")
		return
	}

	go func() {
		buf := make([]byte, SCTPReadBufferSize)

		for {
			n, info, err := conn.SCTPRead(buf)
			if err != nil {
				if err == io.EOF {
					logger.Logger.Debug("SCTP connection closed (EOF)")
				} else {
					logger.Logger.Error("could not read SCTP frame", zap.Error(err))
				}

				return
			}

			if n == 0 {
				logger.Logger.Info("SCTP read returned 0 bytes (connection closed?)")
				return
			}

			cp := append([]byte(nil), buf[:n]...) // copy to isolate from buffer reuse

			g.receivedFrames = append(g.receivedFrames, SCTPFrame{Data: cp, Info: info})

			go func(data []byte) {
				if err := handleFrame(data); err != nil {
					logger.Logger.Error("could not handle SCTP frame", zap.Error(err))
				}
			}(cp)
		}
	}()
}

func (g *GnodeB) Close() {
	if g.Conn != nil {
		err := g.Conn.Close()
		if err != nil {
			fmt.Println("could not close SCTP connection:", err)
		}
	}
}
