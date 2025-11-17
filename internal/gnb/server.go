package gnb

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/aper"
	"github.com/free5gc/nas/nasType"
	"github.com/ishidawataru/sctp"
	"go.uber.org/zap"
)

const (
	SCTPReadBufferSize = 65535
)

type GnodeB struct {
	GnbID           string
	MCC             string
	MNC             string
	SST             int32
	TAC             string
	Name            string
	NGSetupComplete bool
	UEPool          sync.Map // map[int64]engine.DownlinkSender, UeRanNgapId as key
	Conn            *sctp.SCTPConn
	receivedFrames  []SCTPFrame
	N3Address       netip.Addr
	PDUSessionID    int64
	DownlinkTEID    uint32
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

// WaitForNGSetupComplete waits until the NG Setup procedure is complete or the timeout is reached.
// Flushes received frames upon successful completion.
func (g *GnodeB) WaitForNGSetupComplete(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if g.NGSetupComplete {
			g.receivedFrames = nil
			return nil
		}

		time.Sleep(1 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for NGSetupComplete")
}

type SCTPFrame struct {
	Data []byte
	Info *sctp.SndRcvInfo
}

func Start(
	GnbID string,
	MCC string,
	MNC string,
	SST int32,
	TAC string,
	Name string,
	coreN2Address string,
	gnbN2Address string,
	gnbN3Address string,
	downlinkTEID uint32,
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

	gnbN3IPAddress, err := netip.ParseAddr(gnbN3Address)
	if err != nil {
		return nil, fmt.Errorf("could not parse gNB N3 address: %v", err)
	}

	gnodeB := &GnodeB{
		GnbID:           GnbID,
		MCC:             MCC,
		MNC:             MNC,
		SST:             SST,
		TAC:             TAC,
		Name:            Name,
		Conn:            conn,
		NGSetupComplete: false,
		N3Address:       gnbN3IPAddress,
		PDUSessionID:    1,
		DownlinkTEID:    downlinkTEID,
	}

	gnodeB.listenAndServe(conn)

	opts := &NGSetupRequestOpts{
		GnbID: gnodeB.GnbID,
		Mcc:   gnodeB.MCC,
		Mnc:   gnodeB.MNC,
		Sst:   gnodeB.SST,
		Tac:   gnodeB.TAC,
		Name:  gnodeB.Name,
	}

	err = gnodeB.SendNGSetupRequest(opts)
	if err != nil {
		return nil, fmt.Errorf("could not send NGSetupRequest: %v", err)
	}

	logger.Logger.Debug(
		"Sent NGSetupRequest",
		zap.String("MCC", opts.Mcc),
		zap.String("MNC", opts.Mnc),
		zap.Int32("SST", opts.Sst),
		zap.String("TAC", opts.Tac),
		zap.String("Name", opts.Name),
	)

	return gnodeB, nil
}

func (g *GnodeB) AddUE(ranUENGAPID int64, ue engine.DownlinkSender) {
	g.UEPool.Store(ranUENGAPID, ue)
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
				if err := HandleFrame(g, data); err != nil {
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

func (g *GnodeB) SendUplinkNAS(nasPDU []byte, amfUENGAPID int64, ranUENGAPID int64) error {
	err := g.SendUplinkNASTransport(&UplinkNasTransportOpts{
		AMFUeNgapID: amfUENGAPID,
		RANUeNgapID: ranUENGAPID,
		Mcc:         g.MCC,
		Mnc:         g.MNC,
		GnbID:       g.GnbID,
		Tac:         g.TAC,
		NasPDU:      nasPDU,
	})
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.Logger.Debug(
		"Sent Uplink NAS Transport",
		zap.Int64("AMF UE NGAP ID", amfUENGAPID),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
		zap.String("GNB ID", g.GnbID),
	)

	return nil
}

func (g *GnodeB) SendInitialUEMessage(nasPDU []byte, ranUENGAPID int64, guti5G *nasType.GUTI5G, cause aper.Enumerated) error {
	opts := &InitialUEMessageOpts{
		Mcc:                   g.MCC,
		Mnc:                   g.MNC,
		GnbID:                 g.GnbID,
		Tac:                   g.TAC,
		RanUENGAPID:           ranUENGAPID,
		NasPDU:                nasPDU,
		Guti5g:                guti5G,
		RRCEstablishmentCause: cause,
	}

	pdu, err := BuildInitialUEMessage(opts)
	if err != nil {
		return fmt.Errorf("couldn't build InitialUEMessage: %s", err.Error())
	}

	err = g.SendMessage(pdu, NGAPProcedureInitialUEMessage)
	if err != nil {
		return fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	logger.Logger.Debug(
		"Sent Initial UE Message",
		zap.String("GNB ID", g.GnbID),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
		zap.String("MCC", g.MCC),
		zap.String("MNC", g.MNC),
		zap.String("TAC", g.TAC),
	)

	return nil
}
