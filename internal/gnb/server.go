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
	GnbID          string
	MCC            string
	MNC            string
	SST            int32
	SD             string
	TAC            string
	DNN            string
	Name           string
	UEPool         map[int64]engine.DownlinkSender // RANUENGAPID -> UE
	NGAPIDs        map[int64]int64                 // RANUENGAPID -> AMFUENGAPID
	Conn           *sctp.SCTPConn
	receivedFrames map[int]map[int][]SCTPFrame // pduType -> msgType -> frames
	mu             sync.Mutex
	N3Address      netip.Addr
	PDUSessionID   int64
	PDUSessions    map[int64]*PDUSessionInformation // RANUENGAPID -> PDUSessionInformation
	DownlinkTEID   uint32
}

func (g *GnodeB) StorePDUSession(ranUeId int64, pduSessionInfo *PDUSessionInformation) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.PDUSessions == nil {
		g.PDUSessions = make(map[int64]*PDUSessionInformation)
	}

	g.PDUSessions[ranUeId] = pduSessionInfo
}

func (g *GnodeB) GetPDUSession(ranUeId int64) *PDUSessionInformation {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.PDUSessions[ranUeId]
}

func (g *GnodeB) GetAMFUENGAPID(ranUeId int64) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.NGAPIDs[ranUeId]
}

func (g *GnodeB) UpdateNGAPIDs(ranUeId int64, amfUeId int64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.NGAPIDs == nil {
		g.NGAPIDs = make(map[int64]int64)
	}

	g.NGAPIDs[ranUeId] = amfUeId
}

func (g *GnodeB) LoadUE(ranUeId int64) (engine.DownlinkSender, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	ue, ok := g.UEPool[ranUeId]
	if !ok {
		return nil, fmt.Errorf("UE is not found in GNB UE POOL with RAN UE ID %d", ranUeId)
	}

	return ue, nil
}

func (g *GnodeB) WaitForMessage(pduType int, msgType int, timeout time.Duration) (SCTPFrame, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		g.mu.Lock()

		msgTypeMap, ok := g.receivedFrames[pduType]
		if !ok {
			g.mu.Unlock()
			time.Sleep(1 * time.Millisecond)

			continue
		}

		frames, ok := msgTypeMap[msgType]
		if !ok {
			g.mu.Unlock()
			time.Sleep(1 * time.Millisecond)

			continue
		}

		frame := frames[0]

		if len(frames) == 1 {
			delete(msgTypeMap, msgType)
		} else {
			msgTypeMap[msgType] = frames[1:]
		}

		g.receivedFrames[pduType] = msgTypeMap

		g.mu.Unlock()

		return frame, nil
	}

	return SCTPFrame{}, fmt.Errorf("timeout waiting for NGAP message %v", getMessageName(pduType, msgType))
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
	SD string,
	DNN string,
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
		GnbID:        GnbID,
		MCC:          MCC,
		MNC:          MNC,
		SST:          SST,
		SD:           SD,
		DNN:          DNN,
		TAC:          TAC,
		Name:         Name,
		Conn:         conn,
		N3Address:    gnbN3IPAddress,
		PDUSessionID: 1,
		DownlinkTEID: downlinkTEID,
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

	logger.GnbLogger.Debug(
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
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.UEPool == nil {
		g.UEPool = make(map[int64]engine.DownlinkSender)
	}

	g.UEPool[ranUENGAPID] = ue
}

func (g *GnodeB) listenAndServe(conn *sctp.SCTPConn) {
	if conn == nil {
		logger.GnbLogger.Error("SCTP connection is nil")
		return
	}

	go func() {
		buf := make([]byte, SCTPReadBufferSize)

		for {
			n, info, err := conn.SCTPRead(buf)
			if err != nil {
				if err == io.EOF {
					logger.GnbLogger.Debug("SCTP connection closed (EOF)")
				} else {
					logger.GnbLogger.Error("could not read SCTP frame", zap.Error(err))
				}

				return
			}

			if n == 0 {
				logger.GnbLogger.Info("SCTP read returned 0 bytes (connection closed?)")
				return
			}

			cp := append([]byte(nil), buf[:n]...) // copy to isolate from buffer reuse

			sctpFrame := SCTPFrame{
				Data: cp,
				Info: info,
			}

			go func(sctpFrame SCTPFrame) {
				if err := HandleFrame(g, sctpFrame); err != nil {
					logger.GnbLogger.Error("could not handle SCTP frame", zap.Error(err))
				}
			}(sctpFrame)
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

	logger.GnbLogger.Debug(
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

	logger.GnbLogger.Debug(
		"Sent Initial UE Message",
		zap.String("GNB ID", g.GnbID),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
		zap.String("MCC", g.MCC),
		zap.String("MNC", g.MNC),
		zap.String("TAC", g.TAC),
	)

	return nil
}
