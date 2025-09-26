package gtp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"runtime"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

type Tunnel struct {
	Name    string
	gtpConn *net.UDPConn
	tuns    []*water.Interface
	lteid   uint32
	rteid   uint32
}

type TunnelOptions struct {
	UEIP             string
	GnbIP            string
	UpfIP            string
	GTPUPort         int
	TunInterfaceName string
	Lteid            uint32
	Rteid            uint32
}

func NewTunnel(opts *TunnelOptions) (*Tunnel, error) {
	laddr := &net.UDPAddr{IP: net.ParseIP(opts.GnbIP), Port: opts.GTPUPort}
	raddr := &net.UDPAddr{IP: net.ParseIP(opts.UpfIP), Port: opts.GTPUPort}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to UPF: %v", err)
	}

	config := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			MultiQueue: true,
		},
	}
	config.Name = opts.TunInterfaceName

	// Open N queues
	nq := runtime.NumCPU() / 2
	if nq < 2 {
		nq = 2
	}
	tuns := make([]*water.Interface, 0, nq)
	for i := 0; i < nq; i++ {
		ifce, err := water.New(config)
		if err != nil {
			return nil, fmt.Errorf("open TUN (mq): %w", err)
		}
		tuns = append(tuns, ifce)
	}

	// Configure IP once on the device
	link, err := netlink.LinkByName(tuns[0].Name())
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %w", err)
	}
	ueAddr, err := netlink.ParseAddr(opts.UEIP)
	if err != nil {
		return nil, fmt.Errorf("could not parse UE address: %w", err)
	}
	if err := netlink.AddrAdd(link, ueAddr); err != nil {
		return nil, fmt.Errorf("addr add: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("link up: %w", err)
	}

	// Start workers for each queue
	for _, ifce := range tuns {
		go tunToGtp(conn, ifce, opts.Lteid)
		go gtpToTun(conn, ifce)
	}

	return &Tunnel{
		Name:    tuns[0].Name(),
		gtpConn: conn,
		tuns:    tuns,
		lteid:   opts.Lteid,
		rteid:   opts.Rteid,
	}, nil
}

func (t *Tunnel) Close() error {
	var firstErr error
	if err := t.gtpConn.Close(); err != nil {
		firstErr = err
	}
	for _, ifce := range t.tuns {
		if err := ifce.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func tunToGtp(conn *net.UDPConn, ifce *water.Interface, lteid uint32) {
	buf := make([]byte, 2000)
	hdr := [8]byte{0x30, 0xFF, 0, 0, 0, 0, 0, 0}
	for {
		n, err := ifce.Read(buf)
		if err != nil {
			log.Printf("tun read: %v", err)
			continue
		}
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		binary.BigEndian.PutUint32(hdr[4:8], lteid)
		pkt := append(hdr[:], buf[:n]...)
		if _, err := conn.Write(pkt); err != nil {
			log.Printf("udp write: %v", err)
		}
	}
}

func gtpToTun(conn *net.UDPConn, ifce *water.Interface) {
	pkt := make([]byte, 2000)
	for {
		n, err := conn.Read(pkt)
		if err != nil {
			log.Printf("udp read: %v", err)
			continue
		}
		if n < 8 || (pkt[0]&0x30) != 0x30 || pkt[1] != 0xFF {
			continue
		}
		payloadStart := 8
		if _, err := ifce.Write(pkt[payloadStart:n]); err != nil {
			log.Printf("tun write: %v", err)
		}
	}
}
