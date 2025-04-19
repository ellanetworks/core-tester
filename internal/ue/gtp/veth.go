package gtp

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

type VethPairOptions struct {
	Interface0Name  string
	Interface1Name  string
	N3InterfaceName string
	UEIP            string
	GnbIP           string
	UpfIP           string
	GTPUPort        int
	Rteid           uint32
}

type VethPair struct {
	Veth0Link netlink.Link
	Veth1Link netlink.Link
}

func NewVethPair(opts *VethPairOptions) (*VethPair, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:  opts.Interface0Name,
			MTU:   1500,
			Flags: net.FlagUp,
		},
		PeerName: opts.Interface1Name,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("could not create veth pair: %v", err)
	}

	link0, err := netlink.LinkByName(opts.Interface0Name)
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %v", err)
	}

	if err := netlink.LinkSetUp(link0); err != nil {
		return nil, fmt.Errorf("could not set TUN interface up: %v", err)
	}

	link1, err := netlink.LinkByName(opts.Interface1Name)
	if err != nil {
		return nil, fmt.Errorf("cannot read TUN interface: %v", err)
	}

	if err := netlink.LinkSetUp(link1); err != nil {
		return nil, fmt.Errorf("could not set TUN interface up: %v", err)
	}

	addr, err := netlink.ParseAddr(opts.UEIP)
	if err != nil {
		return nil, fmt.Errorf("could not parse UE address: %v", err)
	}

	err = netlink.AddrAdd(link0, addr)
	if err != nil {
		return nil, fmt.Errorf("could not assign UE address to TUN interface: %v", err)
	}

	err = addRoute(opts.UpfIP, opts.N3InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("could not add route to UPF: %v", err)
	}

	// go tunToGtp(conn, ifce, opts.Lteid)
	// go gtpToTun(conn, ifce)

	return &VethPair{
		Veth0Link: link0,
		Veth1Link: link1,
	}, nil
}

func (v *VethPair) Close() error {
	if err := netlink.LinkDel(v.Veth0Link); err != nil {
		return fmt.Errorf("could not delete veth pair link 0: %v", err)
	}
	if err := netlink.LinkDel(v.Veth1Link); err != nil {
		return fmt.Errorf("could not delete veth pair link 1: %v", err)
	}
	return nil
}

func addRoute(upfIP string, ifaceName string) error {
	// 1) Parse the destination IP
	dst := net.ParseIP(upfIP)
	if dst == nil {
		return fmt.Errorf("invalid UPF IP: %s", upfIP)
	}
	// We want a /32 route to that single host:
	dstNet := &net.IPNet{IP: dst, Mask: net.CIDRMask(32, 32)}

	// 2) Find the link by name
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("LinkByName(%s): %w", ifaceName, err)
	}

	// 3) Construct the route
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dstNet,
		// No explicit Gateway means “send directly to dst via this interface”
	}

	// 4) Add (or replace) it
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("RouteReplace %v: %w", route, err)
	}
	return nil
}

// func (t *Tunnel) Close() error {
// 	var err error
// 	errG := t.gtpConn.Close()
// 	if errG != nil {
// 		err = fmt.Errorf("could not close GTP connection: %v", errG)
// 	}
// 	errT := t.tunIF.Close()
// 	if errT != nil {
// 		err = fmt.Errorf("%v; could not close TUN interface: %v", err, errT)
// 	}
// 	return err
// }

// func tunToGtp(conn *net.UDPConn, ifce *water.Interface, lteid uint32) {
// 	packet := make([]byte, 2000)
// 	packet[0] = 0x30                               // Version 1, Protocol type GTP
// 	packet[1] = 0xFF                               // Message type T-PDU
// 	binary.BigEndian.PutUint16(packet[2:4], 0)     // Length
// 	binary.BigEndian.PutUint32(packet[4:8], lteid) // TEID
// 	for {
// 		n, err := ifce.Read(packet[8:])
// 		if err != nil {
// 			log.Printf("error reading from tun interface: %v", err)
// 			continue
// 		}
// 		if n == 0 {
// 			log.Println("read 0 bytes")
// 			continue
// 		}
// 		binary.BigEndian.PutUint16(packet[2:4], uint16(n))
// 		_, err = conn.Write(packet[:n+8])
// 		if err != nil {
// 			log.Printf("error writing to GTP: %v", err)
// 			continue
// 		}
// 	}
// }

// func gtpToTun(conn *net.UDPConn, ifce *water.Interface) {
// 	var payloadStart int
// 	packet := make([]byte, 2000)
// 	for {
// 		// Read a packet from UDP
// 		// Currently ignores the address
// 		n, _, err := conn.ReadFrom(packet)
// 		if err != nil {
// 			log.Printf("error reading from GTP: %v", err)
// 		}
// 		// Ignore packets that are not a GTP-U v1 T-PDU packet
// 		if packet[0]&0x30 != 0x30 || packet[1] != 0xFF {
// 			continue
// 		}
// 		// Write the packet to the TUN interface
// 		// ignoring the GTP header
// 		payloadStart = 8
// 		if packet[0]&0x07 > 0 {
// 			payloadStart = payloadStart + 3
// 		}
// 		if packet[0]&0x04 > 0 {
// 			// Next Header extension present
// 			for {
// 				if packet[payloadStart] == 0x00 {
// 					payloadStart = payloadStart + 1
// 					break
// 				}
// 				payloadStart = payloadStart + (int(packet[payloadStart+1]) * 4)
// 			}
// 		}
// 		_, err = ifce.Write(packet[payloadStart:n])
// 		if err != nil {
// 			log.Printf("error writing to tun interface: %v", err)
// 			continue
// 		}
// 	}
// }
