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
