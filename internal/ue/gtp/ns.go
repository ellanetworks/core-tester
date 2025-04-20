package gtp

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type SetupUEVethPairOpts struct {
	NSName          string
	UpfIP           string
	VethHost        string
	VethUE          string
	HostCIDR        string
	UECIDR          string
	HostN3Interface string
}

func SetupUEVethPair(opts *SetupUEVethPairOpts) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// save root ns
	rootNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get root ns: %w", err)
	}
	defer rootNS.Close()

	// 1) Create veth pair
	v := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: opts.VethHost},
		PeerName:  opts.VethUE,
	}
	err = netlink.LinkAdd(v)
	if err != nil {
		return fmt.Errorf("create veth: %w", err)
	}

	// 2) Bring up host side and give it hostCIDR (Ex. 10.45.0.2/16)
	hostLink, err := netlink.LinkByName(opts.VethHost)
	if err != nil {
		return fmt.Errorf("get %s: %w", opts.VethHost, err)
	}

	hostAddr, err := netlink.ParseAddr(opts.HostCIDR)
	if err != nil {
		return fmt.Errorf("parse addr %s: %w", opts.HostCIDR, err)
	}

	err = netlink.AddrAdd(hostLink, hostAddr)
	if err != nil {
		return fmt.Errorf("addr add %s: %w", opts.HostCIDR, err)
	}

	// MBring up veth-ue, assign UECIDR (ex. 10.45.0.1/16), set default via hostCIDR (ex. 10.45.0.2)
	ueLink, err := netlink.LinkByName(opts.VethUE)
	if err != nil {
		return fmt.Errorf("get %s: %w", opts.VethUE, err)
	}

	err = netlink.LinkSetUp(ueLink)
	if err != nil {
		return fmt.Errorf("up %s: %w", opts.VethUE, err)
	}

	logger.UELog.Infof("up %s", opts.VethUE)

	ueAddr, err := netlink.ParseAddr(opts.UECIDR)
	if err != nil {
		return fmt.Errorf("parse addr %s: %w", opts.UECIDR, err)
	}

	err = netlink.AddrAdd(ueLink, ueAddr)
	if err != nil {
		return fmt.Errorf("addr add %s: %w", opts.UECIDR, err)
	}

	logger.UELog.Infof("addr add %s", opts.UECIDR)

	gwIP, _, err := net.ParseCIDR(opts.HostCIDR)
	if err != nil {
		return fmt.Errorf("parse hostCIDR %s: %w", opts.HostCIDR, err)
	}

	route := &netlink.Route{
		LinkIndex: ueLink.Attrs().Index,
		Gw:        gwIP,
	}
	err = netlink.RouteAdd(route)
	if err != nil {
		return fmt.Errorf("route add default via %s: %w", gwIP, err)
	}

	logger.UELog.Infof("route add default via %s", gwIP)

	// disable rp_filter in UE ns
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0").Run()

	// 4) pop back to root ns
	err = netns.Set(rootNS)
	if err != nil {
		return fmt.Errorf("restore root ns: %w", err)
	}

	// 5) enable forwarding on host
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// 6) Route UPF IP via Host N3 interface
	upfDst, err := netlink.ParseIPNet(opts.UpfIP + "/32")
	if err != nil {
		return fmt.Errorf("parse UPF IP: %w", err)
	}

	n3Link, err := netlink.LinkByName(opts.HostN3Interface)
	if err != nil {
		return fmt.Errorf("get n3 link: %w", err)
	}

	rt := &netlink.Route{
		LinkIndex: n3Link.Attrs().Index,
		Dst:       upfDst,
	}
	if err := netlink.RouteReplace(rt); err != nil {
		return fmt.Errorf("route replace UPF: %w", err)
	}

	logger.UELog.Infof("route replace UPF %s via %s", opts.UpfIP, opts.HostN3Interface)

	// 3) Create  UE namespace and move UE link to it
	ueNS, err := netns.NewNamed(opts.NSName)
	if err != nil {
		return fmt.Errorf("new ns %s: %w", opts.NSName, err)
	}
	defer ueNS.Close()

	err = netlink.LinkSetNsFd(ueLink, int(ueNS))
	if err != nil {
		return fmt.Errorf("set ns %s: %w", opts.NSName, err)
	}

	logger.UELog.Infof("moved %s to ns %s", ueLink.Attrs().Name, opts.NSName)

	return nil
}
