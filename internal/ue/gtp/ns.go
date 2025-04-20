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
	if err := netlink.LinkAdd(v); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}

	// 2) Bring up host side and give it hostCIDR (Ex. 10.45.0.2/16)
	hostLink, _ := netlink.LinkByName(opts.VethHost)
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("up %s: %w", opts.VethHost, err)
	}
	hostAddr, _ := netlink.ParseAddr(opts.HostCIDR)
	if err := netlink.AddrAdd(hostLink, hostAddr); err != nil {
		return fmt.Errorf("addr add %s→%s: %w", opts.HostCIDR, opts.VethHost, err)
	}

	// 3) Create and enter UE namespace
	ueNS, err := netns.NewNamed(opts.NSName)
	if err != nil {
		return fmt.Errorf("new ns %s: %w", opts.NSName, err)
	}
	defer ueNS.Close()

	// Move Ue link to UE namespace, change to ue ns, bring up veth-ue, assign UECIDR (ex. 10.45.0.1/16), set default via hostCIDR (ex. 10.45.0.2)
	ueLink, err := netlink.LinkByName(opts.VethUE)
	if err != nil {
		return fmt.Errorf("get %s: %w", opts.VethUE, err)
	}

	err = netlink.LinkSetNsFd(ueLink, int(ueNS))
	if err != nil {
		return fmt.Errorf("set ns %s: %w", opts.NSName, err)
	}

	logger.UELog.Infof("moved %s to ns %s", ueLink.Attrs().Name, opts.NSName)

	err = netns.Set(ueNS)
	if err != nil {
		return fmt.Errorf("enter ns %s: %w", opts.NSName, err)
	}

	logger.UELog.Infof("entered ns %s", opts.NSName)

	err = netlink.LinkSetUp(ueLink)
	if err != nil {
		return fmt.Errorf("ue: up %s: %w", opts.VethUE, err)
	}

	logger.UELog.Infof("up %s", opts.VethUE)

	ueAddr, err := netlink.ParseAddr(opts.UECIDR)
	if err != nil {
		return fmt.Errorf("ue: parse addr %s: %w", opts.UECIDR, err)
	}

	err = netlink.AddrAdd(ueLink, ueAddr)
	if err != nil {
		return fmt.Errorf("ue: addr add %s: %w", opts.UECIDR, err)
	}

	logger.UELog.Infof("addr add %s", opts.UECIDR)

	// default route
	gw := net.ParseIP(opts.HostCIDR)
	route := &netlink.Route{
		LinkIndex: ueLink.Attrs().Index,
		Gw:        gw,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("ue: route add default via %s: %w", gw, err)
	}
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

	return nil
}
