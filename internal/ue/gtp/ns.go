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
	NSName          string // e.g. "ue"
	UpfIP           string // e.g. "33.33.33.2"
	VethHost        string // e.g. "veth-host"
	VethUE          string // e.g. "veth-ue"
	HostCIDR        string // e.g. "10.45.0.2/16"
	UECIDR          string // e.g. "10.45.0.1/16"
	HostN3Interface string // e.g. "ens5"
}

func SetupUEVethPair(opts *SetupUEVethPairOpts) error {
	// Make sure all ns‐switches happen on one OS thread:
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 0) Save root namespace so we can come back at the end
	rootNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("getting original netns: %w", err)
	}
	defer rootNS.Close()

	// 1) Create the UE namespace (if it doesn’t already exist)
	ueNS, err := netns.NewNamed(opts.NSName)
	if err != nil {
		return fmt.Errorf("creating namespace %q: %w", opts.NSName, err)
	}
	defer ueNS.Close()

	// 2) Create the veth pair in the root ns
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: opts.VethHost},
		PeerName:  opts.VethUE,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("creating veth‐pair: %w", err)
	}

	// 3) Configure the host‐side end (still in root ns)
	hostLink, err := netlink.LinkByName(opts.VethHost)
	if err != nil {
		return fmt.Errorf("lookup %s in root ns: %w", opts.VethHost, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("bringing up %s: %w", opts.VethHost, err)
	}
	hostAddr, _ := netlink.ParseAddr(opts.HostCIDR)
	if err := netlink.AddrAdd(hostLink, hostAddr); err != nil {
		return fmt.Errorf("assign %s to %s: %w", opts.HostCIDR, opts.VethHost, err)
	}

	// 4) Move the peer into the UE namespace BEFORE trying to configure it
	ueLink, err := netlink.LinkByName(opts.VethUE)
	if err != nil {
		return fmt.Errorf("lookup %s in root ns: %w", opts.VethUE, err)
	}
	if err := netlink.LinkSetNsFd(ueLink, int(ueNS)); err != nil {
		return fmt.Errorf("moving %s to ns %s: %w", opts.VethUE, opts.NSName, err)
	}

	// 5) Switch this thread into the UE ns and set up the UE side
	if err := netns.Set(ueNS); err != nil {
		return fmt.Errorf("entering ns %s: %w", opts.NSName, err)
	}
	// Now we are in the UE namespace:
	ueIf, err := netlink.LinkByName(opts.VethUE)
	if err != nil {
		return fmt.Errorf("lookup %s in UE ns: %w", opts.VethUE, err)
	}
	if err := netlink.LinkSetUp(ueIf); err != nil {
		return fmt.Errorf("bringing up %s in UE ns: %w", opts.VethUE, err)
	}
	ueAddr, _ := netlink.ParseAddr(opts.UECIDR)
	if err := netlink.AddrAdd(ueIf, ueAddr); err != nil {
		return fmt.Errorf("assign %s to %s: %w", opts.UECIDR, opts.VethUE, err)
	}
	// Add default route in UE ns via the host‐side IP
	gw, _, _ := net.ParseCIDR(opts.HostCIDR)
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: ueIf.Attrs().Index,
		Gw:        gw,
	}); err != nil {
		return fmt.Errorf("default route via %s in UE ns: %w", gw, err)
	}
	// disable rp_filter in UE ns so ARP/IPv4 work
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0").Run()

	// 6) Switch back to the root namespace
	if err := netns.Set(rootNS); err != nil {
		return fmt.Errorf("restoring original netns: %w", err)
	}

	// 7) On the host: enable forwarding & route to the UPF
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	upfDst, _ := netlink.ParseIPNet(opts.UpfIP + "/32")
	n3If, err := netlink.LinkByName(opts.HostN3Interface)
	if err != nil {
		return fmt.Errorf("lookup host N3 iface %q: %w", opts.HostN3Interface, err)
	}
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: n3If.Attrs().Index,
		Dst:       upfDst,
	}); err != nil {
		return fmt.Errorf("route to UPF %q: %w", opts.UpfIP, err)
	}

	logger.UELog.Infof("UE veth %s<->%s in ns %q set up OK", opts.VethHost, opts.VethUE, opts.NSName)
	return nil
}
