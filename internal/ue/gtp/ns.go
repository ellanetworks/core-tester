package gtp

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"

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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 0) grab & save the root namespace
	rootNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("getting original netns: %w", err)
	}
	defer rootNS.Close()

	// 1) create the UE namespace (this also ENTERS it)
	ueNS, err := netns.NewNamed(opts.NSName)
	if err != nil {
		return fmt.Errorf("creating namespace %q: %w", opts.NSName, err)
	}
	defer ueNS.Close()

	// — we are now in UE ns!  we need to go back to root before doing any veth work —
	if err := netns.Set(rootNS); err != nil {
		return fmt.Errorf("restoring root ns after NewNamed: %w", err)
	}

	// 2) in root ns: make the veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: opts.VethHost},
		PeerName:  opts.VethUE,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("creating veth‐pair: %w", err)
	}

	// 3) still in root ns: bring up & IP the host side
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

	// 4) move the peer into UE ns
	ueLink, err := netlink.LinkByName(opts.VethUE)
	if err != nil {
		return fmt.Errorf("lookup %s in root ns: %w", opts.VethUE, err)
	}
	if err := netlink.LinkSetNsFd(ueLink, int(ueNS)); err != nil {
		return fmt.Errorf("moving %s to ns %s: %w", opts.VethUE, opts.NSName, err)
	}

	// 5) now switch into the UE ns to finish the UE‐side config
	if err := netns.Set(ueNS); err != nil {
		return fmt.Errorf("entering ns %s: %w", opts.NSName, err)
	}
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
	gw, _, _ := net.ParseCIDR(opts.HostCIDR)
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: ueIf.Attrs().Index,
		Gw:        gw,
	}); err != nil {
		return fmt.Errorf("default route via %s in UE ns: %w", gw, err)
	}
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0").Run()

	// 6) switch back to root and finish up
	if err := netns.Set(rootNS); err != nil {
		return fmt.Errorf("restoring original netns: %w", err)
	}
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	upfDst, err := netlink.ParseIPNet(opts.UpfIP + "/32")
	if err != nil {
		return fmt.Errorf("parsing UPF IP %s: %w", opts.UpfIP, err)
	}
	n3If, err := netlink.LinkByName(opts.HostN3Interface)
	if err != nil {
		return fmt.Errorf("lookup %s in root ns: %w", opts.HostN3Interface, err)
	}
	err = netlink.RouteReplace(&netlink.Route{
		LinkIndex: n3If.Attrs().Index,
		Dst:       upfDst,
	})
	if err != nil {
		return fmt.Errorf("adding route to UPF %s: %w", opts.UpfIP, err)
	}
	return nil
}
