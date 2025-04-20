package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf ebpf/gtp_encaps.c

type AttachEbpfProgramOptions struct {
	IfaceName     string
	GnbIPAddress  string
	GnbMacAddress []byte
	UpfIPAddress  string
	UpfMacAddress []byte
	UEMacAddress  []byte
	Teid          uint32
}

// func getNeighborMAC(ifaceName string, upfIP string) (net.HardwareAddr, error) {
// 	link, err := netlink.LinkByName(ifaceName)
// 	if err != nil {
// 		return nil, err
// 	}
// 	neighbors, err := netlink.NeighList(
// 		link.Attrs().Index,
// 		netlink.FAMILY_V4,
// 	)
// 	if err != nil {
// 		return nil, err
// 	}
// 	ip := net.ParseIP(upfIP)
// 	for _, n := range neighbors {
// 		if n.IP.Equal(ip) && n.State == netlink.NUD_REACHABLE {
// 			return n.HardwareAddr, nil
// 		}
// 	}
// 	return nil, fmt.Errorf("no neighbor entry for %s on %s", upfIP, ifaceName)
// }

func AttachEbpfProgram(opts *AttachEbpfProgramOptions) error {
	iface, err := net.InterfaceByName(opts.IfaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %q: %w", opts.IfaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("could not load BPF objects: %w", err)
	}
	defer objs.Close()

	l, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return fmt.Errorf("could not find link %q: %w", iface.Name, err)
	}

	err = attachTCProg(l, "gtp_encap", objs.GtpEncap)
	if err != nil {
		return fmt.Errorf("could not attach TC program: %w", err)
	}

	logger.EBPFLog.Infof("Attached GTP-U encapsulation eBPF program to egress of iface %q (index %d)", iface.Name, iface.Index)

	gnbIP := net.ParseIP(opts.GnbIPAddress).To4()
	if gnbIP == nil {
		return fmt.Errorf("invalid GNB IP: %s", opts.GnbIPAddress)
	}
	upfIP := net.ParseIP(opts.UpfIPAddress).To4()
	if upfIP == nil {
		return fmt.Errorf("invalid UPF IP: %s", opts.UpfIPAddress)
	}

	gnbIPVal := binary.LittleEndian.Uint32(gnbIP)
	upfIPVal := binary.LittleEndian.Uint32(upfIP)

	var key uint32 = 0
	if err := objs.GnbIpMap.Update(&key, &gnbIPVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update gnb_ip_map: %w", err)
	}

	logger.EBPFLog.Infof("Added GNB IP %s to gnb_ip_map", gnbIP)

	if err := objs.UpfIpMap.Update(&key, &upfIPVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update upf_ip_map: %w", err)
	}

	logger.EBPFLog.Infof("Added UPF IP %s to upf_ip_map", upfIP)

	if err := objs.TeidMap.Update(&key, &opts.Teid, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update teid_map: %w", err)
	}

	logger.EBPFLog.Infof("Added TEID %d to teid_map", opts.Teid)

	if err := objs.UeMacMap.Update(&key, &opts.UEMacAddress, ebpf.UpdateAny); err != nil {
		return err
	}
	if err := objs.UpfMacMap.Update(&key, &opts.UpfMacAddress, ebpf.UpdateAny); err != nil {
		return err
	}

	// if err := objs.GnbMacMap.Update(&key, &opts.GnbMacAddress, ebpf.UpdateAny); err != nil {
	// 	return fmt.Errorf("failed to update gnb_mac_map: %w", err)
	// }

	// logger.EBPFLog.Infof("Added GNB MAC %s to gnb_mac_map", net.HardwareAddr(opts.GnbMacAddress))

	// if err := objs.UeMacMap.Update(&key, &opts.UeMacAddress, ebpf.UpdateAny); err != nil {
	// 	return fmt.Errorf("failed to update ue_mac_map: %w", err)
	// }

	// logger.EBPFLog.Infof("Added UE MAC %s to gnb_mac_map", net.HardwareAddr(opts.UeMacAddress))

	// Print the contents of the counters maps.
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		// s, err := formatCounters(objs.UpstreamPktCount)
		// if err != nil {
		// 	logger.EBPFLog.Warnf("Error reading map: %s", err)
		// 	continue
		// }

		logger.EBPFLog.Infof("Waiting: \n")
	}

	return nil
}

func formatCounters(upstreamVar *ebpf.Variable) (string, error) {
	var upstreamPacketCount uint64

	// retrieve value from the ebpf map
	if err := upstreamVar.Get(&upstreamPacketCount); err != nil {
		return "", err
	}

	return fmt.Sprintf("%10v Upstream", upstreamPacketCount), nil
}
func ensureClsact(ifi string) error {
	// exactly: tc qdisc replace dev $IFACE clsact
	cmd := exec.Command("tc", "qdisc", "replace",
		"dev", ifi,
		"clsact",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc qdisc replace: %v\n%s", err, out)
	}
	return nil
}

func attachTCProg(device netlink.Link, progName string, prog *ebpf.Program) error {
	err := ensureClsact(device.Attrs().Name)
	if err != nil {
		return fmt.Errorf("could not ensure clsact qdisc: %w", err)
	}

	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: device.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1, // must be non‑zero
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, device.Attrs().Name),
		DirectAction: false,
	}

	if err := netlink.FilterAdd(f); err != nil {
		return fmt.Errorf("could not attach TC filter: %w", err)
	}
	return nil
}
