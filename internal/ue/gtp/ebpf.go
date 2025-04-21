package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ellanetworks/core-tester/internal/logger"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf ebpf/gtp_encaps.c

type AttachEbpfProgramOptions struct {
	IfaceName       string
	N3InterfaceName string
	GnbIPAddress    string
	GnbMacAddress   []byte
	UpfIPAddress    string
	UpfMacAddress   []byte
	UEMacAddress    []byte
	Teid            uint32
}

func AttachEbpfProgram(opts *AttachEbpfProgramOptions) error {
	iface, err := net.InterfaceByName(opts.IfaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %q: %w", opts.IfaceName, err)
	}

	n3Iface, err := net.InterfaceByName(opts.N3InterfaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %q: %w", opts.N3InterfaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("could not load BPF objects: %w", err)
	}
	defer objs.Close()

	// l, err := netlink.LinkByName(iface.Name)
	// if err != nil {
	// 	return fmt.Errorf("could not find link %q: %w", iface.Name, err)
	// }

	// err = attachTCProg(l, "gtp_encap", objs.GtpEncap)
	// if err != nil {
	// 	return fmt.Errorf("could not attach TC program: %w", err)
	// }

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.GtpEncap,
		Interface: iface.Index,
		Flags:     StringToXDPAttachMode("native"),
	})
	if err != nil {
		return fmt.Errorf("failed to attach eBPF program on interface %q: %s", iface.Name, err)
	}
	defer func() {
		if err := xdpLink.Close(); err != nil {
			logger.UELog.Warnf("Failed to detach eBPF program from interface: %s", err)
		}
	}()

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
	err = objs.IfindexMap.Update(&key, uint32(n3Iface.Index), ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update ifindex_map: %w", err)
	}
	if err := objs.N3IpMap.Update(&key, &gnbIPVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update gnb_ip_map: %w", err)
	}

	// logger.EBPFLog.Infof("Added GNB IP %s to gnb_ip_map", gnbIP)

	if err := objs.UpfIpMap.Update(&key, &upfIPVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update upf_ip_map: %w", err)
	}

	// logger.EBPFLog.Infof("Added UPF IP %s to upf_ip_map", upfIP)

	if err := objs.TeidMap.Update(&key, &opts.Teid, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update teid_map: %w", err)
	}

	// logger.EBPFLog.Infof("Added TEID %d to teid_map", opts.Teid)

	// if err := objs.UeMacMap.Update(&key, &opts.UEMacAddress, ebpf.UpdateAny); err != nil {
	// 	return err
	// }
	// if err := objs.UpfMacMap.Update(&key, &opts.UpfMacAddress, ebpf.UpdateAny); err != nil {
	// 	return err
	// }

	// Print the contents of the counters maps.
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {

		logger.EBPFLog.Infof("Waiting: \n")
	}

	return nil
}

// func attachTCProg(device netlink.Link, progName string, prog *ebpf.Program) error {
// 	// err := ensureClsact(device.Attrs().Name)
// 	// if err != nil {
// 	// 	return fmt.Errorf("could not ensure clsact qdisc: %w", err)
// 	// }

// 	// f := &netlink.BpfFilter{
// 	// 	FilterAttrs: netlink.FilterAttrs{
// 	// 		LinkIndex: device.Attrs().Index,
// 	// 		Parent:    netlink.HANDLE_MIN_INGRESS,
// 	// 		Handle:    1, // must be non‑zero
// 	// 		Priority:  1,
// 	// 		Protocol:  unix.ETH_P_ALL,
// 	// 	},
// 	// 	Fd:           prog.FD(),
// 	// 	Name:         fmt.Sprintf("%s-%s", progName, device.Attrs().Name),
// 	// 	DirectAction: false,
// 	// }

// 	// if err := netlink.FilterAdd(f); err != nil {
// 	// 	return fmt.Errorf("could not attach TC filter: %w", err)
// 	// }
// 	return nil
// }

func StringToXDPAttachMode(Mode string) link.XDPAttachFlags {
	switch Mode {
	case "generic":
		return link.XDPGenericMode
	case "native":
		return link.XDPDriverMode
	case "offload":
		return link.XDPOffloadMode
	default:
		return link.XDPGenericMode
	}
}
