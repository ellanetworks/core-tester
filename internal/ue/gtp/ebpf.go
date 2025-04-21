package gtp

import (
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

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.GtpEncap,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
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

	// gnbIPVal := binary.LittleEndian.Uint32(gnbIP)
	// upfIPVal := binary.LittleEndian.Uint32(upfIP)

	var key uint32 = 0
	idx32 := uint32(n3Iface.Index)
	err = objs.IfindexMap.Update(&key, &idx32, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update ifindex_map: %w", err)
	}

	logger.EBPFLog.Infof("Added interface index %d to ifindex_map", n3Iface.Index)

	// if err := objs.N3IpMap.Update(&key, &gnbIPVal, ebpf.UpdateAny); err != nil {
	// 	return fmt.Errorf("failed to update gnb_ip_map: %w", err)
	// }

	// logger.EBPFLog.Infof("Added GNB IP %s to gnb_ip_map", gnbIP)

	// if err := objs.UpfIpMap.Update(&key, &upfIPVal, ebpf.UpdateAny); err != nil {
	// 	return fmt.Errorf("failed to update upf_ip_map: %w", err)
	// }

	// logger.EBPFLog.Infof("Added UPF IP %s to upf_ip_map", upfIP)

	// if err := objs.TeidMap.Update(&key, &opts.Teid, ebpf.UpdateAny); err != nil {
	// 	return fmt.Errorf("failed to update teid_map: %w", err)
	// }

	// logger.EBPFLog.Infof("Added TEID %d to teid_map", opts.Teid)

	// Print the contents of the counters maps.
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {

		logger.EBPFLog.Infof("Waiting: \n")
	}

	return nil
}
