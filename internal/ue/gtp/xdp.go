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

type AttachebpfProgramOptions struct {
	IfaceName     string
	GnbIPAddress  string
	GnbMacAddress []byte
	UeMacAddress  []byte
	UpfIPAddress  string
	Teid          uint32
}

func AttachebpfProgram(opts *AttachebpfProgramOptions) error {
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

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpGtpEncap,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("could not attach XDP program: %w", err)
	}
	defer l.Close()

	logger.EBPFLog.Infof("Attached GTP-U encapsulation eBPF program to ingress of iface %q (index %d)", iface.Name, iface.Index)

	gnbIP := net.ParseIP(opts.GnbIPAddress).To4()
	if gnbIP == nil {
		return fmt.Errorf("invalid GNB IP: %s", opts.GnbIPAddress)
	}
	upfIP := net.ParseIP(opts.UpfIPAddress).To4()
	if upfIP == nil {
		return fmt.Errorf("invalid UPF IP: %s", opts.UpfIPAddress)
	}

	gnbIPVal := binary.BigEndian.Uint32(gnbIP)
	upfIPVal := binary.BigEndian.Uint32(upfIP)

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

	if err := objs.GnbMacMap.Update(&key, &opts.GnbMacAddress, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update gnb_mac_map: %w", err)
	}

	logger.EBPFLog.Infof("Added GNB MAC %s to gnb_mac_map", net.HardwareAddr(opts.GnbMacAddress))

	if err := objs.UeMacMap.Update(&key, &opts.UeMacAddress, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update ue_mac_map: %w", err)
	}

	logger.EBPFLog.Infof("Added UE MAC %s to gnb_mac_map", net.HardwareAddr(opts.UeMacAddress))

	// Print the contents of the counters maps.
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatCounters(objs.UpstreamPktCount)
		if err != nil {
			logger.EBPFLog.Warnf("Error reading map: %s", err)
			continue
		}

		logger.EBPFLog.Infof("Packet Count: %s\n", s)
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
