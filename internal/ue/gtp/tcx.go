package gtp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ellanetworks/core-tester/internal/logger"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf tcx/tcx.c

func AttachTCProgram(ifaceName string, gnbIPAddress string, upfIPAddress string, teid uint32) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %q: %w", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("could not load BPF objects: %w", err)
	}
	defer objs.Close()

	// Attach the program to Egress TC.
	l2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("could not attach TCx program: %w", err)
	}
	defer l2.Close()

	gnbIP := net.ParseIP(gnbIPAddress).To4()
	if gnbIP == nil {
		return fmt.Errorf("invalid GNB IP: %s", gnbIPAddress)
	}
	upfIP := net.ParseIP(upfIPAddress).To4()
	if upfIP == nil {
		return fmt.Errorf("invalid UPF IP: %s", upfIPAddress)
	}

	gnbIPVal := binary.BigEndian.Uint32(gnbIP)
	upfIPVal := binary.BigEndian.Uint32(upfIP)

	var key uint32 = 0
	// Populate gnb_ip_map
	if err := objs.GnbIpMap.Update(&key, &gnbIPVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update gnb_ip_map: %w", err)
	}
	if err := objs.UpfIpMap.Update(&key, &upfIPVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update upf_ip_map: %w", err)
	}

	if err := objs.TeidMap.Update(&key, &teid, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update teid_map: %w", err)
	}

	logger.EBPFLog.Infof("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	logger.EBPFLog.Infof("Press Ctrl-C to exit and remove the program")

	// // Print the contents of the counters maps.
	// ticker := time.NewTicker(1 * time.Second)
	// defer ticker.Stop()
	// for range ticker.C {
	// 	s, err := formatCounters(objs.EgressPktCount)
	// 	if err != nil {
	// 		logger.EBPFLog.Warnf("Error reading map: %s", err)
	// 		continue
	// 	}

	// 	logger.EBPFLog.Infof("Packet Count: %s\n", s)
	// }

	return nil
}

// func formatCounters(egressVar *ebpf.Variable) (string, error) {
// 	var egressPacketCount uint64

// 	// retrieve value from the egress map
// 	if err := egressVar.Get(&egressPacketCount); err != nil {
// 		return "", err
// 	}

// 	return fmt.Sprintf("%10v Egress", egressPacketCount), nil
// }
