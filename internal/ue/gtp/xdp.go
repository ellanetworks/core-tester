package gtp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf ebpf/gtp_encaps.c

const (
	tcDirectAction = 1 << 2 // BPF_TC_F_DIRECT_ACTION
)

type AttachEbpfProgramOptions struct {
	IfaceName     string
	GnbIPAddress  string
	GnbMacAddress []byte
	UpfIPAddress  string
	Teid          uint32
}

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

	// make sure clsact is in place on veth0
	// l, err := netlink.LinkByName(opts.IfaceName)
	// if err != nil {
	// 	return fmt.Errorf("lookup %s: %w", opts.IfaceName, err)
	// }
	// q := &netlink.GenericQdisc{
	// 	QdiscAttrs: netlink.QdiscAttrs{
	// 		LinkIndex: l.Attrs().Index,
	// 		Handle:    netlink.MakeHandle(0xffff, 0),
	// 		Parent:    netlink.HANDLE_CLSACT,
	// 	},
	// 	QdiscType: "clsact",
	// }
	// if err := netlink.QdiscReplace(q); err != nil {
	// 	return fmt.Errorf("install clsact qdisc: %w", err)
	// }

	// filter := &netlink.BpfFilter{
	// 	FilterAttrs: netlink.FilterAttrs{
	// 		LinkIndex: device.Attrs().Index,
	// 		Parent:    parent,
	// 		Handle:    1,
	// 		Protocol:  unix.ETH_P_ALL,
	// 		Priority:  prio,
	// 	},
	// 	Fd:           prog.FD(),
	// 	Name:         fmt.Sprintf("%s-%s", progName, device.Attrs().Name),
	// 	DirectAction: true,
	// }

	// tcLink, err := link.AttachTCX(link.TCXOptions{
	// 	Interface: iface.Index,
	// 	Program:   objs.UpstreamProgFunc,
	// 	Attach:    ebpf.AttachTCXEgress,
	// 	Flags:     tcDirectAction,
	// })
	// if err != nil {
	// 	return fmt.Errorf("could not attach TC program: %w", err)
	// }
	// defer tcLink.Close()

	iface, err = net.InterfaceByName(opts.IfaceName)
	if err != nil {
		return fmt.Errorf("could not find interface %q: %w", opts.IfaceName, err)
	}

	// 1) Make sure clsact is there
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", iface.Name, err)
	}
	cls := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(cls); err != nil {
		return fmt.Errorf("install clsact qdisc: %w", err)
	}

	// 2) Load your object
	// objs := bpfObjects{}
	// if err := loadBpfObjects(&objs, nil); err != nil {
	// 	return fmt.Errorf("could not load BPF objects: %w", err)
	// }
	// defer objs.Close()

	prog := objs.UpstreamProgFunc

	//  3. Prepare the TC filter
	//     For egress, clsact's egress hook is parent=ffff:fff2 (minor=2)
	parent := netlink.MakeHandle(0xffff, 2) // 0xFFFF:0x0002

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         "upstream_prog_func",
		DirectAction: true,
	}

	// 4) Install it
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("could not attach TC filter: %w", err)
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
