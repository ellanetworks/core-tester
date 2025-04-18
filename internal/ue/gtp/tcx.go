package gtp

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf tcx/tcx.c

func AttachTCProgram(ifaceName string) error {
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

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the counters maps.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatCounters(objs.EgressPktCount)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}

		log.Printf("Packet Count: %s\n", s)
	}

	return nil
}

func formatCounters(egressVar *ebpf.Variable) (string, error) {
	var (
		egressPacketCount uint64
	)

	// retrieve value from the egress map
	if err := egressVar.Get(&egressPacketCount); err != nil {
		return "", err
	}

	return fmt.Sprintf("%10v Egress", egressPacketCount), nil
}
