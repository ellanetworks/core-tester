package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "$BPF_CFLAGS" -target bpf GTP 	xdp/gtp_bpf.c -- -I. -O2 -Wall -g

// // bpfPrograms contains all programs after they have been loaded into the kernel.
// type bpfPrograms struct {
// 	XdpProgFunc *ebpf.Program `ebpf:"xdp_prog_func"`
// }

// func (p *bpfPrograms) Close() error {
// 	return _BpfClose(
// 		p.XdpProgFunc,
// 	)
// }

// // bpfObjects contains all objects after they have been loaded into the kernel.
// type bpfObjects struct {
// 	bpfPrograms
// 	bpfMaps
// 	bpfVariables
// }

// func (o *bpfObjects) Close() error {
// 	return _BpfClose(
// 		&o.bpfPrograms,
// 		&o.bpfMaps,
// 	)
// }

// func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
// 	spec, err := loadBpf()
// 	if err != nil {
// 		return err
// 	}

// 	return spec.LoadAndAssign(obj, opts)
// }
