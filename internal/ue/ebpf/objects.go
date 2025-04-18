package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "$BPF_CFLAGS" -target bpf GTP 	xdp/gtp_bpf.c -- -I. -O2 -Wall -g
