#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp/gtp")
int gtp(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
