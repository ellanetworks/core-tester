// go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n"; bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

// map[0] = ifindex of ens5
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ifindex_map SEC(".maps");

SEC("xdp")
int gtp_encap(struct xdp_md *ctx)
{
    // Log packet length
    LOG("xdp_redirect: pkt len=%u", (unsigned int)(ctx->data_end - ctx->data));

    __u32 key = 0;
    __u32 *idx = bpf_map_lookup_elem(&ifindex_map, &key);
    if (!idx)
    {
        LOG("xdp_redirect: ifindex map missing");
        return XDP_DROP;
    }

    // Redirect to ens5
    return bpf_redirect(*idx, 0);
}

char LICENSE[] SEC("license") = "GPL";
