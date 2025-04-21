// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n"; bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

/*
 * Use a DEVMAP for proper redirect in generic XDP mode on veth.
 * key=0 maps to the target ifindex (ens5).
 */
struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
} ifindex_map SEC(".maps");

SEC("xdp")
int gtp_encap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Log entry and packet length
    LOG("xdp_redirect: pkt len=%u", (unsigned int)(data_end - data));

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_DROP;

    // Filter only IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // Pass non-IPv4 (e.g. ARP) to kernel
        return XDP_PASS;
    }

    // Perform a devmap redirect
    return bpf_redirect_map(&ifindex_map, /*key=*/0, /*flags=*/0);
}

char LICENSE[] SEC("license") = "GPL";