// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n"; bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

/* map[0] = ifindex of ens5 */
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
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Log entry and packet length
    LOG("xdp_redirect entry: pkt len=%u", (unsigned int)(data_end - data));

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_DROP;

    __u16 hproto = bpf_ntohs(eth->h_proto);
    if (hproto != ETH_P_IP)
    {
        // Pass non-IPv4 (e.g. ARP) up to the kernel
        return XDP_PASS;
    }

    // Lookup redirect ifindex
    __u32 key = 0;
    __u32 *idx = bpf_map_lookup_elem(&ifindex_map, &key);
    if (!idx)
    {
        LOG("xdp_redirect: missing ifindex");
        return XDP_DROP;
    }

    // Redirect IPv4 packets to ens5
    return bpf_redirect(*idx, 0);
}

char LICENSE[] SEC("license") = "GPL";