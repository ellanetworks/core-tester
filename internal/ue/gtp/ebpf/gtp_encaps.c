// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>   // for IPPROTO_ICMP
#include <linux/icmp.h> // for struct icmphdr
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n"; bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

/* map[0] = ifindex of ens5 for redirect */
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

    // Log every packet
    LOG("ping_redirect: pkt len=%u", (unsigned)(data_end - data));

    // Bounds check Ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    struct ethhdr *eth = data;

    // Only IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Bounds check IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;

    // Only ICMP
    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Bounds check ICMP header
    __u32 ip_hdr_len = iph->ihl * 4;
    struct icmphdr *icmph = (void *)iph + ip_hdr_len;
    if ((void *)icmph + sizeof(*icmph) > data_end)
        return XDP_PASS;

    // Only Echo Request (type 8)
    if (icmph->type != ICMP_ECHO)
        return XDP_PASS;

    // Lookup redirect ifindex
    __u32 key = 0;
    __u32 *idx = bpf_map_lookup_elem(&ifindex_map, &key);
    if (!idx)
    {
        LOG("ping_redirect: missing ifindex_map entry");
        return XDP_PASS;
    }

    // Redirect ICMP echo requests out ens5
    return bpf_redirect(*idx, /* flags */ 0);
}

char LICENSE[] SEC("license") = "GPL";
