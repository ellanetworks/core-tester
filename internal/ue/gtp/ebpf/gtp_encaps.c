// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h> // for IPPROTO_UDP
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// Counters
__u64 upstream_pkt_count = 0;

// BPF maps for IPs and TEID (network byte order)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} upf_ip_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} teid_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8) * ETH_ALEN);
} gnb_mac_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8) * ETH_ALEN);
} ue_mac_map SEC(".maps");

#define LOG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

// Build Ethernet header: dst=same as incoming, src=placeholder
static __always_inline int build_eth_header(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u32 key = 0;
    // Lookup source (this host) MAC and destination (gNB) MAC from maps
    __u8 *src_mac = bpf_map_lookup_elem(&ue_mac_map, &key);
    __u8 *dst_mac = bpf_map_lookup_elem(&gnb_mac_map, &key);
    if (!src_mac || !dst_mac)
        return -1;

    // Copy into Ethernet header
    __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);
    return 0;
}

// Build IPv4 header after Ethernet
static __always_inline int build_ip_header(void *data, void *data_end)
{
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return -1;

    __u32 key = 0;
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!saddr || !daddr)
        return -1;

    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->tos = 0;
    __u16 total_len = bpf_ntohs(iph->tot_len);
    // reconstruct total length: IP + UDP + GTP + payload
    __u16 payload_len = (__u16)(data_end - (data + sizeof(struct ethhdr) + sizeof(*iph)));
    iph->tot_len = bpf_htons(sizeof(*iph) + payload_len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = *saddr;
    iph->daddr = *daddr;
    iph->check = 0;
    iph->check = bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);
    return 0;
}

// Build UDP header after IP
static __always_inline int build_udp_header(void *data, void *data_end)
{
    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
        return -1;
    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);
    __u16 udp_len = (__u16)(data_end - (data + sizeof(struct ethhdr) + sizeof(struct iphdr)));
    udph->len = bpf_htons(udp_len);
    udph->check = 0;
    return 0;
}

// Build GTP-U header in-place
static __always_inline int build_gtp_header(void *data, void *data_end)
{
    __u8 *gtp = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if ((void *)(gtp + GTP_HDR_LEN) > data_end)
        return -1;
    gtp[0] = 0x30;
    gtp[1] = 0xFF;
    __u16 payload_len = (__u16)((__u8 *)data_end - (gtp + GTP_HDR_LEN));
    *(__u16 *)(gtp + 2) = bpf_htons(payload_len);
    __u32 key = 0;
    __u32 *teid_p = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid_p)
        return -1;
    *(__u32 *)(gtp + 4) = bpf_htonl(*teid_p);
    return 0;
}

SEC("xdp/gtp")
int xdp_gtp_encap(struct xdp_md *ctx)
{
    __sync_fetch_and_add(&upstream_pkt_count, 1);
    LOG("xdp_gtp: pkt seen");

    int hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, -hdr_size))
    {
        LOG("xdp_gtp: adjust_head failed");
        return XDP_ABORTED;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (build_eth_header(data, data_end) < 0)
    {
        LOG("xdp_gtp: eth_header failed");
        return XDP_ABORTED;
    }
    if (build_ip_header(data, data_end) < 0)
    {
        LOG("xdp_gtp: ip_header failed");
        return XDP_ABORTED;
    }
    if (build_udp_header(data, data_end) < 0)
    {
        LOG("xdp_gtp: udp_header failed");
        return XDP_ABORTED;
    }
    if (build_gtp_header(data, data_end) < 0)
    {
        LOG("xdp_gtp: gtp_header failed");
        return XDP_ABORTED;
    }

    LOG("xdp_gtp: success");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
