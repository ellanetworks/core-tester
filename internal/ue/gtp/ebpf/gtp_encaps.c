// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h> // for IPPROTO_UDP
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// packet counter
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

// BPF maps for MACs (6 bytes each)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
} ue_mac_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
} gnb_mac_map SEC(".maps");

// logging macro
#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n";                \
       bpf_trace_printk(____fmt, sizeof(____fmt),##__VA_ARGS__); })

// build Ethernet header
static __always_inline int build_eth_header(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u32 key = 0;
    __u8 *src = bpf_map_lookup_elem(&ue_mac_map, &key);
    __u8 *dst = bpf_map_lookup_elem(&gnb_mac_map, &key);
    if (!src || !dst)
        return -1;

    __builtin_memcpy(eth->h_source, src, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, dst, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    return 0;
}

// build IPv4 header
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
    // total length = IP header + UDP payload (UDP+GTP+inner)
    __u16 plen = (__u16)(data_end - ((void *)iph));
    iph->tot_len = bpf_htons(plen);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = *saddr;
    iph->daddr = *daddr;

    iph->check = 0;
    iph->check = bpf_csum_diff(0, 0, iph, sizeof(*iph), 0);

    return 0;
}

// build UDP header and checksum
static __always_inline int build_udp_header(void *data, void *data_end)
{
    struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
        return -1;

    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);

    __u16 udp_len = (__u16)(data_end - ((void *)udph));
    udph->len = bpf_htons(udp_len);

    // compute UDP checksum (pseudo-header + UDP header+payload)
    udph->check = 0;
    // gather pseudo-header
    struct
    {
        __be32 src;
        __be32 dst;
        __u8 zero;
        __u8 proto;
        __be16 len;
    } psh;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    psh.src = iph->saddr;
    psh.dst = iph->daddr;
    psh.zero = 0;
    psh.proto = IPPROTO_UDP;
    psh.len = udph->len;

    // checksum over UDP header + payload
    __u64 csum = bpf_csum_diff(0, 0, udph, udp_len, 0);
    // fold in pseudo-header
    csum = bpf_csum_diff(0, 0, &psh, sizeof(psh), csum);
    udph->check = ~csum;

    return 0;
}

// build GTP-U header
static __always_inline int build_gtp_header(void *data, void *data_end)
{
    __u8 *gtp = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if ((void *)(gtp + GTP_HDR_LEN) > data_end)
        return -1;

    gtp[0] = 0x30; // version=1, PT=1
    gtp[1] = 0xFF; // T-PDU

    __u16 payload = (__u16)((__u8 *)data_end - (gtp + GTP_HDR_LEN));
    *(__u16 *)(gtp + 2) = bpf_htons(payload);

    __u32 key = 0;
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid)
        return -1;
    *(__u32 *)(gtp + 4) = bpf_htonl(*teid);

    return 0;
}

// XDP entry point
SEC("xdp/gtp")
int xdp_gtp_encap(struct xdp_md *ctx)
{
    __sync_fetch_and_add(&upstream_pkt_count, 1);
    LOG("xdp_gtp: pkt seen");

    int hdrs = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;

    if (bpf_xdp_adjust_head(ctx, -hdrs))
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
