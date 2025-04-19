// go:build ignore

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h> // for IPPROTO_UDP
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

/* Counter */
__u64 upstream_pkt_count = 0;

/* IP & TEID maps */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps"),
    upf_ip_map SEC(".maps"),
    teid_map SEC(".maps");

/* MAC maps */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
} ue_mac_map SEC(".maps"),
    gnb_mac_map SEC(".maps");

/* Simple logger */
#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n";                 \
       bpf_trace_printk(____fmt, sizeof(____fmt), \
                        ##__VA_ARGS__); })

/* 1) Ethernet header */
static __always_inline int build_eth(void *data, void *data_end)
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

/* 2) IPv4 header + checksum */
static __always_inline int build_ip(void *data, void *data_end)
{
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return -1;

    __u32 key = 0;
    __u32 *s = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *d = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!s || !d)
        return -1;

    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->tos = 0;
    iph->tot_len = bpf_htons((__u16)(data_end - (void *)iph));
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = *s;
    iph->daddr = *d;

    iph->check = 0;
    iph->check = bpf_csum_diff(
        /*from=*/NULL, /*from_size=*/0,
        /*to=*/(__be32 *)iph, /*to_size=*/sizeof(*iph),
        /*seed=*/0);
    return 0;
}

/* 3) UDP header + checksum via XDP helper */
static __always_inline int build_udp(struct xdp_md *ctx,
                                     void *data, void *data_end)
{
    struct udphdr *udph =
        data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
        return -1;

    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);
    __u16 ulen = (__u16)(data_end - (void *)udph);
    udph->len = bpf_htons(ulen);

    udph->check = 0;
    /* offset of UDP checksum field in the packet */
    __u32 csum_off = sizeof(struct ethhdr) + offsetof(struct udphdr, check);

    /*
     * bpf_l4_csum_replace works in XDP context as well:
     * - ctx:      pointer from XDP prog
     * - csum_off: offset to checksum
     * - from = 0 (old)
     * - to   = ulen network order
     * - flags = BPF_F_PSEUDO_HDR to include IP pseudo-header
     */
    if (bpf_l4_csum_replace(ctx,
                            csum_off,
                            /*from=*/0,
                            /*to=*/bpf_htons(ulen),
                            BPF_F_PSEUDO_HDR) < 0)
    {
        return -1;
    }
    return 0;
}

/* 4) GTP‑U header */
static __always_inline int build_gtp(void *data, void *data_end)
{
    __u8 *gtph = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if ((void *)(gtph + GTP_HDR_LEN) > data_end)
        return -1;

    gtph[0] = 0x30;
    gtph[1] = 0xFF;
    *(__u16 *)(gtph + 2) = bpf_htons(
        (__u16)((__u8 *)data_end - (gtph + GTP_HDR_LEN)));

    __u32 key = 0;
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid)
        return -1;
    *(__u32 *)(gtph + 4) = bpf_htonl(*teid);

    return 0;
}

/* XDP entry point */
SEC("xdp/gtp")
int xdp_gtp_encap(struct xdp_md *ctx)
{
    __sync_fetch_and_add(&upstream_pkt_count, 1);
    LOG("xdp_gtp: pkt seen");

    int push = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, -push))
    {
        LOG("xdp_gtp: adjust_head failed");
        return XDP_ABORTED;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (build_eth(data, data_end) < 0)
    {
        LOG("eth failed");
        return XDP_ABORTED;
    }
    if (build_ip(data, data_end) < 0)
    {
        LOG("ip failed");
        return XDP_ABORTED;
    }
    if (build_udp(ctx, data, data_end) < 0)
    {
        LOG("udp failed");
        return XDP_ABORTED;
    }
    if (build_gtp(data, data_end) < 0)
    {
        LOG("gtp failed");
        return XDP_ABORTED;
    }

    LOG("xdp_gtp: success");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
