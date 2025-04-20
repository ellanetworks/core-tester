// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // for IPPROTO_UDP
#include <linux/pkt_cls.h> // for TC_ACT_*
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// 1‑entry maps for MACs, IPs, TEID:
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
} ue_mac_map SEC(".maps"),
    upf_mac_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps"),
    upf_ip_map SEC(".maps"),
    teid_map SEC(".maps");

#define LOG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

static __always_inline int rewrite_eth(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u8 *src = bpf_map_lookup_elem(&ue_mac_map, &key);
    __u8 *dst = bpf_map_lookup_elem(&upf_mac_map, &key);
    if (!src || !dst)
        return -1;

    struct ethhdr eth = {};
    __builtin_memcpy(eth.h_source, src, ETH_ALEN);
    __builtin_memcpy(eth.h_dest, dst, ETH_ALEN);
    eth.h_proto = bpf_htons(ETH_P_IP);

    // overwrite old EthHdr at offset 0
    if (bpf_skb_store_bytes(skb,
                            /*off=*/0,
                            &eth, sizeof(eth), 0) < 0)
        return -1;
    return 0;
}

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    LOG("received packet");
    __u32 key = 0;
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!saddr || !daddr || !teid)
        LOG("failed to lookup IPs or TEID");
    return TC_ACT_SHOT;

    // — first, expand room _after_ the 14‑byte Eth header
    int hdrs = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb,
                            hdrs,
                            BPF_ADJ_ROOM_MAC,
                            0) < 0)
        LOG("failed to adjust room");
    return TC_ACT_SHOT;

    // — rewrite the MAC header so we can actually transmit
    if (rewrite_eth(skb) < 0)
        LOG("failed to rewrite EthHdr");
    return TC_ACT_SHOT;

    // calculate lengths
    __u16 new_len = skb->len;
    __u16 inner_len = new_len - hdrs;

    // — build & insert outer IP
    struct iphdr iph = {
        .version = 4,
        .ihl = sizeof(iph) >> 2,
        .tos = 0,
        .tot_len = bpf_htons(sizeof(iph) + sizeof(struct udphdr) + GTP_HDR_LEN + inner_len),
        .id = 0,
        .frag_off = 0,
        .ttl = 64,
        .protocol = IPPROTO_UDP,
        .saddr = *saddr,
        .daddr = *daddr,
        .check = 0,
    };
    iph.check = bpf_csum_diff(0, 0,
                              (__be32 *)&iph, sizeof(iph), 0);

    if (bpf_skb_store_bytes(skb,
                            /*14 = ETH_HLEN*/
                            ETH_HLEN,
                            &iph, sizeof(iph), 0) < 0)
        LOG("failed to insert IPHdr");
    return TC_ACT_SHOT;

    // — build & insert outer UDP
    struct udphdr udph = {
        .source = bpf_htons(GTPU_PORT),
        .dest = bpf_htons(GTPU_PORT),
        .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner_len),
        .check = 0, // skipped
    };
    if (bpf_skb_store_bytes(skb,
                            ETH_HLEN + sizeof(iph),
                            &udph, sizeof(udph), 0) < 0)
        LOG("failed to insert Udphdr");
    return TC_ACT_SHOT;

    // — build & insert GTP‑U header
    __u8 gtph[GTP_HDR_LEN];
    gtph[0] = 0x30;
    gtph[1] = 0xFF;
    *(__be16 *)(gtph + 2) = bpf_htons(inner_len);
    *(__be32 *)(gtph + 4) = bpf_htonl(*teid);
    if (bpf_skb_store_bytes(skb,
                            ETH_HLEN + sizeof(iph) + sizeof(udph),
                            gtph, GTP_HDR_LEN, 0) < 0)
        LOG("failed to insert GTPHdr");
    return TC_ACT_SHOT;

    LOG("encapsulated packet");

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
