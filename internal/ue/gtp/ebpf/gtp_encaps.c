// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // for IPPROTO_UDP
#include <linux/pkt_cls.h> // for TC_ACT_*
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// 1‑entry maps for MACs, IPs, TEID:
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
} ue_mac_map SEC(".maps"), upf_mac_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps"), upf_ip_map SEC(".maps"), teid_map SEC(".maps");

#define LOG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

static __always_inline int lookup_params(__u32 *saddr, __u32 *daddr, __u32 *teid)
{
    __u32 key = 0;
    __u32 *sa = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *da = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *ti = bpf_map_lookup_elem(&teid_map, &key);
    if (!sa || !da || !ti)
    {
        LOG("lookup_params: missing map entry");
        return -1;
    }
    *saddr = *sa;
    *daddr = *da;
    *teid = *ti;
    LOG("lookup_params: saddr=0x%x, daddr=0x%x, teid=0x%x", *saddr, *daddr, *teid);
    return 0;
}

static __always_inline int reserve_room(struct __sk_buff *skb, int hdrs)
{
    if (bpf_skb_adjust_room(skb, hdrs, BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("reserve_room: adjust_room failed");
        return -1;
    }
    LOG("reserve_room: hdrs=%d, new_len=%d", hdrs, skb->len);
    return 0;
}

static __always_inline int rewrite_eth(struct __sk_buff *skb, void *data, void *data_end)
{
    __u32 key = 0;
    __u8 src[ETH_ALEN], dst[ETH_ALEN];
    void *m;

    m = bpf_map_lookup_elem(&ue_mac_map, &key);
    if (!m)
    {
        LOG("rewrite_eth: no ue_mac");
        return -1;
    }
    bpf_probe_read_kernel(src, ETH_ALEN, m);

    m = bpf_map_lookup_elem(&upf_mac_map, &key);
    if (!m)
    {
        LOG("rewrite_eth: no upf_mac");
        return -1;
    }
    bpf_probe_read_kernel(dst, ETH_ALEN, m);

    struct ethhdr eth = {};
    __builtin_memcpy(eth.h_source, src, ETH_ALEN);
    __builtin_memcpy(eth.h_dest, dst, ETH_ALEN);
    eth.h_proto = bpf_htons(ETH_P_IP);

    if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) < 0)
    {
        LOG("rewrite_eth: store_bytes failed");
        return -1;
    }
    LOG("rewrite_eth: done");
    return 0;
}

static __always_inline int insert_ip(struct __sk_buff *skb, void *data, void *data_end,
                                     __u32 saddr, __u32 daddr)
{
    void *off = data + ETH_HLEN;
    if (off + sizeof(struct iphdr) > data_end)
    {
        LOG("insert_ip: bounds check failed");
        return -1;
    }

    __u16 inner = skb->len - (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN);
    struct iphdr iph = {
        .version = 4,
        .ihl = sizeof(iph) >> 2,
        .tos = 0,
        .tot_len = bpf_htons(sizeof(iph) + sizeof(struct udphdr) + GTP_HDR_LEN + inner),
        .id = 0,
        .frag_off = 0,
        .ttl = 64,
        .protocol = IPPROTO_UDP,
        .saddr = saddr,
        .daddr = daddr,
        .check = 0,
    };
    iph.check = bpf_csum_diff(0, 0, (__be32 *)&iph, sizeof(iph), 0);

    if (bpf_skb_store_bytes(skb, ETH_HLEN, &iph, sizeof(iph), 0) < 0)
    {
        LOG("insert_ip: store_bytes failed");
        return -1;
    }
    LOG("insert_ip: tot_len=%d, check=0x%x", bpf_ntohs(iph.tot_len), iph.check);
    return 0;
}

static __always_inline int insert_udp(struct __sk_buff *skb, void *data, void *data_end)
{
    void *off = data + ETH_HLEN + sizeof(struct iphdr);
    if (off + sizeof(struct udphdr) > data_end)
    {
        LOG("insert_udp: bounds check failed");
        return -1;
    }

    __u16 inner = skb->len - (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN);
    struct udphdr udph = {
        .source = bpf_htons(GTPU_PORT),
        .dest = bpf_htons(GTPU_PORT),
        .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner),
        .check = 0,
    };

    if (bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(struct iphdr),
                            &udph, sizeof(udph), 0) < 0)
    {
        LOG("insert_udp: store_bytes failed");
        return -1;
    }

    // fix UDP checksum over pseudo‑header + payload
    int csum_off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check);
    if (bpf_l4_csum_replace(skb, csum_off, 0, udph.len, BPF_F_PSEUDO_HDR) < 0)
    {
        LOG("insert_udp: csum_replace failed");
        return -1;
    }
    LOG("insert_udp: len=%d", bpf_ntohs(udph.len));
    return 0;
}

static __always_inline int insert_gtp(struct __sk_buff *skb, void *data, void *data_end,
                                      __u32 teid)
{
    void *off = data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (off + GTP_HDR_LEN > data_end)
    {
        LOG("insert_gtp: bounds check failed");
        return -1;
    }

    __u16 inner = skb->len - (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN);
    __u8 gtph[GTP_HDR_LEN];

    gtph[0] = 0x30; // version=1, PT=1
    gtph[1] = 0xFF; // T‑PDU
    *(__be16 *)(gtph + 2) = bpf_htons(inner);
    *(__be32 *)(gtph + 4) = bpf_htonl(teid);

    if (bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr),
                            gtph, GTP_HDR_LEN, 0) < 0)
    {
        LOG("insert_gtp: store_bytes failed");
        return -1;
    }
    LOG("insert_gtp: inner=%d, teid=0x%x", inner, teid);
    return 0;
}

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    LOG("=== gtp_encap start");
    LOG(" original skb->len=%d", skb->len);

    __u32 saddr, daddr, teid;
    if (lookup_params(&saddr, &daddr, &teid) < 0)
        return TC_ACT_SHOT;

    int hdrs = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (reserve_room(skb, hdrs) < 0)
        return TC_ACT_SHOT;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    LOG(" post‑reserve skb->len=%d", skb->len);

    if (rewrite_eth(skb, data, data_end) < 0)
        return TC_ACT_SHOT;
    if (insert_ip(skb, data, data_end, saddr, daddr) < 0)
        return TC_ACT_SHOT;
    if (insert_udp(skb, data, data_end) < 0)
        return TC_ACT_SHOT;
    if (insert_gtp(skb, data, data_end, teid) < 0)
        return TC_ACT_SHOT;

    LOG("=== gtp_encap done, final skb->len=%d", skb->len);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
