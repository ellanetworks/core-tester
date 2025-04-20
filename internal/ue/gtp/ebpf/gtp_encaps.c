// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // for IPPROTO_UDP
#include <linux/pkt_cls.h> // for TC_ACT_*
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h> // for offsetof()

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

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    LOG("new packet");
    // look up your map values
    __u32 key = 0;
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!saddr || !daddr || !teid)
        return TC_ACT_SHOT;

    // 1) reserve headroom for ETH+IP+UDP+GTP
    int hdrs = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, hdrs,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_SHOT;

    // reload data pointers
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + hdrs > data_end)
        return TC_ACT_SHOT;

    // 2) rewrite Ethernet header
    {
        __u8 src[ETH_ALEN], dst[ETH_ALEN];
        void *m;
        m = bpf_map_lookup_elem(&ue_mac_map, &key);
        if (!m)
            return TC_ACT_SHOT;
        bpf_probe_read_kernel(src, ETH_ALEN, m);
        m = bpf_map_lookup_elem(&upf_mac_map, &key);
        if (!m)
            return TC_ACT_SHOT;
        bpf_probe_read_kernel(dst, ETH_ALEN, m);

        struct ethhdr eth = {};
        __builtin_memcpy(eth.h_source, src, ETH_ALEN);
        __builtin_memcpy(eth.h_dest, dst, ETH_ALEN);
        eth.h_proto = bpf_htons(ETH_P_IP);
        if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) < 0)
            return TC_ACT_SHOT;
    }

    // 3) insert outer IP at offset = ETH_HLEN
    {
        __u16 inner = skb->len - hdrs;
        struct iphdr iph = {
            .version = 4,
            .ihl = sizeof(struct iphdr) >> 2,
            .tos = 0,
            .tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN + inner),
            .id = 0,
            .frag_off = 0,
            .ttl = 64,
            .protocol = IPPROTO_UDP,
            .saddr = *saddr,
            .daddr = *daddr,
            .check = 0,
        };
        iph.check = bpf_csum_diff(0, 0,
                                  (__be32 *)&iph,
                                  sizeof(iph), 0);
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN,
                                &iph, sizeof(iph),
                                0) < 0)
            return TC_ACT_SHOT;
    }

    // 4) insert outer UDP + recompute checksum
    {
        __u16 inner = skb->len - hdrs;
        struct udphdr udph = {
            .source = bpf_htons(GTPU_PORT),
            .dest = bpf_htons(GTPU_PORT),
            .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner),
            .check = 0,
        };
        // write the new UDP header
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr),
                                &udph, sizeof(udph), 0) < 0)
            return TC_ACT_SHOT;

        // now fix up UDP checksum (pseudo‑header + new length)
        int csum_off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check);
        if (bpf_l4_csum_replace(skb,
                                csum_off,
                                /*from=*/0,
                                /*to=*/udph.len,
                                BPF_F_PSEUDO_HDR) < 0)
            return TC_ACT_SHOT;
    }

    // 5) insert GTP‑U header
    {
        __u16 inner = skb->len - hdrs;
        __u8 gtph[GTP_HDR_LEN];
        gtph[0] = 0x30; // flags
        gtph[1] = 0xFF; // T‑PDU
        *(__be16 *)(gtph + 2) = bpf_htons(inner);
        *(__be32 *)(gtph + 4) = bpf_htonl(*teid);
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr),
                                gtph, GTP_HDR_LEN, 0) < 0)
            return TC_ACT_SHOT;
    }

    LOG("gtp_encap: done len=%d", skb->len);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
