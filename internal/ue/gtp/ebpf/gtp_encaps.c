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

// maps for the single key=0 entry
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps"), upf_ip_map SEC(".maps"), teid_map SEC(".maps");

#define LOG(fmt, ...)                                           \
    do                                                          \
    {                                                           \
        bpf_trace_printk(fmt "\n", sizeof(fmt), ##__VA_ARGS__); \
    } while (0)

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    LOG("Received packet");
    __u32 key = 0;
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!saddr || !daddr || !teid)
    {
        LOG("gtp_encap: missing map");
        return TC_ACT_SHOT;
    }

    // 1) Reserve space for (IP + UDP + GTP) just *after* the Ethernet header
    int push = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;

    if (bpf_skb_adjust_room(skb, push, BPF_ADJ_ROOM_NET, 0) < 0)
    {
        LOG("gtp_encap: adjust_room failed");
        return TC_ACT_SHOT;
    }

    // 2) Calculate lengths
    //    skb->len is now old_len + push
    __u16 total = skb->len;
    __u16 inner = total - push;

    // 3) Build outer IP header at offset = ETH_HLEN
    struct iphdr iph = {
        .version = 4,
        .ihl = sizeof(iph) >> 2,
        .tos = 0,
        .tot_len = bpf_htons(sizeof(iph) + sizeof(struct udphdr) + GTP_HDR_LEN + inner),
        .id = 0,
        .frag_off = 0,
        .ttl = 64,
        .protocol = IPPROTO_UDP,
        .saddr = *saddr,
        .daddr = *daddr,
        .check = 0,
    };
    iph.check = bpf_csum_diff(0, 0, (__be32 *)&iph, sizeof(iph), 0);

    if (bpf_skb_store_bytes(skb,
                            /*off=*/ETH_HLEN,
                            &iph, sizeof(iph),
                            0) < 0)
    {
        LOG("gtp_encap: write IP hdr failed");
        return TC_ACT_SHOT;
    }

    // 4) Build outer UDP header at offset = ETH_HLEN + sizeof(iph)
    struct udphdr udph = {
        .source = bpf_htons(GTPU_PORT),
        .dest = bpf_htons(GTPU_PORT),
        .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner),
        .check = 0, // skip UDP checksum for GTP‑U
    };
    if (bpf_skb_store_bytes(skb,
                            /*off=*/ETH_HLEN + sizeof(iph),
                            &udph, sizeof(udph),
                            0) < 0)
    {
        LOG("gtp_encap: write UDP hdr failed");
        return TC_ACT_SHOT;
    }

    // 5) Build GTP‑U header at offset = ETH_HLEN + sizeof(iph) + sizeof(udph)
    __u8 gtph[GTP_HDR_LEN];
    gtph[0] = 0x30; // version=1, PT=1
    gtph[1] = 0xFF; // T‑PDU
    *(__be16 *)(gtph + 2) = bpf_htons(inner);
    *(__be32 *)(gtph + 4) = bpf_htonl(*teid);

    if (bpf_skb_store_bytes(skb,
                            /*off=*/ETH_HLEN + sizeof(iph) + sizeof(udph),
                            gtph, sizeof(gtph),
                            0) < 0)
    {
        LOG("gtp_encap: write GTP hdr failed");
        return TC_ACT_SHOT;
    }

    LOG("gtp_encap: success, new len=%d", total);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
