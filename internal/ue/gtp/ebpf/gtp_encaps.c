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

// maps for GNB↔UPF IPs and TEID
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
    __u32 key = 0;
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!saddr || !daddr || !teid)
    {
        LOG("missing map entries");
        return TC_ACT_SHOT;
    }

    // 1) reserve headroom for IP + UDP + GTP
    int hdrs = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, hdrs,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("adjust_room failed");
        return TC_ACT_SHOT;
    }

    // 2) figure out inner payload length (L2 stripped by TC)
    //    skb->len is now old_len + hdrs
    __u16 new_len = skb->len;
    __u16 inner_len = new_len - hdrs;

    // 3) write outer IP header at offset = 0
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
        .check = 0, // will be filled next
    };
    iph.check = bpf_csum_diff(0, 0,
                              (__be32 *)&iph, sizeof(iph),
                              0);
    if (bpf_skb_store_bytes(skb,
                            /*off=*/0,
                            &iph, sizeof(iph),
                            0) < 0)
    {
        LOG("write IP hdr failed");
        return TC_ACT_SHOT;
    }

    // 4) write outer UDP header immediately after IP
    struct udphdr udph = {
        .source = bpf_htons(GTPU_PORT),
        .dest = bpf_htons(GTPU_PORT),
        .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner_len),
        .check = 0, // skip checksum
    };
    if (bpf_skb_store_bytes(skb,
                            /*off=*/sizeof(iph),
                            &udph, sizeof(udph),
                            0) < 0)
    {
        LOG("write UDP hdr failed");
        return TC_ACT_SHOT;
    }

    // 5) write GTP header immediately after UDP
    __u8 gtph[GTP_HDR_LEN];
    gtph[0] = 0x30; // version=1, PT=1
    gtph[1] = 0xFF; // T‑PDU
    *(__be16 *)(gtph + 2) = bpf_htons(inner_len);
    *(__be32 *)(gtph + 4) = bpf_htonl(*teid);
    if (bpf_skb_store_bytes(skb,
                            /*off=*/sizeof(iph) + sizeof(udph),
                            gtph, GTP_HDR_LEN,
                            0) < 0)
    {
        LOG("write GTP hdr failed");
        return TC_ACT_SHOT;
    }

    LOG("gtp_encap: done len=%d", new_len);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
