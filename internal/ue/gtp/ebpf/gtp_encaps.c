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
    __u64 key = 0, *teid, *saddr, *daddr;
    void *data_end = (void *)(long)skb->data_end;

    // 1) reserve headroom for [IP][UDP][GTP]
    int hdrs = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, hdrs,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("adjust_room failed");
        return TC_ACT_SHOT;
    }

    // 2) re-load pointers
    void *raw = (void *)(long)skb->data;
    struct ethhdr *eth = raw;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    struct iphdr *outer_iph = (void *)eth + sizeof(*eth);
    if ((void *)(outer_iph + 1) > data_end)
        return TC_ACT_SHOT;

    struct udphdr *outer_udph = (void *)outer_iph + sizeof(*outer_iph);
    if ((void *)(outer_udph + 1) > data_end)
        return TC_ACT_SHOT;

    __u8 *gtph = (void *)outer_udph + sizeof(*outer_udph);
    if (gtph + GTP_HDR_LEN > (__u8 *)data_end)
        return TC_ACT_SHOT;

    // 3) compute inner‐payload length
    __u16 inner_len = skb->len - hdrs - sizeof(*eth);

    // 4) build GTP header
    teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid)
    {
        LOG("no TEID");
        return TC_ACT_SHOT;
    }
    gtph[0] = 0x30; // v1, PT=1
    gtph[1] = 0xFF; // T‑PDU
    *(__u16 *)(gtph + 2) = bpf_htons(inner_len);
    *(__u32 *)(gtph + 4) = bpf_htonl(*teid);

    // 5) build outer UDP header
    outer_udph->source = bpf_htons(GTPU_PORT);
    outer_udph->dest = bpf_htons(GTPU_PORT);
    outer_udph->len = bpf_htons(sizeof(*outer_udph) + GTP_HDR_LEN + inner_len);
    outer_udph->check = 0; // no checksum

    // 6) build outer IP header
    saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!saddr || !daddr)
    {
        LOG("no IP maps");
        return TC_ACT_SHOT;
    }

    outer_iph->version = 4;
    outer_iph->ihl = sizeof(*outer_iph) >> 2;
    outer_iph->tos = 0;
    outer_iph->tot_len = bpf_htons(sizeof(*outer_iph) + sizeof(*outer_udph) + GTP_HDR_LEN + inner_len);
    outer_iph->id = 0;
    outer_iph->frag_off = 0;
    outer_iph->ttl = 64;
    outer_iph->protocol = IPPROTO_UDP;
    outer_iph->saddr = *saddr;
    outer_iph->daddr = *daddr;
    outer_iph->check = 0;
    outer_iph->check = bpf_csum_diff(0, 0,
                                     (__be32 *)outer_iph,
                                     sizeof(*outer_iph),
                                     0);

    LOG("gtp_encap: done");
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
