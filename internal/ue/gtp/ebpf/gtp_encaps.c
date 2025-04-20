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

// maps to hold our configured GNB/IP→UPF/IP and TEID
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps"), upf_ip_map SEC(".maps"), teid_map SEC(".maps");

// simple tracer
#define LOG(fmt, ...) \
    ({ char _f[] = fmt "\n"; bpf_trace_printk(_f, sizeof(_f), ##__VA_ARGS__); })

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    // 1) Push room after Ethernet for: [IP][UDP][GTP]
    int push = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, push,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("adjust_room failed");
        return TC_ACT_SHOT;
    }

    LOG("adjusted room: %d", push);

    // 2) reload data pointers
    void *raw = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 3) Ethernet header
    struct ethhdr *eth = raw;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    // 4) New IP header
    struct iphdr *new_iph = raw + sizeof(*eth);
    if ((void *)(new_iph + 1) > data_end)
        return TC_ACT_SHOT;

    // 5) New UDP header
    struct udphdr *new_udph = (void *)new_iph + sizeof(*new_iph);
    if ((void *)(new_udph + 1) > data_end)
        return TC_ACT_SHOT;

    // 6) GTP header
    __u8 *gtph = (void *)new_udph + sizeof(*new_udph);
    if ((__u8 *)gtph + GTP_HDR_LEN > (__u8 *)data_end)
        return TC_ACT_SHOT;

    // compute inner payload length
    __u32 total = skb->len - sizeof(*eth);
    __u32 inner = total - (sizeof(*new_iph) + sizeof(*new_udph) + GTP_HDR_LEN);

    // --- write GTP header ---
    gtph[0] = 0x30; // flags: v1, PT=1
    gtph[1] = 0xFF; // T‑PDU
    *(__u16 *)(gtph + 2) = bpf_htons(inner);
    __u32 key = 0;
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid)
        return TC_ACT_SHOT;
    *(__u32 *)(gtph + 4) = bpf_htonl(*teid);

    LOG("Wrote GTP header");

    // --- write UDP header ---
    new_udph->source = bpf_htons(GTPU_PORT);
    new_udph->dest = bpf_htons(GTPU_PORT);
    new_udph->len = bpf_htons(sizeof(*new_udph) + GTP_HDR_LEN + inner);
    new_udph->check = 0; // skip checksum

    LOG("Wrote UDP header");

    // --- write IP header ---
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!saddr || !daddr)
        return TC_ACT_SHOT;

    LOG("Wrote IP header");

    new_iph->version = 4;
    new_iph->ihl = sizeof(*new_iph) >> 2;
    new_iph->tos = 0;
    new_iph->tot_len = bpf_htons(sizeof(*new_iph) + sizeof(*new_udph) + GTP_HDR_LEN + inner);
    new_iph->id = 0;
    new_iph->frag_off = 0;
    new_iph->ttl = 64;
    new_iph->protocol = IPPROTO_UDP;
    new_iph->saddr = *saddr;
    new_iph->daddr = *daddr;
    new_iph->check = 0;
    new_iph->check = bpf_csum_diff(0, 0,
                                   (__be32 *)new_iph,
                                   sizeof(*new_iph),
                                   0);

    LOG("IP checksum: %x", new_iph->check);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
