// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // IPPROTO_UDP
#include <linux/pkt_cls.h> // TC_ACT_* & BPF_ADJ_ROOM_MAC
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// single‑entry maps for your UE→UPF MACs
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
} ue_mac_map SEC(".maps"),
    upf_mac_map SEC(".maps");

// single‑entry maps for outer IPs and TEID
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps"),
    upf_ip_map SEC(".maps"),
    teid_map SEC(".maps");

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u8 *src_mac = bpf_map_lookup_elem(&ue_mac_map, &key);
    __u8 *dst_mac = bpf_map_lookup_elem(&upf_mac_map, &key);
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);

    if (!src_mac || !dst_mac || !saddr || !daddr || !teid)
        return TC_ACT_SHOT;

    // 1) carve out room **after** the 14‑byte Ethernet header
    const int l3l4gtp = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, l3l4gtp,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_SHOT;

    // new data pointers
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + ETH_HLEN + l3l4gtp > data_end)
        return TC_ACT_SHOT;

    // 2) write **outer Ethernet** at offset 0
    {
        struct ethhdr eth = {};
        __builtin_memcpy(eth.h_source, src_mac, ETH_ALEN);
        __builtin_memcpy(eth.h_dest, dst_mac, ETH_ALEN);
        eth.h_proto = bpf_htons(ETH_P_IP);
        if (bpf_skb_store_bytes(skb,
                                /*off=*/0,
                                &eth, sizeof(eth), 0) < 0)
            return TC_ACT_SHOT;
    }

    // 3) write **outer IPv4** at offset 14, then fix its checksum
    {
        __u16 inner = skb->len - ETH_HLEN - l3l4gtp;
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
            .check = 0, // placeholder
        };
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN,
                                &iph, sizeof(iph), 0) < 0)
            return TC_ACT_SHOT;
        // incremental IP checksum fix:
        if (bpf_l3_csum_replace(skb,
                                ETH_HLEN + offsetof(struct iphdr, check),
                                /*from*/ 0,
                                /*to*/ iph.check,
                                /*flags*/ 0) < 0)
            return TC_ACT_SHOT;
    }

    // 4) write **outer UDP** at offset 14+20, then fix with pseudo‑header
    {
        __u16 inner = skb->len - ETH_HLEN - l3l4gtp;
        struct udphdr udph = {
            .source = bpf_htons(GTPU_PORT),
            .dest = bpf_htons(GTPU_PORT),
            .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner),
            .check = 0, // placeholder
        };
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr),
                                &udph, sizeof(udph), 0) < 0)
            return TC_ACT_SHOT;
        // full UDP checksum (pseudo‑header + udp header + payload):
        if (bpf_l4_csum_replace(skb,
                                ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                                /*from*/ 0,
                                /*to*/ udph.len,
                                BPF_F_PSEUDO_HDR) < 0)
            return TC_ACT_SHOT;
    }

    // 5) write the 8‑byte **GTP‑U** header at offset 14+20+8
    {
        __u16 inner = skb->len - ETH_HLEN - l3l4gtp;
        __u8 gtph[GTP_HDR_LEN];
        gtph[0] = 0x30; // version=1, PT=1
        gtph[1] = 0xff; // message type = T‑PDU
        *(__be16 *)(gtph + 2) = bpf_htons(inner);
        *(__be32 *)(gtph + 4) = bpf_htonl(*teid);

        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr),
                                gtph, GTP_HDR_LEN, 0) < 0)
            return TC_ACT_SHOT;
    }

    // Everything **after** byte 50 (14+20+8+8) is the **unaltered**
    // original IP header + payload.

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
