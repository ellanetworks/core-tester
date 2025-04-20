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

// single‑entry maps for MACs
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, ETH_ALEN);
} ue_mac_map SEC(".maps"),
    upf_mac_map SEC(".maps");

// single‑entry maps for GNB/IPs and TEID
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
    __u8 *ue_mac = bpf_map_lookup_elem(&ue_mac_map, &key);
    __u8 *upf_mac = bpf_map_lookup_elem(&upf_mac_map, &key);
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!ue_mac || !upf_mac || !saddr || !daddr || !teid)
        return TC_ACT_SHOT;

    // 1) Reserve room: ETH (14) + IPv4 (20) + UDP (8) + GTP‑U (8)
    const int hdrs = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, hdrs,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_SHOT;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + hdrs > data_end)
        return TC_ACT_SHOT;

    // 2) Rewrite Ethernet header for UE → UPF
    {
        struct ethhdr eth = {};
        __builtin_memcpy(eth.h_source, ue_mac, ETH_ALEN);
        __builtin_memcpy(eth.h_dest, upf_mac, ETH_ALEN);
        eth.h_proto = bpf_htons(ETH_P_IP);
        if (bpf_skb_store_bytes(skb,
                                0, &eth, sizeof(eth), 0) < 0)
            return TC_ACT_SHOT;
    }

    // 3) Build & insert outer IPv4 header
    {
        __u16 inner = skb->len - ETH_HLEN - hdrs;
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
            .check = 0, // we’ll fix this next
        };
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN,
                                &iph, sizeof(iph), 0) < 0)
            return TC_ACT_SHOT;
        // incremental compute IP checksum (old=0 → new=correct)
        if (bpf_l3_csum_replace(skb,
                                ETH_HLEN + offsetof(struct iphdr, check),
                                0, iph.check, 0) < 0)
            return TC_ACT_SHOT;
    }

    // 4) Build & insert outer UDP header + full pseudo‐header checksum
    {
        __u16 inner = skb->len - ETH_HLEN - hdrs;
        struct udphdr udph = {
            .source = bpf_htons(GTPU_PORT),
            .dest = bpf_htons(GTPU_PORT),
            .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner),
            .check = 0, // will be fixed by helper
        };
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr),
                                &udph, sizeof(udph), 0) < 0)
            return TC_ACT_SHOT;
        // adjust UDP checksum (old=0 → new covers pseudo‐hdr+udp+payload)
        if (bpf_l4_csum_replace(skb,
                                ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                                0,
                                udph.len,
                                BPF_F_PSEUDO_HDR) < 0)
            return TC_ACT_SHOT;
    }

    // 5) Build & insert GTP‑U header
    {
        __u16 inner = skb->len - ETH_HLEN - hdrs;
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

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
