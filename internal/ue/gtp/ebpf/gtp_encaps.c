// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // IPPROTO_UDP
#include <linux/pkt_cls.h> // TC_ACT_*
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// single‐entry maps:
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

#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n";                                            \
     bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

static __always_inline int lookup_params(__u32 *saddr,
                                         __u32 *daddr,
                                         __u32 *teid)
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
    LOG("lookup: s=0x%x, d=0x%x, teid=0x%x", *saddr, *daddr, *teid);
    return 0;
}

static __always_inline int reserve_room(struct __sk_buff *skb,
                                        int amt)
{
    if (bpf_skb_adjust_room(skb, amt,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("reserve_room failed");
        return -1;
    }
    LOG("reserved=%d, new_len=%d", amt, skb->len);
    return 0;
}

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    LOG("=== start, orig len=%d", skb->len);

    __u32 saddr, daddr, teid;
    if (lookup_params(&saddr, &daddr, &teid) < 0)
        return TC_ACT_SHOT;

    /* reserve IP+UDP+GTP after the MAC */
    int l3l4gtp = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (reserve_room(skb, l3l4gtp) < 0)
        return TC_ACT_SHOT;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    LOG("post-reserve len=%d", skb->len);

    /* rewrite Ethernet */
    {
        __u8 src[ETH_ALEN], dst[ETH_ALEN];
        void *m;

        m = bpf_map_lookup_elem(&ue_mac_map, &(__u32){0});
        if (!m)
            return TC_ACT_SHOT;
        bpf_probe_read_kernel(src, ETH_ALEN, m);

        m = bpf_map_lookup_elem(&upf_mac_map, &(__u32){0});
        if (!m)
            return TC_ACT_SHOT;
        bpf_probe_read_kernel(dst, ETH_ALEN, m);

        struct ethhdr eth = {};
        __builtin_memcpy(eth.h_source, src, ETH_ALEN);
        __builtin_memcpy(eth.h_dest, dst, ETH_ALEN);
        eth.h_proto = bpf_htons(ETH_P_IP);
        if (bpf_skb_store_bytes(skb, 0,
                                &eth, sizeof(eth), 0) < 0)
            return TC_ACT_SHOT;
        LOG("eth rewritten");
    }

    /* outer IP */
    {
        if (data + ETH_HLEN + sizeof(struct iphdr) > data_end)
            return TC_ACT_SHOT;

        __u16 inner = skb->len - ETH_HLEN - l3l4gtp;

        struct iphdr iph = {
            .version = 4,
            .ihl = sizeof(iph) >> 2,
            .tos = 0,
            .tot_len = bpf_htons(
                sizeof(iph) + sizeof(struct udphdr) + GTP_HDR_LEN + inner),
            .id = 0,
            .frag_off = 0,
            .ttl = 64,
            .protocol = IPPROTO_UDP,
            .saddr = saddr,
            .daddr = daddr,
            .check = 0,
        };
        iph.check = bpf_csum_diff(
            /*from=*/NULL, /*from_size=*/0,
            /*to=*/(__be32 *)&iph, /*to_size=*/sizeof(iph),
            /*seed=*/0);
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN,
                                &iph, sizeof(iph), 0) < 0)
            return TC_ACT_SHOT;
        LOG("inserted IP: tot_len=%d", bpf_ntohs(iph.tot_len));
    }

    /* outer UDP + full checksum over header+payload+pseudo */
    {
        if (data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return TC_ACT_SHOT;

        __u16 inner = skb->len - ETH_HLEN - l3l4gtp;

        /* build UDP header with zero checksum */
        struct udphdr udph = {
            .source = bpf_htons(GTPU_PORT),
            .dest = bpf_htons(GTPU_PORT),
            .len = bpf_htons(
                sizeof(udph) + GTP_HDR_LEN + inner),
            .check = 0,
        };
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr),
                                &udph, sizeof(udph), 0) < 0)
            return TC_ACT_SHOT;

        /* compute full checksum */
        __u64 csum = 0;
        csum = bpf_csum_diff(
            /*from=*/NULL, /*from_size=*/0,
            /*to=*/(__be32 *)(data + ETH_HLEN),
            /*to_size=*/sizeof(udph),
            /*seed=*/csum);
        csum = bpf_csum_diff(
            NULL, 0,
            (__be32 *)(data + ETH_HLEN + sizeof(udph)),
            /*inner payload*/ inner,
            csum);
        struct
        {
            __be32 src, dst;
            __u8 zero;
            __u8 proto;
            __be16 len;
        } psh = {
            .src = bpf_htonl(saddr),
            .dst = bpf_htonl(daddr),
            .zero = 0,
            .proto = IPPROTO_UDP,
            .len = udph.len,
        };
        csum = bpf_csum_diff(
            NULL, 0,
            (__be32 *)&psh, sizeof(psh),
            csum);
        udph.check = ~csum;

        /* write back UDP checksum */
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                                &udph.check,
                                sizeof(udph.check),
                                0) < 0)
            return TC_ACT_SHOT;
        LOG("inserted UDP: len=%d csum=0x%x",
            bpf_ntohs(udph.len), udph.check);
    }

    /* GTP‑U header */
    {
        if (data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN > data_end)
            return TC_ACT_SHOT;

        __u16 inner = skb->len - ETH_HLEN - l3l4gtp;

        __u8 gtph[GTP_HDR_LEN];
        gtph[0] = 0x30; // ver=1, PT=1
        gtph[1] = 0xFF; // T‑PDU
        *(__be16 *)(gtph + 2) = bpf_htons(inner);
        *(__be32 *)(gtph + 4) = bpf_htonl(teid);

        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr),
                                gtph, GTP_HDR_LEN, 0) < 0)
            return TC_ACT_SHOT;
        LOG("inserted GTP: inner=%d", inner);
    }

    LOG("=== done, final len=%d", skb->len);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
