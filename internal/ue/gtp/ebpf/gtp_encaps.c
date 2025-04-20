// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // IPPROTO_UDP
#include <linux/pkt_cls.h> // TC action codes & BPF_ADJ_ROOM_MAC
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h> // offsetof()

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// maps: single entry each
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

// lookup saddr, daddr, teid from maps
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
        LOG("lookup_params failed");
        return -1;
    }
    *saddr = *sa;
    *daddr = *da;
    *teid = *ti;
    return 0;
}

// reserve headroom for MAC+IP+UDP+GTP
static __always_inline int reserve_room(struct __sk_buff *skb, int amt)
{
    if (bpf_skb_adjust_room(skb, amt, BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("reserve_room failed");
        return -1;
    }
    return 0;
}

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    LOG("gtp_encap start, orig len=%d", skb->len);

    // 1) grab our parameters
    __u32 saddr, daddr, teid;
    if (lookup_params(&saddr, &daddr, &teid) < 0)
        return TC_ACT_SHOT;

    // 2) reserve room for IP+UDP+GTP after the 14‑byte Ethernet header
    int hdrs = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (reserve_room(skb, hdrs) < 0)
        return TC_ACT_SHOT;

    // pointers into the newly‑adjusted skb
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + ETH_HLEN + hdrs > data_end)
        return TC_ACT_SHOT;

    // 3) rewrite Ethernet header with UE→UPF MACs
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
        if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) < 0)
            return TC_ACT_SHOT;
    }

    // 4) build & insert outer IPv4 header
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
            .saddr = saddr,
            .daddr = daddr,
            .check = 0,
        };
        // checksum = csum_diff(NULL,0, &iph, sizeof(iph), 0)
        iph.check = bpf_csum_diff((void *)0, 0,
                                  (__be32 *)&iph, sizeof(iph),
                                  0);
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN,
                                &iph, sizeof(iph),
                                0) < 0)
            return TC_ACT_SHOT;
    }

    // 5) build & insert UDP header + checksum
    {
        __u16 inner = skb->len - ETH_HLEN - hdrs;
        struct udphdr udph = {
            .source = bpf_htons(GTPU_PORT),
            .dest = bpf_htons(GTPU_PORT),
            .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner),
            .check = 0,
        };
        // write UDP header
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr),
                                &udph, sizeof(udph),
                                0) < 0)
            return TC_ACT_SHOT;

        // compute checksum over UDP hdr + payload + pseudo‑header
        __u64 csum = 0;
        // UDP header
        csum = bpf_csum_diff((void *)0, 0,
                             (void *)(data + ETH_HLEN),
                             sizeof(udph), csum);
        // UDP payload
        csum = bpf_csum_diff((void *)0, 0,
                             (void *)(data + ETH_HLEN + sizeof(udph)),
                             inner, csum);
        // pseudo‑header
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
            (__be32 *)&psh, sizeof(psh),
            (__be32 *)NULL, 0,
            csum);
        udph.check = ~csum;

        // store the checksum field
        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                                &udph.check, sizeof(udph.check),
                                0) < 0)
            return TC_ACT_SHOT;
    }

    // 6) build & insert GTP‑U header
    {
        __u16 inner = skb->len - ETH_HLEN - hdrs;
        __u8 gtph[GTP_HDR_LEN] = {
            [0] = 0x30, // version=1, PT=1
            [1] = 0xFF, // T‑PDU
        };
        *(__be16 *)(gtph + 2) = bpf_htons(inner);
        *(__be32 *)(gtph + 4) = bpf_htonl(teid);

        if (bpf_skb_store_bytes(skb,
                                ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr),
                                gtph, GTP_HDR_LEN, 0) < 0)
            return TC_ACT_SHOT;
    }

    LOG("gtp_encap done, new len=%d", skb->len);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
