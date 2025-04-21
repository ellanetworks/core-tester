// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // IPPROTO_UDP
#include <linux/pkt_cls.h> // TC_ACT_*, BPF_ADJ_ROOM_MAC
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

/* one‑slot maps for MACs, IPs, TEID, and the ens5 ifindex */
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
} gnb_ip_map SEC(".maps"),
    upf_ip_map SEC(".maps"),
    teid_map SEC(".maps"),
    ifindex_map SEC(".maps");

/* fold a 64‑bit sum into a 16‑bit checksum */
static __always_inline __u16 csum_fold(__u64 sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~(__u16)sum;
}

/* tiny printk logger */
#define LOG(fmt, ...)                              \
    ({                                             \
        char ____fmt[] = fmt "\n";                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    LOG("gtp_encap: start, len=%d", skb->len);

    __u32 key = 0;
    __u8 *src_mac = bpf_map_lookup_elem(&ue_mac_map, &key);
    __u8 *dst_mac = bpf_map_lookup_elem(&upf_mac_map, &key);
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    __u32 *ifidx = bpf_map_lookup_elem(&ifindex_map, &key);

    if (!src_mac || !dst_mac || !saddr || !daddr || !teid || !ifidx)
    {
        LOG("gtp_encap: missing map");
        return TC_ACT_SHOT;
    }

    /* reserve headroom for outer‑IP + UDP + GTP */
    const int hdr_room = sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, hdr_room,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("gtp_encap: adjust_room failed");
        return TC_ACT_SHOT;
    }
    LOG("reserved %d bytes, new len=%d", hdr_room, skb->len);

    void *data_end = (void *)(long)skb->data_end;
    /* make sure we can write ETH + our new headers */
    if ((void *)(long)skb->data + ETH_HLEN + hdr_room > data_end)
    {
        LOG("gtp_encap: bounds");
        return TC_ACT_SHOT;
    }

    /* 1) rewrite Eth */
    struct ethhdr eth = {};
    __builtin_memcpy(eth.h_source, src_mac, ETH_ALEN);
    __builtin_memcpy(eth.h_dest, dst_mac, ETH_ALEN);
    eth.h_proto = bpf_htons(ETH_P_IP);
    if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) < 0)
    {
        LOG("rewrite_eth failed");
        return TC_ACT_SHOT;
    }

    /* compute lengths */
    __u16 inner_len = skb->len - ETH_HLEN - hdr_room;

    /* 2) build & checksum outer IP */
    struct iphdr iph = {
        .version = 4,
        .ihl = sizeof(iph) >> 2,
        .tot_len = bpf_htons(sizeof(iph) + sizeof(struct udphdr) + GTP_HDR_LEN + inner_len),
        .ttl = 64,
        .protocol = IPPROTO_UDP,
        .saddr = *saddr,
        .daddr = *daddr,
    };
    {
        __u64 sum = bpf_csum_diff((__be32 *)&iph, sizeof(iph),
                                  NULL, 0, 0);
        iph.check = csum_fold(sum);
    }
    if (bpf_skb_store_bytes(skb, ETH_HLEN,
                            &iph, sizeof(iph), 0) < 0)
    {
        LOG("insert_ip failed");
        return TC_ACT_SHOT;
    }

    /* 3) build & checksum outer UDP */
    struct udphdr udph = {
        .source = bpf_htons(GTPU_PORT),
        .dest = bpf_htons(GTPU_PORT),
        .len = bpf_htons(sizeof(udph) + GTP_HDR_LEN + inner_len),
    };
    if (bpf_skb_store_bytes(skb,
                            ETH_HLEN + sizeof(iph),
                            &udph, sizeof(udph), 0) < 0)
    {
        LOG("insert_udp failed");
        return TC_ACT_SHOT;
    }
    {
        /* pseudo‑header */
        struct
        {
            __u32 saddr, daddr;
            __u8 zero, proto;
            __u16 ulen;
        } pseudo = {
            .saddr = iph.saddr,
            .daddr = iph.daddr,
            .zero = 0,
            .proto = IPPROTO_UDP,
            .ulen = udph.len,
        };
        __u64 sum = bpf_csum_diff((__be32 *)&pseudo, sizeof(pseudo),
                                  NULL, 0, 0);
        sum = bpf_csum_diff((__be32 *)&udph,
                            sizeof(udph) + inner_len,
                            NULL, 0, sum);
        udph.check = csum_fold(sum);
    }
    if (bpf_skb_store_bytes(skb,
                            ETH_HLEN + sizeof(iph) + offsetof(struct udphdr, check),
                            &udph.check, sizeof(udph.check), 0) < 0)
    {
        LOG("store_udp_csum failed");
        return TC_ACT_SHOT;
    }

    /* 4) write GTP‑U header */
    __u8 gtph[GTP_HDR_LEN];
    gtph[0] = 0x30; /* version=1, PT=1 */
    gtph[1] = 0xff; /* T‑PDU */
    *(__be16 *)(gtph + 2) = bpf_htons(inner_len);
    *(__be32 *)(gtph + 4) = bpf_htonl(*teid);
    if (bpf_skb_store_bytes(skb,
                            ETH_HLEN + sizeof(iph) + sizeof(udph),
                            gtph, GTP_HDR_LEN, 0) < 0)
    {
        LOG("insert_gtp failed");
        return TC_ACT_SHOT;
    }

    /* 5) redirect out ens5 */
    return bpf_redirect_map(&ifindex_map, key, 0);
}

char LICENSE[] SEC("license") = "GPL";
