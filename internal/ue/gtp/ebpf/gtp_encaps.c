// go:build ignore

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // IPPROTO_UDP
#include <linux/pkt_cls.h> // TC action codes
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

__u64 upstream_pkt_count = 0;

// BPF maps for IPs and TEID (network byte order)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps"),
    upf_ip_map SEC(".maps"),
    teid_map SEC(".maps");

// simple tracer
#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n";                                \
       bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

// 1) Adjust IP total length and IP checksum
static __always_inline int build_ip_header(struct __sk_buff *skb)
{
    // offset of iphdr->tot_len from skb->data
    int off = ETH_HLEN + offsetof(struct iphdr, tot_len);
    __u16 old_len, new_len;

    // load old total_len
    if (bpf_skb_load_bytes(skb, off, &old_len, sizeof(old_len)) < 0)
        return -1;

    // new total_len = old + GTP header
    new_len = bpf_htons(bpf_ntohs(old_len) + GTP_HDR_LEN);

    // incremental IP checksum update
    if (bpf_l3_csum_replace(skb, off,
                            old_len, new_len,
                            0 /* no flags */) < 0)
        return -1;

    // write new tot_len
    if (bpf_skb_store_bytes(skb, off,
                            &new_len, sizeof(new_len), 0) < 0)
        return -1;

    return 0;
}

// 2) Adjust UDP length and UDP checksum (pseudo‑header)
static __always_inline int build_udp_header(struct __sk_buff *skb)
{
    // offset of udphdr->len from skb->data
    int off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, len);
    __u16 old_len, new_len;

    // load old udp length
    if (bpf_skb_load_bytes(skb, off, &old_len, sizeof(old_len)) < 0)
        return -1;

    // new udp length = old + GTP header
    new_len = bpf_htons(bpf_ntohs(old_len) + GTP_HDR_LEN);

    // incremental UDP checksum (includes pseudo‑header)
    if (bpf_l4_csum_replace(skb, off,
                            old_len, new_len,
                            BPF_F_PSEUDO_HDR) < 0)
        return -1;

    // write new udp length
    if (bpf_skb_store_bytes(skb, off,
                            &new_len, sizeof(new_len), 0) < 0)
        return -1;

    return 0;
}

// 3) Inject the 8‑byte GTP‑U header after the UDP header
static __always_inline int build_gtp_header(struct __sk_buff *skb,
                                            void *data, void *data_end)
{
    int offset = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);

    // bounds check
    if (data + offset + GTP_HDR_LEN > data_end)
        return -1;

    __u8 hdr[GTP_HDR_LEN];
    hdr[0] = 0x30; // version=1, PT=1
    hdr[1] = 0xFF; // T-PDU
    __u16 payload_len = (__u16)(skb->len - offset - GTP_HDR_LEN);
    *(__u16 *)(hdr + 2) = bpf_htons(payload_len);

    __u32 key = 0;
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid)
        return -1;
    *(__u32 *)(hdr + 4) = bpf_htonl(*teid);

    if (bpf_skb_store_bytes(skb,
                            offset,
                            hdr, GTP_HDR_LEN, 0) < 0)
        return -1;

    return 0;
}

SEC("tc")
int upstream_prog_func(struct __sk_buff *skb)
{
    __sync_fetch_and_add(&upstream_pkt_count, 1);
    LOG("upstream_prog: pkt seen len=%d", skb->len);

    // 1) Reserve room for GTP header just after UDP
    if (bpf_skb_adjust_room(skb,
                            GTP_HDR_LEN,
                            BPF_ADJ_ROOM_MAC,
                            0) < 0)
    {
        LOG("adjust_room failed");
        return TC_ACT_SHOT;
    }

    // 2) Update IP length + checksum
    if (build_ip_header(skb) < 0)
    {
        LOG("build_ip_header failed");
        return TC_ACT_SHOT;
    }

    // 3) Update UDP length + checksum
    if (build_udp_header(skb) < 0)
    {
        LOG("build_udp_header failed");
        return TC_ACT_SHOT;
    }

    // 4) Insert GTP header
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (build_gtp_header(skb, data, data_end) < 0)
    {
        LOG("build_gtp_header failed");
        return TC_ACT_SHOT;
    }

    LOG("upstream_prog: success");
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
