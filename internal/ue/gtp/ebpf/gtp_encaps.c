// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h> // for TC action codes
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h> // for offsetof()

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

#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n";                               \
       bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

// 1) Update IPv4 total‑length and IP checksum
static __always_inline int build_ip_header(struct __sk_buff *skb)
{
    // Offset to ip->tot_len field from skb->data
    int off = ETH_HLEN + offsetof(struct iphdr, tot_len);
    __u16 old, nw;

    // Load old IP total length
    if (bpf_skb_load_bytes(skb, off, &old, sizeof(old)) < 0)
        return -1;

    // Compute new length = old + GTP_HDR_LEN
    nw = bpf_htons(bpf_ntohs(old) + GTP_HDR_LEN);

    // Incrementally fix IP checksum
    if (bpf_l3_csum_replace(skb, off, old, nw, 0) < 0)
        return -1;

    // Store new tot_len back
    if (bpf_skb_store_bytes(skb, off, &nw, sizeof(nw), 0) < 0)
        return -1;

    return 0;
}

// 2) Update UDP length and UDP checksum (with pseudo‑header)
static __always_inline int build_udp_header(struct __sk_buff *skb)
{
    // Offset to udp->len from skb->data
    int off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, len);
    __u16 old, nw;

    // Load old UDP length
    if (bpf_skb_load_bytes(skb, off, &old, sizeof(old)) < 0)
        return -1;

    // New UDP length = old + GTP_HDR_LEN
    nw = bpf_htons(bpf_ntohs(old) + GTP_HDR_LEN);

    // Incrementally fix UDP checksum (pseudo‑header)
    if (bpf_l4_csum_replace(skb,
                            off,
                            old,
                            nw,
                            BPF_F_PSEUDO_HDR) < 0)
        return -1;

    // Store new udp len
    if (bpf_skb_store_bytes(skb, off, &nw, sizeof(nw), 0) < 0)
        return -1;

    return 0;
}

// 3) Inject 8‑byte GTP‑U header after UDP header
static __always_inline int build_gtp_header(struct __sk_buff *skb,
                                            void *data, void *data_end)
{
    int offset = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);

    if (data + offset + GTP_HDR_LEN > data_end)
        return -1;

    __u8 hdr[GTP_HDR_LEN];
    hdr[0] = 0x30; // version=1, PT=1
    hdr[1] = 0xFF; // T‑PDU
    __u16 payload_len = (__u16)(skb->len - offset - GTP_HDR_LEN);
    *(__u16 *)(hdr + 2) = bpf_htons(payload_len);

    __u32 key = 0;
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid)
        return -1;
    *(__u32 *)(hdr + 4) = bpf_htonl(*teid);

    if (bpf_skb_store_bytes(skb,
                            offset,
                            hdr,
                            GTP_HDR_LEN,
                            0) < 0)
        return -1;

    LOG("build_gtp_header: inserted GTP header payload_len=%d teid=0x%x",
        payload_len, *teid);
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
        LOG("upstream_prog: adjust_room failed");
        return TC_ACT_SHOT;
    }

    // 2) Fix IP header
    if (build_ip_header(skb) < 0)
    {
        LOG("upstream_prog: build_ip_header failed");
        return TC_ACT_SHOT;
    }
    // 3) Fix UDP header
    if (build_udp_header(skb) < 0)
    {
        LOG("upstream_prog: build_udp_header failed");
        return TC_ACT_SHOT;
    }

    // 4) Push GTP header
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (build_gtp_header(skb, data, data_end) < 0)
    {
        LOG("upstream_prog: build_gtp_header failed");
        return TC_ACT_SHOT;
    }

    LOG("upstream_prog: success");
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
