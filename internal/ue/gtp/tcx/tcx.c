// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

__u64 egress_pkt_count = 0;

// BPF maps for IPs and TEID (network byte order)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} upf_ip_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} teid_map SEC(".maps");

#define LOG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

// Stub: build the outer IP (and Ethernet) header
static __always_inline int build_ip_header(struct __sk_buff *skb)
{
    // TODO: reserve room and write Ethernet+IP fields
    LOG("build_ip_header: stub called");
    return 0;
}

// Stub: build the outer UDP header
static __always_inline int build_udp_header(struct __sk_buff *skb)
{
    // TODO: write UDP fields
    LOG("build_udp_header: stub called");
    return 0;
}

// Build the 8-byte GTP-U header in-place at offset beyond UDP
static __always_inline int build_gtp_header(struct __sk_buff *skb, void *data, void *data_end)
{
    int offset = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (data + offset + GTP_HDR_LEN > data_end)
    {
        LOG("build_gtp_header: bounds check failed");
        return -1;
    }
    // Write GTP header bytes
    __u8 hdr[GTP_HDR_LEN];
    hdr[0] = 0x30; // version=1, PT=1
    hdr[1] = 0xFF; // T-PDU
    // payload length = skb->len - headers
    __u16 payload_len = (__u16)(skb->len - offset - GTP_HDR_LEN);
    *(__u16 *)(hdr + 2) = bpf_htons(payload_len);
    // Lookup TEID
    __u32 key = 0;
    __u32 *teid_p = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid_p)
    {
        LOG("build_gtp_header: teid map lookup failed");
        return -1;
    }
    *(__u32 *)(hdr + 4) = bpf_htonl(*teid_p);

    // Inject header into skb
    if (bpf_skb_store_bytes(skb, offset, hdr, GTP_HDR_LEN, 0) < 0)
    {
        LOG("build_gtp_header: skb_store_bytes failed");
        return -1;
    }

    LOG("build_gtp_header: inserted GTP header payload_len=%d teid=0x%x", payload_len, *teid_p);
    return 0;
}

SEC("tc")
int egress_prog_func(struct __sk_buff *skb)
{
    __sync_fetch_and_add(&egress_pkt_count, 1);
    LOG("egress_prog: pkt seen len=%d", skb->len);
    // 1) Reserve room for GTP header
    int hdr_size = GTP_HDR_LEN;
    if (bpf_skb_adjust_room(skb, hdr_size, BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("egress_prog: adjust_room failed");
        return TC_ACT_SHOT;
    }

    // 2) Retrieve data pointers
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 3) Call stubs/builders
    if (build_ip_header(skb) < 0)
    {
        LOG("egress_prog: build_ip_header failed");
        return TC_ACT_SHOT;
    }
    if (build_udp_header(skb) < 0)
    {
        LOG("egress_prog: build_udp_header failed");
        return TC_ACT_SHOT;
    }
    if (build_gtp_header(skb, data, data_end) < 0)
    {
        LOG("egress_prog: build_gtp_header failed");
        return TC_ACT_SHOT;
    }

    LOG("egress_prog: success");
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
