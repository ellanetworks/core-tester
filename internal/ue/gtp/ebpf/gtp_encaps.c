// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8

// Counters
__u64 upstream_pkt_count = 0;

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

// Logging
#define LOG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

// Stub: build IPv4 header at given data pointer
static __always_inline int build_ip_header(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return -1;

    // TODO: lookup saddr/daddr maps and populate
    LOG("build_ip_header: stub");
    return 0;
}

// Stub: build UDP header after IP
static __always_inline int build_udp_header(void *data, void *data_end)
{
    void *udp_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    struct udphdr *udph = udp_start;
    if ((void *)(udph + 1) > data_end)
        return -1;
    // TODO: populate source/dest ports, length, checksum
    LOG("build_udp_header: stub");
    return 0;
}

// Build GTP-U header in-place
static __always_inline int build_gtp_header(void *data, void *data_end)
{
    if ((void *)(data + GTP_HDR_LEN) > data_end)
        return -1;

    __u8 *gtp = data;
    gtp[0] = 0x30; // version=1, PT=1
    gtp[1] = 0xFF; // T-PDU

    __u16 payload_len = (__u16)(data_end - (data + GTP_HDR_LEN));
    *(__u16 *)(gtp + 2) = bpf_htons(payload_len);

    __u32 key = 0;
    __u32 *teid_p = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid_p)
    {
        LOG("build_gtp_header: teid lookup");
        return -1;
    }
    *(__u32 *)(gtp + 4) = bpf_htonl(*teid_p);

    return 0;
}

SEC("xdp/gtp")
int xdp_gtp_encap(struct xdp_md *ctx)
{
    // Increment counter
    __sync_fetch_and_add(&upstream_pkt_count, 1);
    LOG("xdp_gtp: pkt seen");

    // Reserve headroom for headers: Eth+IP+UDP+GTP
    int hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, -hdr_size))
    {
        LOG("xdp_gtp: adjust_head failed");
        return XDP_ABORTED;
    }

    // Reload pointers
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Build headers in order
    if (build_ip_header(data, data_end) < 0)
    {
        LOG("xdp_gtp: ip_header failed");
        return XDP_ABORTED;
    }
    if (build_udp_header(data, data_end) < 0)
    {
        LOG("xdp_gtp: udp_header failed");
        return XDP_ABORTED;
    }
    void *gtp_pos = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (build_gtp_header(gtp_pos, data_end) < 0)
    {
        LOG("xdp_gtp: gtp_header failed");
        return XDP_ABORTED;
    }

    LOG("xdp_gtp: success");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
