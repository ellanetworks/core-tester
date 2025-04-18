#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // for bpf_htons, bpf_htonl

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// BPF maps to hold GNB and UPF IP addresses (network byte order)
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

// BPF map to hold TEID value
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} teid_map SEC(".maps");

// Helper to log errors and info
#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)

// Builds the outer Ethernet + IPv4 header
static __always_inline int build_ip_header(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        LOG("build_ip_header: ethhdr bounds check failed");
        return -1;
    }
    eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
    {
        LOG("build_ip_header: iphdr bounds check failed");
        return -1;
    }

    // Lookup IPs from maps
    __u32 key = 0;
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!saddr || !daddr)
    {
        LOG("build_ip_header: map lookup failed saddr=%p daddr=%p", saddr, daddr);
        return -1;
    }

    iph->version = 4;
    iph->ihl = sizeof(*iph) >> 2;
    iph->tos = 0;
    __u16 total_len = (__u16)(data_end - (data + sizeof(*eth)));
    iph->tot_len = bpf_htons(total_len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = *saddr;
    iph->daddr = *daddr;
    iph->check = 0;
    iph->check = bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);

    LOG("build_ip_header: built IP hdr saddr=0x%x daddr=0x%x total_len=%d", *saddr, *daddr, total_len);
    return 0;
}

// Builds the outer UDP header
static __always_inline int build_udp_header(void *data, void *data_end)
{
    void *udp_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    struct udphdr *udph = udp_start;
    if ((void *)(udph + 1) > data_end)
    {
        LOG("build_udp_header: udphdr bounds check failed");
        return -1;
    }

    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);

    __u16 inner_len = (__u16)(data_end - (udp_start + sizeof(*udph) + GTP_HDR_LEN));
    udph->len = bpf_htons(sizeof(*udph) + GTP_HDR_LEN + inner_len);
    udph->check = 0; // optional: compute UDP checksum

    LOG("build_udp_header: built UDP hdr src_port=%d dst_port=%d len=%d", GTPU_PORT, GTPU_PORT, inner_len);
    return 0;
}

// Builds the 8-byte GTP‑U header in-place, fetching TEID from map
static __always_inline int build_gtp_header(void *data, void *data_end)
{
    if ((void *)(data + GTP_HDR_LEN) > data_end)
    {
        LOG("build_gtp_header: bounds check failed");
        return -1;
    }

    __u8 *gtp = data;
    gtp[0] = 0x30; // version=1, PT=1, no extensions
    gtp[1] = 0xFF; // T-PDU

    __u16 payload_len = (__u16)(data_end - (data + GTP_HDR_LEN));
    *(__u16 *)(gtp + 2) = bpf_htons(payload_len);

    // Lookup TEID from map
    __u32 key = 0;
    __u32 *teid_p = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid_p)
    {
        LOG("build_gtp_header: teid_map lookup failed");
        return -1;
    }
    __u32 teid_val = *teid_p;
    *(__u32 *)(gtp + 4) = bpf_htonl(teid_val);

    LOG("build_gtp_header: built GTP hdr payload_len=%d teid=0x%x", payload_len, teid_val);
    return 0;
}

SEC("xdp/gtp")
int gtp(struct xdp_md *ctx)
{
    LOG("xdp/gtp: entry");
    int hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, -hdr_size))
    {
        LOG("xdp/gtp: adjust_head failed");
        return XDP_ABORTED;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (build_ip_header(data, data_end) < 0)
    {
        LOG("xdp/gtp: build_ip_header failed");
        return XDP_ABORTED;
    }
    if (build_udp_header(data, data_end) < 0)
    {
        LOG("xdp/gtp: build_udp_header failed");
        return XDP_ABORTED;
    }
    void *gtp_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (build_gtp_header(gtp_start, data_end) < 0)
    {
        LOG("xdp/gtp: build_gtp_header failed");
        return XDP_ABORTED;
    }

    LOG("xdp/gtp: success");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";