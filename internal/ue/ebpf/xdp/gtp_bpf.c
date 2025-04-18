#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
#define GTP_HDR_LEN 8
#define IPPROTO_UDP 17

// BPF maps to hold GNB and UPF IP addresses (network byte order)
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gnb_ip_map SEC("maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} upf_ip_map SEC("maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} teid_map SEC("maps");

// Builds the outer Ethernet + IPv4 header
static __always_inline int build_ip_header(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return -1;

    // Lookup IPs from maps
    __u32 key = 0;
    __u32 *saddr = bpf_map_lookup_elem(&gnb_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!saddr || !daddr)
        return -1;

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

    return 0;
}

// Builds the outer UDP header
static __always_inline int build_udp_header(void *data, void *data_end)
{
    void *udp_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    struct udphdr *udph = udp_start;
    if ((void *)(udph + 1) > data_end)
        return -1;

    udph->source = bpf_htons(GTPU_PORT);
    udph->dest = bpf_htons(GTPU_PORT);

    __u16 inner_len = (__u16)(data_end - (udp_start + sizeof(*udph) + GTP_HDR_LEN));
    udph->len = bpf_htons(sizeof(*udph) + GTP_HDR_LEN + inner_len);
    udph->check = 0; // optional: compute UDP checksum

    return 0;
}

// Builds the 8-byte GTP‑U header in-place
static __always_inline int build_gtp_header(void *data, void *data_end)
{
    if (data + GTP_HDR_LEN > data_end)
        return -1;

    __u8 *gtp = data;
    gtp[0] = 0x30; // version=1, PT=1, no extensions
    gtp[1] = 0xFF; // T-PDU

    __u16 payload_len = (__u16)(data_end - (data + GTP_HDR_LEN));
    *(__u16 *)(gtp + 2) = bpf_htons(payload_len);

    __u32 key = 0;
    __u32 *teid_p = bpf_map_lookup_elem(&teid_map, &key);
    if (!teid_p)
        return -1;
    __u32 teid_val = *teid_p;
    *(__u32 *)(gtp + 4) = bpf_htonl(teid_val);

    return 0;
}

SEC("xdp/gtp")
int gtp(struct xdp_md *ctx)
{
    int hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + GTP_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, -hdr_size))
        return XDP_ABORTED;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (build_ip_header(data, data_end) < 0)
        return XDP_ABORTED;
    if (build_udp_header(data, data_end) < 0)
        return XDP_ABORTED;
    void *gtp_start = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (build_gtp_header(gtp_start, data_end) < 0)
        return XDP_ABORTED;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
