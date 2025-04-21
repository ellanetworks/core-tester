// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h> // IPPROTO_UDP
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_HDR_LEN 8

/* map[0] = ifindex of ens5 */
struct
{
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_devmap_val));
} ifindex_map SEC(".maps");

/* map[0] = TEID (host‑order) */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} teid_map SEC(".maps");

/* map[0] = outer IP src (N3) */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} n3_ip_map SEC(".maps");

/* map[0] = outer IP dst (UPF) */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} upf_ip_map SEC(".maps");

/* GTP flags+type (ver=1, PT=1, T‑PDU) */
static const __u8 gtp_ft[2] = {0x30, 0xFF};

/* Static outer IP header (20 bytes): version/IHL, TTL, protocol, checksum=0 */
static const __u8 ip_hdr_static[20] = {
    0x45, 0x00, 0x00, 0x00, // ver=4,ihl=5, TOS=0, tot_len=0
    0x00, 0x00, 0x00, 0x00, // id=0, frag_off=0
    0x40, 0x11, 0x00, 0x00, // TTL=64, proto=UDP(17), csum=0
    /* place for saddr (4 bytes) */ 0x00, 0x00, 0x00, 0x00,
    /* place for daddr (4 bytes) */ 0x00, 0x00, 0x00, 0x00};

/* Static outer UDP header (8 bytes): 2152→2152, len=0, csum=0 */
static const __u8 udp_hdr_static[8] = {
    0x08, 0x78, 0x08, 0x78, // src=2152, dst=2152
    0x00, 0x00, 0x00, 0x00  // len=0, csum=0
};

SEC("xdp")
int gtp_encap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1) look up maps */
    __u32 key = 0;
    __u32 *ifidx = bpf_map_lookup_elem(&ifindex_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    __u32 *saddr = bpf_map_lookup_elem(&n3_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!ifidx || !teid || !saddr || !daddr)
        return XDP_DROP;

    /* 2) carve headroom for 20+8+8 bytes */
    const int headroom = sizeof(ip_hdr_static) + sizeof(udp_hdr_static) + GTPU_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, -headroom) < 0)
        return XDP_DROP;

    /* 3) reload data pointers */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data + ETH_HLEN + headroom > data_end)
        return XDP_DROP;

    /* 4) insert outer IP */
    __builtin_memcpy(data + ETH_HLEN,
                     ip_hdr_static,
                     sizeof(ip_hdr_static));
    /* patch saddr,daddr */
    __builtin_memcpy(data + ETH_HLEN + offsetof(struct iphdr, saddr),
                     saddr, sizeof(*saddr));
    __builtin_memcpy(data + ETH_HLEN + offsetof(struct iphdr, daddr),
                     daddr, sizeof(*daddr));

    /* 5) insert outer UDP */
    __builtin_memcpy(data + ETH_HLEN + sizeof(ip_hdr_static),
                     udp_hdr_static,
                     sizeof(udp_hdr_static));

    /* 6) insert GTP‑U */
    __u32 gtp_off = ETH_HLEN + sizeof(ip_hdr_static) + sizeof(udp_hdr_static);
    __builtin_memcpy(data + gtp_off, gtp_ft, sizeof(gtp_ft));
    __builtin_memcpy(data + gtp_off + sizeof(gtp_ft),
                     teid, sizeof(*teid));

    /* 7) redirect out ens5 */
    return bpf_redirect_map(&ifindex_map, key, XDP_REDIRECT);
}

char LICENSE[] SEC("license") = "GPL";
