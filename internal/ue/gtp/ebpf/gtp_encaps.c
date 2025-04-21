// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h> // TC_ACT_* & BPF_ADJ_ROOM_MAC
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_HDR_LEN 8

/* map[0] = ifindex of ens5 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
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

/* Static outer IP header (20 bytes):
 * [0] version=4,IHL=5
 * [1] TOS=0
 * [2-3] tot_len=0
 * [4-5] id=0
 * [6-7] frag_off=0
 * [8] TTL=64
 * [9] protocol=UDP(17)
 * [10-11] checksum=0
 * [12-19] saddr,daddr placeholders
 */
static const __u8 ip_hdr_static[20] = {
    0x45, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x11, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

/* Static outer UDP header (8 bytes):
 * [0-1] src port = 2152 (0x0878)
 * [2-3] dst port = 2152
 * [4-5] len = 0
 * [6-7] csum = 0
 */
static const __u8 udp_hdr_static[8] = {
    0x08, 0x78, 0x08, 0x78,
    0x00, 0x00, 0x00, 0x00};

/* lightweight printk */
#define LOG(fmt, ...)                              \
    ({                                             \
        char ____fmt[] = fmt "\n";                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    /* 1) log + look up all maps */
    LOG("gtp_encap: pkt len=%d", skb->len);
    __u32 key = 0;
    __u32 *idx = bpf_map_lookup_elem(&ifindex_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    __u32 *saddr = bpf_map_lookup_elem(&n3_ip_map, &key);
    __u32 *daddr = bpf_map_lookup_elem(&upf_ip_map, &key);
    if (!idx || !teid || !saddr || !daddr)
    {
        LOG("gtp_encap: missing map");
        return TC_ACT_SHOT;
    }

    /* 2) reserve headroom for IP+UDP+GTP */
    /* total headroom needed = outer-IP(20) + outer-UDP(8) + GTP-U(8) */
    int hdr_room = 20 + 8 + 8;

    /* tell the helper this is an IPv4→UDP tunnel */
    __u64 flags = BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;

    if (bpf_skb_adjust_room(skb,
                            hdr_room,
                            BPF_ADJ_ROOM_MAC,
                            flags) < 0)
    {
        LOG("gtp_encap: adjust_room failed, flags=0x%llx", flags);
        return TC_ACT_SHOT;
    }

    /* pointers to new and old data */
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    /* verify we can write Eth + hdrs */
    if (data + ETH_HLEN + hdr_room > data_end)
        return TC_ACT_SHOT;

    /* 3) write outer IP header at offset ETH_HLEN */
    bpf_skb_store_bytes(skb,
                        ETH_HLEN,
                        ip_hdr_static,
                        sizeof(ip_hdr_static),
                        0);

    /* override saddr+daddr in that IP header */
    bpf_skb_store_bytes(skb,
                        ETH_HLEN + offsetof(struct iphdr, saddr),
                        saddr, 4, 0);
    bpf_skb_store_bytes(skb,
                        ETH_HLEN + offsetof(struct iphdr, daddr),
                        daddr, 4, 0);

    /* 4) write outer UDP header at IP_OFF + sizeof(iphdr) */
    bpf_skb_store_bytes(skb,
                        ETH_HLEN + sizeof(ip_hdr_static),
                        udp_hdr_static,
                        sizeof(udp_hdr_static),
                        0);

    /* compute offset to GTP: */
    __u32 gtp_off = ETH_HLEN + sizeof(ip_hdr_static) + sizeof(udp_hdr_static);

    /* 5) write GTP flags/type */
    bpf_skb_store_bytes(skb,
                        gtp_off,
                        gtp_ft,
                        sizeof(gtp_ft),
                        0);

    /* 6) write TEID (network order) at gtp_off+2 */
    bpf_skb_store_bytes(skb,
                        gtp_off + sizeof(gtp_ft),
                        teid,
                        sizeof(*teid),
                        0);

    /* 7) finally redirect out ens5 */
    return bpf_redirect(*idx, 0);
}

char LICENSE[] SEC("license") = "GPL";
