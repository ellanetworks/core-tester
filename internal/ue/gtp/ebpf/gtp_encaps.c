// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>      // IPPROTO_UDP
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

/* map[0] = TEID to insert */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} teid_map SEC(".maps");

/* GTP flags+type (ver=1, PT=1, T-PDU) */
static const __u8 gtp_ft[2] = {0x30, 0xFF};

/* very lightweight logger */
#define LOG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    /* 1) log and lookup maps */
    LOG("gtp_encap: pkt len=%d", skb->len);
    __u32 key = 0;
    __u32 *idx = bpf_map_lookup_elem(&ifindex_map, &key);
    __u32 *teid = bpf_map_lookup_elem(&teid_map, &key);
    if (!idx || !teid)
    {
        LOG("gtp_encap: missing map");
        return TC_ACT_SHOT;
    }

    /* 2) parse L2/L3/L4 to find UDP payload offset */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Ether */
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_SHOT;
    struct ethhdr *eth = data;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return bpf_redirect(*idx, 0);

    /* IP */
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;
    if (iph->protocol != IPPROTO_UDP)
        return bpf_redirect(*idx, 0);
    __u32 ip_hdr_len = iph->ihl * 4;

    /* UDP */
    struct udphdr *udph = data + sizeof(*eth) + ip_hdr_len;
    if ((void *)udph + sizeof(*udph) > data_end)
        return TC_ACT_SHOT;

    /* 3) carve out GTP header space right after the UDP header */
    if (bpf_skb_adjust_room(skb, GTPU_HDR_LEN,
                            BPF_ADJ_ROOM_MAC, 0) < 0)
    {
        LOG("gtp_encap: adjust_room failed");
        return TC_ACT_SHOT;
    }

    /* 4) insert GTP flags+type */
    __u32 insert_off = sizeof(*eth) + ip_hdr_len + sizeof(*udph);
    bpf_skb_store_bytes(skb,
                        insert_off,
                        gtp_ft, sizeof(gtp_ft),
                        0);

    /* 5) insert TEID (network‑order) immediately after flags+type */
    bpf_skb_store_bytes(skb,
                        insert_off + sizeof(gtp_ft),
                        teid, sizeof(*teid),
                        0);

    /* 6) finally, redirect out ens5 */
    return bpf_redirect(*idx, 0);
}

char LICENSE[] SEC("license") = "GPL";
