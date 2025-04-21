// go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h> // TC_ACT_* helpers
#include <bpf/bpf_helpers.h>

// one‐slot map: key=0 → value=ifindex of ens5
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ifindex_map SEC(".maps");

// minimal logging macro
#define LOG(fmt, ...)                                              \
    ({                                                             \
        char ____fmt[] = fmt "\n";                                 \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

SEC("tc")
int gtp_encap(struct __sk_buff *skb)
{
    // log packet arrival + length
    LOG("gtp_encap: pkt len=%d", skb->len);

    __u32 key = 0;
    __u32 *idx = bpf_map_lookup_elem(&ifindex_map, &key);
    if (!idx)
    {
        LOG("gtp_encap: ifindex missing");
        return TC_ACT_SHOT;
    }

    // send it out the interface in map[0]
    return bpf_redirect(*idx, 0);
}

char LICENSE[] SEC("license") = "GPL";
