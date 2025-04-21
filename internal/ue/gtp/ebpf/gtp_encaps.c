// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG(fmt, ...) \
    ({ char ____fmt[] = fmt "\n"; bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })

SEC("xdp")
int gtp_encap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Log entry and packet length
    LOG("xdp_redirect: pkt len=%u", (unsigned int)(data_end - data));

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";