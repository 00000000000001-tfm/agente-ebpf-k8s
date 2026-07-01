#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DNS_RATE_WINDOW  5000000000ULL
#define DNS_RATE_THRESH  20

struct dns_counter { __u64 start; __u32 count; __u32 pad; };

struct dns_event {
    __u64 ts; __u32 pid; __u32 pad;
    char  comm[16];
    char  msg[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32); // tgid
    __type(value, struct dns_counter);
} dns_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} dns_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int dns_rate_monitor(struct trace_event_raw_sys_enter *ctx) {
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pidtgid >> 32);
    __u64 now  = bpf_ktime_get_ns();

    struct dns_counter new = { .start = now, .count = 0 };
    bpf_map_update_elem(&dns_rate, &tgid, &new, BPF_NOEXIST);

    struct dns_counter *c = bpf_map_lookup_elem(&dns_rate, &tgid);
    if (!c) return 0;

    if (now - c->start > DNS_RATE_WINDOW) {
        c->start = now;
        c->count = 1;
        return 0;
    }

    __sync_fetch_and_add(&c->count, 1);
    if (c->count < DNS_RATE_THRESH) return 0;

    struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts  = now;
    e->pid = (__u32)pidtgid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->msg, "high sendmsg rate", 17);
    bpf_ringbuf_submit(e, 0);

    c->count = 0;
    c->start = now;
    return 0;
}
