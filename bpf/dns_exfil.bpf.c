// dns_exfil.bpf.c — Detector de exfiltración/tunneling DNS
// Migrado a common.h (formato unificado) y raw tracepoints (sin dependencia de tracefs)

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DNS_RATE_WINDOW  5000000000ULL   // 5 segundos
#define DNS_RATE_THRESH  20              // sendmsg por ventana

struct dns_counter { __u64 start; __u32 count; __u32 pad; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32); // mntns
    __type(value, struct dns_counter);
} dns_rate SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int raw_dns_rate_monitor(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_id = ctx->args[1];
    if (syscall_id != 1) return 0;

    __u32 mntns = get_mntns_id();
    if (!bpf_map_lookup_elem(&watchlist, &mntns))
        return 0;

    __u64 now = bpf_ktime_get_ns();
    struct dns_counter init = { .start = now, .count = 0 };
    bpf_map_update_elem(&dns_rate, &mntns, &init, BPF_NOEXIST);

    struct dns_counter *c = bpf_map_lookup_elem(&dns_rate, &mntns);
    if (!c) return 0;

    if (now - c->start > DNS_RATE_WINDOW) {
        c->start = now;
        c->count = 1;
        return 0;
    }

    __sync_fetch_and_add(&c->count, 1);
    if (c->count < DNS_RATE_THRESH) return 0;

    struct unified_event *e = bpf_ringbuf_reserve(&unified_events, sizeof(*e), 0);
    if (!e) return 0;
    if (fill_common(e, SENSOR_DNS_EXFIL, DNS_HIGH_RATE, 6, 2)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    __builtin_memcpy(e->payload, "high sendmsg rate (posible DNS tunneling)", 39);
    bpf_ringbuf_submit(e, 0);

    c->count = 0;
    c->start = now;
    return 0;
}
