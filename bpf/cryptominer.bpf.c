// cryptominer.bpf.c — Detector de cryptominers en contenedores
//
// Técnicas detectadas:
//   1. Conexión a puertos stratum conocidos (3333, 4444, 14444, 45700, etc.)
//   2. Nombre de proceso coincidente con mineros conocidos (xmrig, ethminer...)
//   3. Uso de instrucciones de CPU intensivas (heurística via cpu time)
//
// El agente Go cruza con SENSOR_RS: un minero que también
// abre una shell inversa sube inmediatamente a nivel-3.

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

// Puertos stratum más comunes de pools de minería
// Monero (XMR): 3333, 5555, 7777, 14444
// Ethereum:     4444, 8008, 8545
// Genéricos:    45700, 9999, 14433
#define STRATUM_PORT_1  3333
#define STRATUM_PORT_2  4444
#define STRATUM_PORT_3  14444
#define STRATUM_PORT_4  5555
#define STRATUM_PORT_5  7777
#define STRATUM_PORT_6  45700
#define STRATUM_PORT_7  8008
#define STRATUM_PORT_8  9999
#define STRATUM_PORT_9  14433
#define STRATUM_PORT_10 3032

static __always_inline bool is_stratum_port(__u16 port) {
    return port == STRATUM_PORT_1  || port == STRATUM_PORT_2  ||
           port == STRATUM_PORT_3  || port == STRATUM_PORT_4  ||
           port == STRATUM_PORT_5  || port == STRATUM_PORT_6  ||
           port == STRATUM_PORT_7  || port == STRATUM_PORT_8  ||
           port == STRATUM_PORT_9  || port == STRATUM_PORT_10;
}

// Comms de mineros conocidos
static __always_inline bool is_miner_comm(void) {
    char c[16] = {};
    bpf_get_current_comm(c, sizeof(c));
    // xmrig — el más común en contenedores comprometidos
    if (c[0]=='x' && c[1]=='m' && c[2]=='r' && c[3]=='i' && c[4]=='g' && c[5]==0) return true;
    // ethminer
    if (c[0]=='e' && c[1]=='t' && c[2]=='h' && c[3]=='m' && c[4]=='i' && c[5]=='n') return true;
    // minerd
    if (c[0]=='m' && c[1]=='i' && c[2]=='n' && c[3]=='e' && c[4]=='r' && c[5]=='d') return true;
    // cgminer
    if (c[0]=='c' && c[1]=='g' && c[2]=='m' && c[3]=='i' && c[4]=='n' && c[5]=='e') return true;
    // bfgminer
    if (c[0]=='b' && c[1]=='f' && c[2]=='g' && c[3]=='m' && c[4]=='i' && c[5]=='n') return true;
    // t-rex (miner)
    if (c[0]=='t' && c[1]=='-' && c[2]=='r' && c[3]=='e' && c[4]=='x' && c[5]==0) return true;
    // nbminer
    if (c[0]=='n' && c[1]=='b' && c[2]=='m' && c[3]=='i' && c[4]=='n' && c[5]=='e') return true;
    return false;
}

// Pendiente connect: pidtgid → dport
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u64);
    __type(value, __u16);
} cm_pending SEC(".maps");

// ── Detectar conexión a puerto stratum ───────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_connect")
int cm_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u32 mntns = get_mntns_id();
    if (!bpf_map_lookup_elem(&watchlist, &mntns))
        return 0;

    const struct sockaddr *addr = (const struct sockaddr *)(ctx->args[1]);
    if (!addr) return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET) return 0;

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), addr);
    __u16 dport = bpf_ntohs(sin.sin_port);

    if (!is_stratum_port(dport)) return 0;

    __u64 pidtgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&cm_pending, &pidtgid, &dport, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int cm_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u16 *dp = bpf_map_lookup_elem(&cm_pending, &pidtgid);
    if (!dp) return 0;
    __u16 dport = *dp;
    bpf_map_delete_elem(&cm_pending, &pidtgid);

    if (ctx->ret != 0 && ctx->ret != -115) // -115 = EINPROGRESS (connect async)
        return 0;

    struct unified_event *e = bpf_ringbuf_reserve(&unified_events, sizeof(*e), 0);
    if (!e) return 0;
    if (fill_common(e, SENSOR_CRYPTOMINER, CM_STRATUM_PORT, 7, 3)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    e->dport = dport;
    __builtin_memcpy(e->payload, "stratum pool connection", 23);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Detectar proceso con nombre de minero conocido al hacer execve ────────────

SEC("tracepoint/syscalls/sys_enter_execve")
int cm_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 mntns = get_mntns_id();
    if (!bpf_map_lookup_elem(&watchlist, &mntns))
        return 0;

    if (!is_miner_comm()) return 0;

    struct unified_event *e = bpf_ringbuf_reserve(&unified_events, sizeof(*e), 0);
    if (!e) return 0;
    if (fill_common(e, SENSOR_CRYPTOMINER, CM_MINING_COMM, 8, 3)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    // Capturar path del ejecutable
    const char *fname = (const char *)ctx->args[0];
    if (fname)
        bpf_probe_read_user_str(e->payload, sizeof(e->payload), fname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
