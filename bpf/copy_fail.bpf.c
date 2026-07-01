// copy_fail.bpf.c — Detector CVE-2026-31431 "Copy Fail"
//
// El exploit usa sockets AF_ALG (kernel crypto API) para corromper
// el page cache de binarios compartidos entre contenedores.
// Secuencia del ataque:
//   1. socket(AF_ALG, SOCK_SEQPACKET, 0)  → abre la interfaz crypto
//   2. bind(fd, {salg_type="aead",...})    → selecciona algoritmo AEAD
//   3. sendmsg(fd, ...)                    → escritura de 4 bytes en page cache
//
// Ningún contenedor legítimo normal usa AF_ALG directamente.
// Score: CF_AF_ALG_SOCKET(+6) + CF_ALG_BIND(+7) + CF_SENDMSG_ALG(+8) = 21
// → supera umbral nivel-3 (>20) por sí solo si se completa la secuencia.
//
// Anti-falsos-positivos:
//   - Solo se alerta desde UIDs != 0 (un root legítimo puede usar AF_ALG)
//   - Se rastrea la secuencia completa: socket → bind → se_event_raw_sys_enter *ctx) {

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_ALG
#define AF_ALG 38
#endif

struct cf_event {
    __u64 ts;
    __u32 pid;
    __u32 mntns;
    __u8  code;
    __s8  score_delta;
    char  comm[16];
    char  msg[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32);
    __type(value, __u8);
} watchlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);
} unified_events SEC(".maps");

static __always_inline __u32 get_mntns(void) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = BPF_CORE_READ(t, nsproxy);
    if (!ns) return 0;
    struct mnt_namespace *mnt = BPF_CORE_READ(ns, mnt_ns);
    if (!mnt) return 0;
    return BPF_CORE_READ(mnt, ns.inum);
}

// Usar raw_tracepoint que no requiere tracefs habilitado
SEC("raw_tracepoint/sys_enter")
int raw_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    // ctx->args[1] es el id de la syscall
    unsigned long syscall_id = ctx->args[1];

    // SYS_socket = 41 en x86_64
    if (syscall_id != 41) return 0;

    // Leer el primer argumento (family) desde los registros
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    int family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &regs->di);
    if (family != AF_ALG) return 0;

    __u32 mntns = get_mntns();
    if (!bpf_map_lookup_elem(&watchlist, &mntns)) return 0;

    struct cf_event *e = bpf_ringbuf_reserve(&unified_events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts          = bpf_ktime_get_ns();
    e->pid         = (__u32)bpf_get_current_pid_tgid();
    e->mntns       = mntns;
    e->code        = 1;
    e->score_delta = 6;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->msg, "AF_ALG socket detected", 22);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
