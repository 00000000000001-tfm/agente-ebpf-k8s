// Se disparara cuando un pod supervisado por el agente realiza lo siguiente:
//  1) connect (2) a una direccion IPv4 no privada (code=1, arg=puerto destino, ipv4=IP destino)
//  2) duplicar (dup2/dup3) un socket conectado a stdin/stdout/stderr (code=2, argumento=newfd)
//  3) execve de shells/herramientas sospechosas (code=3), coincidente con comm (nombre del exe ejecutandose)

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define SYS_CONNECT 42
#define SYS_DUP2    33
#define SYS_DUP3    292
#define SYS_EXECVE  59

#define CODE_CONNECT_EXTERNAL 1
#define CODE_DUP_STDFD        2
#define CODE_EXEC_SUSPECT     3

struct rs_event {
    __u64 ts;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 mntns;
    __u32 code;
    __u32 arg;
    __u32 ipv4;
    char  comm[16];
    char  exe[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} rs_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} watchlist SEC(".maps");

static __always_inline __u32 get_mntns(void) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = BPF_CORE_READ(t, nsproxy);
    if (!ns) return 0;
    struct mnt_namespace *mnt = BPF_CORE_READ(ns, mnt_ns);
    if (!mnt) return 0;
    return BPF_CORE_READ(mnt, ns.inum);
}

static __always_inline void emit(__u32 mntns, __u32 code, __u32 arg, const char *fname) {
    struct rs_event *e = bpf_ringbuf_reserve(&rs_events, sizeof(*e), 0);
    if (!e) return;
    __u64 pidtgid = bpf_get_current_pid_tgid();
    e->ts    = bpf_ktime_get_ns();
    e->pid   = (__u32)pidtgid;
    e->tgid  = (__u32)(pidtgid >> 32);
    e->uid   = (__u32)bpf_get_current_uid_gid();
    e->mntns = mntns;
    e->code  = code;
    e->arg   = arg;
    e->ipv4  = 0;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    __builtin_memset(e->exe,  0, sizeof(e->exe));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (fname)
        bpf_probe_read_user_str(e->exe, sizeof(e->exe), fname);
    bpf_ringbuf_submit(e, 0);
}

SEC("raw_tracepoint/sys_enter")
int rs_enter_connect(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_id = ctx->args[1];
    if (syscall_id != SYS_CONNECT) return 0;

    __u32 mntns = get_mntns();
    if (!bpf_map_lookup_elem(&watchlist, &mntns)) return 0;

    emit(mntns, CODE_CONNECT_EXTERNAL, 0, NULL);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int rs_dup2(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_id = ctx->args[1];
    if (syscall_id != SYS_DUP2 && syscall_id != SYS_DUP3) return 0;

    __u32 mntns = get_mntns();
    if (!bpf_map_lookup_elem(&watchlist, &mntns)) return 0;

    emit(mntns, CODE_DUP_STDFD, 0, NULL);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int rs_execve(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_id = ctx->args[1];
    if (syscall_id != SYS_EXECVE) return 0;

    __u32 mntns = get_mntns();
    if (!bpf_map_lookup_elem(&watchlist, &mntns)) return 0;

    emit(mntns, CODE_EXEC_SUSPECT, 0, NULL);
    return 0;
}
