// common.h — tipos y macros compartidos entre todos los sensores eBPF v2
// Todos los sensores incluyen este header para garantizar
// un formato de evento unificado que el agente Go puede leer
// con un único reader.

#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// ─── IDs de sensor ───────────────────────────────────────────────────────────
#define SENSOR_PE          1   // privilege escalation
#define SENSOR_RS          2   // reverse shell
#define SENSOR_COPY_FAIL   3   // CVE-2026-31431 AF_ALG page-cache corruption
#define SENSOR_DNS_EXFIL   4   // DNS tunneling / exfiltración
#define SENSOR_CRYPTOMINER 5   // minero de criptomonedas
#define SENSOR_LATERAL     6   // movimiento lateral entre pods
#define SENSOR_ESCAPE      7   // container escape genérico

// ─── Evento unificado ────────────────────────────────────────────────────────
// Todos los sensores emiten este struct al ring buffer compartido.
// El campo 'code' es específico de cada sensor (ver enums abajo).
// El campo 'payload' lleva datos extra (args, IPs, nombres).

#define PAYLOAD_SIZE 128

struct unified_event {
    __u64 ts;              // timestamp kernel (bpf_ktime_get_ns)
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 mntns;           // mount namespace → identifica el pod
    __u8  sensor_id;       // SENSOR_* arriba
    __u8  code;            // código específico del sensor
    __s8  score_delta;     // puntos que suma este evento al score global
    __u8  severity;        // 0=info 1=low 2=medium 3=high 4=critical
    __u32 ipv4;            // IP destino (sensores de red)
    __u16 dport;           // puerto destino
    __u16 _pad;
    char  comm[16];        // nombre del proceso
    char  payload[PAYLOAD_SIZE]; // args execve / query DNS / etc
};

// ─── Ring buffer unificado (compartido entre sensores) ────────────────────────
// IMPORTANTE: este mapa se declara en cada sensor con el mismo nombre
// para que el linker de eBPF los fusione en uno solo.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB — más grande que antes
} unified_events SEC(".maps");

// ─── Watchlist compartida ─────────────────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32);  // mntns
    __type(value, __u8);
} watchlist SEC(".maps");

// ─── Helper: obtener mount namespace del proceso actual ──────────────────────
static __always_inline __u32 get_mntns_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp) return 0;
    struct mnt_namespace *mntns = BPF_CORE_READ(nsp, mnt_ns);
    if (!mntns) return 0;
    return BPF_CORE_READ(mntns, ns.inum);
}

// ─── Helper: rellenar campos comunes y verificar watchlist ───────────────────
static __always_inline int fill_common(struct unified_event *e,
                                        __u8 sensor, __u8 code,
                                        __s8 delta, __u8 sev) {
    __u32 mntns = get_mntns_id();
    if (!bpf_map_lookup_elem(&watchlist, &mntns))
        return 1; // pod no monitorizado → descartar

    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u64 uidgid  = bpf_get_current_uid_gid();

    e->ts          = bpf_ktime_get_ns();
    e->pid         = (__u32)pidtgid;
    e->tgid        = (__u32)(pidtgid >> 32);
    e->uid         = (__u32)uidgid;
    e->mntns       = mntns;
    e->sensor_id   = sensor;
    e->code        = code;
    e->score_delta = delta;
    e->severity    = sev;
    e->ipv4        = 0;
    e->dport       = 0;
    e->_pad        = 0;
    __builtin_memset(e->comm,    0, sizeof(e->comm));
    __builtin_memset(e->payload, 0, sizeof(e->payload));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return 0;
}

// ─── Helper: IPs privadas (para filtrar tráfico interno) ─────────────────────
static __always_inline bool is_private_ipv4(__u32 host) {
    __u8 a = host >> 24, b = (host >> 16) & 0xff;
    if (a == 10)                             return true; // 10/8
    if (a == 172 && b >= 16 && b <= 31)     return true; // 172.16/12
    if (a == 192 && b == 168)               return true; // 192.168/16
    if (a == 127)                            return true; // loopback
    if (a == 169 && b == 254)               return true; // link-local
    if (a == 100 && b >= 64 && b <= 127)    return true; // CGNAT
    return false;
}

// ─── Enums de códigos por sensor ─────────────────────────────────────────────

// SENSOR_PE
#define PE_UNSHARE_USER  1
#define PE_SETNS_USER    2
#define PE_CLONE_USER    3
#define PE_CAPSET        5
#define PE_PTRACE        6
#define PE_MOUNT         7
#define PE_PIVOT_ROOT    8
#define PE_BPF_SYSCALL   9
#define PE_SETUID0       10

// SENSOR_RS
#define RS_CONNECT_EXT   1
#define RS_DUP_STDFD     2
#define RS_EXEC_SUSPECT  3
#define RS_CONNECT_IPV6  4

// SENSOR_COPY_FAIL
#define CF_AF_ALG_SOCKET 1  // socket(AF_ALG) desde contenedor sin privilegios
#define CF_ALG_BIND      2  // bind sobre socket AF_ALG (preparación del exploit)
#define CF_SENDMSG_ALG   3  // sendmsg sobre AF_ALG (escritura en page cache)

// SENSOR_DNS_EXFIL
#define DNS_HIGH_RATE    1  // demasiadas queries por segundo
#define DNS_LONG_QUERY   2  // subdominio sospechosamente largo (>50 chars)
#define DNS_UNCOMMON_TYPE 3 // tipo TXT/NULL frecuente (tunneling)

// SENSOR_CRYPTOMINER
#define CM_STRATUM_PORT  1  // conexión a puerto stratum conocido
#define CM_HIGH_CPU      2  // CPU time anómalo sostenido
#define CM_MINING_COMM   3  // proceso con nombre de minero conocido

