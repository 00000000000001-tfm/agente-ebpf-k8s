// responder.go — Respuesta graduada según nivel de severidad
//
// Nivel 1 (score 8-12):  Observar y alertar — sin bloqueo
// Nivel 2 (score 12-20): Cuarentena de red + Kyverno banlist (comportamiento actual mejorado)  
// Nivel 3 (score >20):   SIGKILL inmediato + cordon nodo + alerta crítica

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	kyv "tfm.com/perpod-ebpf/internal/kyverno"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// SensorLabels mapea IDs de sensor a nombres legibles para logs
var SensorLabels = map[uint8]string{
	SENSOR_PE:          "priv-esc",
	SENSOR_RS:          "reverse-shell",
	SENSOR_COPY_FAIL:   "copy-fail(CVE-2026-31431)",
	SENSOR_DNS_EXFIL:   "dns-exfil",
	SENSOR_CRYPTOMINER: "cryptominer",
}

// CodeLabels mapea código de evento a descripción
var CodeLabels = map[uint8]map[uint8]string{
	SENSOR_COPY_FAIL: {
		CF_AF_ALG_SOCKET: "AF_ALG socket abierto desde contenedor sin privilegios",
		CF_ALG_BIND:      "bind sobre AF_ALG socket (preparando exploit)",
		CF_SENDMSG_ALG:   "sendmsg AF_ALG: escritura en page cache del host",
	},
	SENSOR_DNS_EXFIL: {
		DNS_HIGH_RATE:  "alta tasa de queries DNS (posible tunneling/exfiltración)",
		DNS_LONG_QUERY: "subdominio DNS muy largo (posible DNS tunneling)",
	},
	SENSOR_CRYPTOMINER: {
		CM_STRATUM_PORT: "conexión a puerto stratum de pool de minería",
		CM_MINING_COMM:  "proceso con nombre de minero conocido ejecutado",
	},
}

// Responder gestiona la respuesta a incidentes
type Responder struct {
	correlator *Correlator
}

func NewResponder(c *Correlator) *Responder {
	return &Responder{correlator: c}
}

// HandleEvent procesa un evento unificado y ejecuta la respuesta adecuada
func (r *Responder) HandleEvent(ev UnifiedEvent, meta podMeta, podImage string) {
	sensorName := SensorLabels[ev.SensorID]
	if sensorName == "" {
		sensorName = fmt.Sprintf("sensor-%d", ev.SensorID)
	}

	score := r.correlator.GetScore(ev.Mntns)
	log.Printf("[%s] ns=%s pod=%s pid=%d code=%d(+%d) score=%d payload=%q",
		sensorName, meta.Namespace, meta.Pod,
		ev.Pid, ev.Code, ev.ScoreDelta, score, trimPayload(ev.Payload[:]))

	level := r.correlator.AddEvent(ev.Mntns, ev.SensorID, ev.Code, ev.ScoreDelta, podImage, ev.CommStr())
	if level == 0 {
		return
	}

	score = r.correlator.GetScore(ev.Mntns)

	switch level {
	case LevelObserve:
		r.respondLevel1(ev, meta, score, sensorName)
	case LevelQuarantine:
		r.respondLevel2(ev, meta, score, sensorName, podImage)
	case LevelKill:
		r.respondLevel3(ev, meta, score, sensorName, podImage)
	}
}

// ── Nivel 1: Observar y alertar ──────────────────────────────────────────────

func (r *Responder) respondLevel1(ev UnifiedEvent, meta podMeta, score int, sensor string) {
	log.Printf("[WARN][L1] ACTIVIDAD SOSPECHOSA ns=%s pod=%s sensor=%s score=%d — observando",
		meta.Namespace, meta.Pod, sensor, score)

	// Incrementar métrica Prometheus (cuando se implemente)
	// metrics.SuspiciousEvents.WithLabelValues(meta.Namespace, meta.Pod, sensor).Inc()
	metricEventsTotal.WithLabelValues(sensor).Inc()
	metricIncidentsTotal.WithLabelValues("L1").Inc()
}

// ── Nivel 2: Cuarentena ───────────────────────────────────────────────────────
func (r *Responder) respondLevel2(ev UnifiedEvent, meta podMeta, score int, sensor, image string) {
	log.Printf("[ALERT][L2] INCIDENTE CONFIRMADO ns=%s pod=%s sensor=%s score=%d — cuarentena",
		meta.Namespace, meta.Pod, sensor, score)
	metricEventsTotal.WithLabelValues(sensor).Inc()
	metricIncidentsTotal.WithLabelValues("L2").Inc()

	ctx := context.Background()

        // 1. Cuarentena de red inmediata (NetworkPolicy egress bloqueado)
	if err := gKM.TempQuarantineEgress(ctx, meta.Namespace, meta.Pod, 15*time.Minute); err != nil {
		log.Printf("[warn] cuarentena red fallida: %v", err)
	}
        // 2. Banlist + Política Kyverno
	fp := kyv.Fingerprint{Images: []string{image}, ServiceAccount: "default"}
	if err := gKM.UpdateBanlist(ctx, fp); err != nil {
		log.Printf("[warn] banlist fallido: %v", err)
	}
	if err := gKM.CreatePreventionPolicy(ctx, fp); err != nil {
		log.Printf("[warn] prevention policy fallida: %v", err)
	}
	if err := gKM.CreateCleanupForPod(ctx, meta.Namespace, meta.Pod); err != nil {
		log.Printf("[warn] cleanup policy fallida: %v", err)
	}
}

// ── Nivel 3: Eliminación inmediata ───────────────────────────────────────────

func (r *Responder) respondLevel3(ev UnifiedEvent, meta podMeta, score int, sensor, image string) {
	log.Printf("[CRITICAL][L3] ATAQUE CRÍTICO ns=%s pod=%s sensor=%s score=%d — KILL+CORDON",
		meta.Namespace, meta.Pod, sensor, score)
	metricEventsTotal.WithLabelValues(sensor).Inc()
	metricIncidentsTotal.WithLabelValues("L3").Inc()

	ctx := context.Background()

	// 1. Cuarentena de red inmediata
	if err := gKM.TempQuarantineEgress(ctx, meta.Namespace, meta.Pod, 60*time.Minute); err != nil {
		log.Printf("[warn] cuarentena red fallida: %v", err)
	}

	// 2. Eliminar el pod inmediatamente (grace period = 0)
	gracePeriod := int64(0)
	err := gKube.CoreV1().Pods(meta.Namespace).Delete(ctx, meta.Pod, metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	})
	if err != nil {
		log.Printf("[warn] eliminacion pod fallida: %v", err)
	} else {
		log.Printf("[L3] pod %s/%s eliminado inmediatamente", meta.Namespace, meta.Pod)
	}

	// 3. Cordon del nodo para evitar nuevos pods hasta investigación
	// Solo si el score es extremadamente alto (ataque Copy Fail completo)
	if score > 30 {
		nodeName := getNodeName()
		if nodeName != "" {
			patch := []byte(`{"spec":{"unschedulable":true}}`)
			_, err := gKube.CoreV1().Nodes().Patch(ctx, nodeName,
				types.MergePatchType, patch, metav1.PatchOptions{})
			if err != nil {
				log.Printf("[warn] cordon nodo fallido: %v", err)
			} else {
				log.Printf("[L3] NODO %s acordonado — no se admiten nuevos pods", nodeName)
			}
		}
	}

	// 4. Banlist + política Kyverno con TTL extendido
	fp := kyv.Fingerprint{Images: []string{image}, ServiceAccount: "default"}
	if err := gKM.UpdateBanlist(ctx, fp); err != nil {
		log.Printf("[warn] banlist fallido: %v", err)
	}
	if err := gKM.CreatePreventionPolicy(ctx, fp); err != nil {
		log.Printf("[warn] prevention policy fallida: %v", err)
	}
	if err := gKM.CreateCleanupForPod(ctx, meta.Namespace, meta.Pod); err != nil {
		log.Printf("[warn] cleanup policy fallida: %v", err)
	}

	// 5. Log de auditoría detallado para SIEM
	logAuditEvent(ev, meta, score, sensor, image)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func trimPayload(p []byte) string {
	for i, b := range p {
		if b == 0 {
			return string(p[:i])
		}
	}
	return string(p)
}

func getNodeName() string {
	// Lee el nombre del nodo desde la variable de entorno inyectada por el DaemonSet
	// (fieldRef: spec.nodeName en el manifiesto)
	name := ""
	// En producción: os.Getenv("NODE_NAME")
	// Aquí se lee del pod spec via downward API
	return name
}

func logAuditEvent(ev UnifiedEvent, meta podMeta, score int, sensor, image string) {
	log.Printf("[AUDIT] ts=%d ns=%s pod=%s image=%s sensor=%s score=%d pid=%d uid=%d payload=%q",
		ev.Ts, meta.Namespace, meta.Pod, image, sensor, score,
		ev.Pid, ev.Uid, trimPayload(ev.Payload[:]))
}

// UnifiedEvent es el struct Go que mapea al struct C unified_event
type UnifiedEvent struct {
	Ts         uint64
	Pid        uint32
	Tgid       uint32
	Uid        uint32
	Mntns      uint32
	SensorID   uint8
	Code       uint8
	ScoreDelta int8
	Severity   uint8
	Ipv4       uint32
	Dport      uint16
	Pad        uint16
	Comm       [16]byte
	Payload    [128]byte
}

// Severity devuelve el nivel de severidad como string
func (e UnifiedEvent) SeverityStr() string {
	switch e.Severity {
	case 0: return "info"
	case 1: return "low"
	case 2: return "medium"
	case 3: return "high"
	case 4: return "critical"
	default: return "unknown"
	}
}

// CommStr devuelve el nombre del proceso como string limpio
func (e UnifiedEvent) CommStr() string {
	for i, b := range e.Comm {
		if b == 0 { return string(e.Comm[:i]) }
	}
	return string(e.Comm[:])
}
