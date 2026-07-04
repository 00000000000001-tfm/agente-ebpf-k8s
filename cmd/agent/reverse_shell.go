package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"syscall"
	"time"

	ebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	rb "github.com/cilium/ebpf/ringbuf"
)

var quarantineMins int = 15

type rsEvent struct {
	Ts    uint64
	Pid   uint32
	Tgid  uint32
	Uid   uint32
	Mntns uint32
	Code  uint32
	Arg   uint32
	IPv4  uint32
	Comm  [16]byte
	Exe   [64]byte
}

const (
	rsConnectExternal = 1
	rsDupStdFD        = 2
	rsExecSuspect     = 3
)

var (
	rsWeights = map[uint32]int{
		rsConnectExternal: 5,
		rsDupStdFD:        8,
		rsExecSuspect:     4,
	}
	rsThreshold  = 12
	rsDecayEvery = 20 * time.Second
	rsCooldown   = 15 * time.Second
	rsDebounce   = 2 * time.Second

	rsScores   = map[uint32]int{}
	rsLastTime = map[uint32]time.Time{}
	rsLastCode = map[uint32]map[uint32]time.Time{}
	rsCooling  = map[uint32]time.Time{}
)

type rsSensor struct {
	coll  *ebpf.Collection
	links []link.Link
	ring  *rb.Reader
	wlMap *ebpf.Map
}

func (s *rsSensor) Close() {
	if s == nil {
		return
	}
	if s.ring != nil {
		_ = s.ring.Close()
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
}

func startReverseShellSensor(objPath string) (*rsSensor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("Error al cargar eBPF: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("Error en leer coleccion: %w", err)
	}

	links := []link.Link{}

	attachRaw := func(event, progName string) error {
		p := coll.Programs[progName]
		if p == nil {
			return fmt.Errorf("sensor %s no encontrado", progName)
		}
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    event,
			Program: p,
		})
		if err != nil {
			return fmt.Errorf("error raw tracepoint %s: %w", event, err)
		}
		links = append(links, l)
		return nil
	}

	if err := attachRaw("sys_enter", "rs_enter_connect"); err != nil {
		coll.Close()
		return nil, err
	}
	if err := attachRaw("sys_enter", "rs_dup2"); err != nil {
		coll.Close()
		return nil, err
	}
	if err := attachRaw("sys_enter", "rs_execve"); err != nil {
		coll.Close()
		return nil, err
	}

	ring, err := rb.NewReader(coll.Maps["rs_events"])
	if err != nil {
		for _, l := range links {
			_ = l.Close()
		}
		coll.Close()
		return nil, fmt.Errorf("Error en Ringbuf: %w", err)
	}

	wl := coll.Maps["watchlist"]
	log.Printf("[agent] sensor reverse-shell cargado.")
	return &rsSensor{
		coll:  coll,
		links: links,
		ring:  ring,
		wlMap: wl,
	}, nil
}

func (s *rsSensor) addWatch(mntns uint32) error {
	if s == nil || s.wlMap == nil {
		return nil
	}
	var one uint8 = 1
	return s.wlMap.Update(&mntns, &one, ebpf.UpdateAny)
}

func readReverseShellRing(ctx context.Context, s *rsSensor) {
	defer s.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := s.ring.Read()
		if err != nil {
			if errors.Is(err, rb.ErrClosed) || errors.Is(err, syscall.EINTR) {
				return
			}
			continue
		}

		if len(rec.RawSample) < int(binary.Size(rsEvent{})) {
			continue
		}

		var ev rsEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		meta := lookupMeta(ev.Mntns)
		comm := cstr(ev.Comm[:])
		exe := cstr(ev.Exe[:])

		w := rsWeights[ev.Code]

		scoreMu.Lock()
		now := time.Now()

		// Cooldown activo
		if until, ok := rsCooling[ev.Mntns]; ok && now.Before(until) {
			scoreMu.Unlock()
			continue
		}

		// Debounce por código
		if rsLastCode[ev.Mntns] == nil {
			rsLastCode[ev.Mntns] = map[uint32]time.Time{}
		}
		if t, ok := rsLastCode[ev.Mntns][ev.Code]; ok && now.Sub(t) < rsDebounce {
			scoreMu.Unlock()
			continue
		}
		rsLastCode[ev.Mntns][ev.Code] = now

		// Decay del score
		if t, ok := rsLastTime[ev.Mntns]; ok && now.Sub(t) > rsDecayEvery {
			rsScores[ev.Mntns] = 0
		}
		rsLastTime[ev.Mntns] = now
		rsScores[ev.Mntns] += w
		sc := rsScores[ev.Mntns]
		scoreMu.Unlock()

		switch ev.Code {
		case rsConnectExternal:
			ip := fmt.Sprintf("%d.%d.%d.%d",
				ev.IPv4>>24, (ev.IPv4>>16)&0xff,
				(ev.IPv4>>8)&0xff, ev.IPv4&0xff)
			log.Printf("[rs] ns=%s pod=%s mntns=%d pid=%d comm=%s exec=%s (+%d) score=%d dst=%s:%d",
				meta.Namespace, meta.Pod, ev.Mntns, ev.Pid, comm, exe, w, sc, ip, ev.Arg)
		case rsDupStdFD:
			log.Printf("[rs] ns=%s pod=%s mntns=%d pid=%d comm=%s dup stdfd=%d (+%d) score=%d",
				meta.Namespace, meta.Pod, ev.Mntns, ev.Pid, comm, ev.Arg, w, sc)
		case rsExecSuspect:
			log.Printf("[rs] ns=%s pod=%s mntns=%d pid=%d comm=%s exec=%s (+%d) score=%d",
				meta.Namespace, meta.Pod, ev.Mntns, ev.Pid, comm, exe, w, sc)
		}

		metricEventsTotal.WithLabelValues("rs").Inc()
		corrLevel := gCorrelator.AddEvent(ev.Mntns, SENSOR_RS, uint8(ev.Code), int8(w), meta.Image, cstr(ev.Comm[:]))
                if corrLevel > 0 {
                        log.Printf("[ALERT] POSIBLE REVERSE SHELL: ns=%s pod=%s mntns=%d score=%d",
                                meta.Namespace, meta.Pod, ev.Mntns, sc)

                        ns, pod := meta.Namespace, meta.Pod
                        level := corrLevel
                        go func(ns, pod string, level int) {
                                if err := handleIncidentLevel(context.Background(), ns, pod, level); err != nil {
                                        log.Printf("[warn] incidente->kyverno ns=%s pod=%s: %v", ns, pod, err)
                                }
                        }(ns, pod, level)

                        scoreMu.Lock()
                        rsScores[ev.Mntns] = 0
                        rsCooling[ev.Mntns] = time.Now().Add(rsCooldown)
                        scoreMu.Unlock()
                }
	}
}
