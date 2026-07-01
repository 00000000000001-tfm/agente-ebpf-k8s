package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	metricEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_events_total",
		Help: "Total de eventos detectados por sensor",
	}, []string{"sensor"})

	metricPodScore = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_pod_score",
		Help: "Score de correlacion actual por pod",
	}, []string{"mntns", "image"})

	metricIncidentsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_incidents_total",
		Help: "Total de incidentes por nivel",
	}, []string{"level"})

	metricClusterPolicies = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_clusterpolicies_active",
		Help: "ClusterPolicies activas creadas por el agente",
	})

	metricNodesReady = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_cluster_nodes_ready",
		Help: "Nodos en estado Ready en el cluster",
	})
)

func startMetricsServer() {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	log.Println("[metrics] servidor en :9090/metrics")
	go func() {
		if err := http.ListenAndServe(":9090", nil); err != nil {
			log.Fatalf("[metrics] error: %v", err)
		}
	}()
}

func startClusterMetricsLoop() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("[metrics] no in-cluster config, metricas de cluster desactivadas: %v", err)
		return
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Printf("[metrics] error creando cliente k8s: %v", err)
		return
	}
	go func() {
		for {
			// Nodos Ready
			nodes, err := client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			if err == nil {
				ready := 0
				for _, n := range nodes.Items {
					for _, c := range n.Status.Conditions {
						if c.Type == "Ready" && c.Status == "True" {
							ready++
						}
					}
				}
				metricNodesReady.Set(float64(ready))
			}

			// ClusterPolicies activas
			cp, err := client.RESTClient().Get().
				AbsPath("/apis/kyverno.io/v1/clusterpolicies").
				DoRaw(context.Background())
			if err == nil && cp != nil {
				var result map[string]interface{}
				if json.Unmarshal(cp, &result) == nil {
					if items, ok := result["items"].([]interface{}); ok {
						metricClusterPolicies.Set(float64(len(items)))
					}
				}
			}

			time.Sleep(5 * time.Second)
		}
	}()
}
