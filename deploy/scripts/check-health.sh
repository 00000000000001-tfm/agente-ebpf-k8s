#!/bin/bash
# check-health.sh — Verificación de salud del clúster tras arranque
# Uso: bash check-health.sh

set +e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FALLO]${NC} $1"; }
warn() { echo -e "${YELLOW}[AVISO]${NC} $1"; }

echo "=================================================="
echo "  VERIFICACION DE SALUD DEL CLUSTER"
echo "=================================================="

# 1. Nodos
echo -e "\n--- 1. Nodos ---"
NODES_NOT_READY=$(kubectl get nodes --no-headers | grep -v " Ready " | wc -l)
kubectl get nodes
if [ "$NODES_NOT_READY" -eq 0 ]; then ok "Todos los nodos Ready"; else fail "Hay nodos no Ready"; fi

# 2. CoreDNS
echo -e "\n--- 2. CoreDNS ---"
kubectl get pods -n kube-system -l k8s-app=kube-dns
COREDNS_BAD=$(kubectl get pods -n kube-system -l k8s-app=kube-dns --no-headers | grep -vc "1/1.*Running")
if [ "$COREDNS_BAD" -eq 0 ]; then ok "CoreDNS sano"; else fail "CoreDNS con problemas — ejecuta: kubectl rollout restart daemonset kube-proxy -n kube-system"; fi

# 3. Ruta Flannel (control plane)
echo -e "\n--- 3. Red Flannel ---"
if ip route | grep -q "10.244.1.0/24"; then ok "Ruta hacia worker presente"; else fail "Falta ruta 10.244.1.0/24 — revisa flannel-route-worker.service"; fi
if ip addr show flannel.1 2>/dev/null | grep -q "10.244.0.0/32"; then ok "IP flannel.1 asignada"; else warn "flannel.1 sin IP propia"; fi

# 4. Kyverno pods
echo -e "\n--- 4. Kyverno ---"
kubectl get pods -n kyverno | grep -v ImagePullBackOff
KYVERNO_BAD=$(kubectl get pods -n kyverno --no-headers | grep -v ImagePullBackOff | grep -vc "1/1.*Running")
if [ "$KYVERNO_BAD" -eq 0 ]; then ok "Kyverno sano"; else fail "Kyverno con pods caídos — ejecuta: kubectl rollout restart deployment -n kyverno"; fi

# 5. Webhook de validación CRITICO
echo -e "\n--- 5. Webhook Kyverno (critico) ---"
CPOL_COUNT=$(kubectl get clusterpolicy --no-headers 2>/dev/null | wc -l)
WH_RULES=$(kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg -o jsonpath='{.webhooks[0].rules}' 2>/dev/null)
if [ "$CPOL_COUNT" -eq 0 ]; then
    ok "Sin ClusterPolicy activas - webhook sin reglas es lo esperado"
elif [ -n "$WH_RULES" ]; then
    ok "Webhook de validacion tiene reglas activas ($CPOL_COUNT politicas)"
else
    fail "Hay $CPOL_COUNT ClusterPolicy activas pero el webhook SIN reglas — Kyverno no bloqueara nada. Ejecuta: kubectl delete validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg"
fi

# 6. Anotacion de bypass (CRITICO - causa raiz que tuvimos)
ANNOT=$(kubectl get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg -o yaml 2>/dev/null | grep "admissions.enforcer")
if [ -z "$ANNOT" ]; then
    ok "Sin anotacion de bypass enforcer"
else
    warn "Anotacion admissions.enforcer presente (default de fabrica de Kyverno v1.12, no es el bug original)"
fi

# 7. Conectividad real a Kyverno
echo -e "\n--- 6. Conectividad a Kyverno ---"
KYV_IP=$(kubectl get endpoints -n kyverno kyverno-svc -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null)
if [ -n "$KYV_IP" ]; then
    if curl -sk --connect-timeout 5 "https://${KYV_IP}:9443/health/liveness" -o /dev/null -w "%{http_code}" | grep -q 200; then
        ok "Kyverno responde en https://${KYV_IP}:9443"
    else
        fail "Kyverno no responde en ${KYV_IP}:9443"
    fi
else
    fail "Sin endpoint de Kyverno disponible"
fi

# 8. Agente eBPF
echo -e "\n--- 7. Agente eBPF ---"
kubectl get pods -n security
AGENT_BAD=$(kubectl get pods -n security --no-headers 2>/dev/null | grep -vc "1/1.*Running")
if [ "$AGENT_BAD" -eq 0 ]; then ok "Agente eBPF Running"; else fail "Agente eBPF con problemas"; fi

SENSORS=$(kubectl logs -n security daemonset/perpod-ebpf-agent 2>/dev/null | grep -c "sensor.*cargado")
echo "Sensores cargados detectados en logs: $SENSORS / 5"
if [ "$SENSORS" -ge 5 ]; then ok "Los 5 sensores cargaron"; else warn "Menos de 5 sensores — revisa logs del agente"; fi

echo -e "\n=================================================="
echo "  VERIFICACION COMPLETADA"
echo "=================================================="
