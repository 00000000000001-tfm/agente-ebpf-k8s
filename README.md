# Agente eBPF de Seguridad para Kubernetes

Agente de seguridad en tiempo real basado en eBPF, desplegado como DaemonSet en Kubernetes. Detecta ataques en contenedores (privilege escalation, reverse shell, CVE-2026-31431, DNS exfiltración, cryptominers), responde automáticamente con políticas de Kyverno y genera alertas vía Grafana + correo electrónico.

## Arquitectura
Sensores eBPF (C) → Agente Go → Correlator → Responder
↓
L1: log   L2: NetworkPolicy + ClusterPolicy   L3: SIGKILL + cordon
↓
Prometheus → Grafana → Email

## Requisitos previos

- 2 VMs Ubuntu 22.04: `k8scontrol` (control plane) y `k8s-worker` (worker)
- Kubernetes v1.30 con kubeadm
- Flannel CNI
- Kyverno v1.12.0
- `nerdctl` + `buildkitd` en el control plane
- `clang`, `llvm`, `libbpf-dev`, `bpftool`, `make` para compilar los sensores eBPF

## Despliegue desde cero

### 1. Clonar el repositorio

```bash
git clone <url-repo> agente_ebpf_k8s
cd agente_ebpf_k8s
```

### 2. Instalar servicios systemd en el control plane

```bash
sudo cp deploy/systemd/flannel-subnet.service /etc/systemd/system/
sudo cp deploy/systemd/flannel-route-control.service /etc/systemd/system/
sudo cp deploy/systemd/k8s-post-boot.service /etc/systemd/system/
sudo cp deploy/systemd/disk-cleanup-control.service /etc/systemd/system/disk-cleanup.service
sudo cp deploy/systemd/disk-cleanup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable flannel-subnet.service flannel-route-control.service k8s-post-boot.service disk-cleanup.timer
```

> **Nota**: edita `flannel-subnet.service` y `flannel-route-control.service` con las IPs y MACs de tus nodos antes de activarlos.

### 3. Instalar servicios systemd en el worker

```bash
# En k8s-worker:
sudo cp deploy/systemd/flannel-subnet.service /etc/systemd/system/
# Copiar también flannel-route-worker.service (ver sección 4.12 del informe)
sudo systemctl daemon-reload
sudo systemctl enable flannel-subnet.service flannel-route-worker.service
```

### 4. Instalar Kyverno

```bash
curl -sL https://github.com/kyverno/kyverno/releases/download/v1.12.0/install.yaml -o /tmp/kyverno-install.yaml

# Ampliar exclusiones de namespaces (ver sección 8.6 del informe)
python3 deploy/scripts/patch-kyverno-install.py /tmp/kyverno-install.yaml

kubectl apply -f /tmp/kyverno-install.yaml --server-side --force-conflicts
```

### 5. Compilar el agente

```bash
# Generar vmlinux.h del kernel actual
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Compilar sensores eBPF y agente Go
make -e TARGETOS=linux TARGETARCH=amd64 programas

# O solo el agente Go (si los .bpf.o ya existen)
go build -o build/agent ./cmd/agent/
```

### 6. Construir e importar la imagen del agente

```bash
# En el control plane
sudo nerdctl build -f Dockerfile.prebuilt -t agente-ebpf:v3 .
sudo nerdctl save agente-ebpf:v3 -o agente-ebpf-v3.tar
scp agente-ebpf-v3.tar ubuntu@<ip-worker>:/tmp/

# En el worker
sudo ctr -n k8s.io images import /tmp/agente-ebpf-v3.tar
```

### 7. Construir e importar imágenes de PoCs

```bash
# En el control plane — construir cada PoC
for poc in pocs/rs-attacker pocs/rs-listener pocs/copyfail-poc pocs/build-victima; do
  name=$(basename $poc)
  sudo nerdctl build -t $name:latest $poc/
  sudo nerdctl save $name:latest -o ${name}.tar
  scp ${name}.tar ubuntu@<ip-worker>:/tmp/
done

# En el worker — importar
for poc in rs-attacker rs-listener copyfail-poc victima-test; do
  sudo ctr -n k8s.io images import /tmp/${poc}.tar
done
```

### 8. Desplegar el agente en Kubernetes

```bash
kubectl apply -f manifests/00-namespace.yaml
kubectl apply -f manifests/01-rbac.yaml
kubectl apply -f rbac/
kubectl apply -f manifests/10-daemonset.yaml
```

### 9. Desplegar monitorización (Prometheus + Grafana)

```bash
# Instalar StorageClass local
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
kubectl patch storageclass local-path \
  -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

# Crear secret SMTP (introducir credenciales manualmente — NO se guardan en el repo)
kubectl create secret generic grafana-smtp -n security \
  --from-literal=smtp_user=<tu-correo@gmail.com> \
  --from-literal=smtp_password=<contraseña-de-aplicacion-gmail>

# Desplegar
kubectl apply -f manifests/monitoring/
```

### 10. Verificar el despliegue

```bash
bash deploy/scripts/check-health.sh
```

### 11. Ejecutar el pentest

```bash
bash deploy/scripts/run-pentest.sh
```

## Estructura del repositorio
├── bpf/                    # Sensores eBPF en C
├── cmd/agent/              # Agente principal en Go
│   ├── main.go
│   ├── correlator.go       # Motor de correlación y scoring
│   ├── responder.go        # Respuesta graduada L1/L2/L3
│   ├── metrics.go          # Métricas Prometheus
│   └── reverse_shell.go
├── internal/kyverno/       # Integración con Kyverno
├── manifests/              # Manifiestos Kubernetes del agente
│   └── monitoring/         # Prometheus + Grafana
├── rbac/                   # ClusterRoles y bindings
├── policies/               # ClusterPolicies base de Kyverno
├── pocs/                   # Código fuente de los PoCs de ataque
├── test/                   # Pods de prueba para el pentest
├── deploy/
│   ├── scripts/            # check-health.sh, run-pentest.sh
│   └── systemd/            # Servicios systemd para persistencia
├── docs/
│   └── informe_proyecto.md # Informe técnico completo
├── Dockerfile              # Build completo (requiere clang/llvm)
├── Dockerfile.prebuilt     # Build con binarios precompilados
└── Makefile

## Credenciales por defecto

| Servicio | Usuario | Contraseña |
|---|---|---|
| Grafana | admin | ebpf-admin |
| Kubernetes | — | kubeconfig en `/home/ubuntu/.kube/config` |

> Las credenciales SMTP de Gmail **no están en el repo** — hay que introducirlas manualmente (paso 9).

## Documentación

Ver `docs/informe_proyecto.md` para la documentación técnica completa, incluyendo todas las decisiones de diseño, incidencias encontradas y soluciones aplicadas.
