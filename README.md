# Agente eBPF de Seguridad para Kubernetes

Agente de seguridad en tiempo real basado en eBPF, desplegado como DaemonSet en Kubernetes. Detecta ataques en contenedores (privilege escalation, reverse shell, CVE-2026-31431, DNS exfiltración, cryptominers), responde automáticamente con políticas de Kyverno y genera alertas vía Grafana + correo electrónico.

## Requisitos previos

### Hardware / VMs
- 2 VMs Ubuntu 22.04 LTS con al menos 4 GB RAM y 20 GB disco cada una
- `k8scontrol` — control plane (ejemplo: `192.168.245.136`)
- `k8s-worker` — worker (ejemplo: `192.168.245.137`)
- Ambas VMs deben verse entre sí por red

### Software a instalar antes de empezar

**En ambas VMs:**
```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

# Instalar containerd
sudo apt-get install -y containerd
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd

# Instalar kubeadm, kubelet, kubectl
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet=1.30.14-1.1 kubeadm=1.30.14-1.1 kubectl=1.30.14-1.1
sudo apt-mark hold kubelet kubeadm kubectl

# Deshabilitar swap
sudo swapoff -a
sudo sed -i '/swap/d' /etc/fstab

# Habilitar módulos de red
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sudo sysctl --system
```

**Solo en el control plane:**
```bash
# nerdctl + buildkitd para construir imágenes
wget https://github.com/containerd/nerdctl/releases/download/v1.7.6/nerdctl-1.7.6-linux-amd64.tar.gz
sudo tar -C /usr/local/bin -xzf nerdctl-1.7.6-linux-amd64.tar.gz

# Herramientas de compilación eBPF
sudo apt-get install -y clang llvm make pkg-config git build-essential \
  libelf-dev zlib1g-dev linux-tools-$(uname -r)
```

---

## Instalación paso a paso

### 1. Inicializar el clúster Kubernetes

**En el control plane:**
```bash
sudo kubeadm init --pod-network-cidr=10.244.0.0/16 --apiserver-advertise-address=<IP-CONTROL-PLANE>
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

**En el worker** (con el comando que genera `kubeadm init`):
```bash
sudo kubeadm join <IP-CONTROL-PLANE>:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash>
```

### 2. Instalar Flannel CNI

**En el control plane:**
```bash
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
```

**Instalar servicios de persistencia de red Flannel:**

> **Importante**: edita las IPs y MACs antes de copiar. Obtén las MACs con `ip -d link show flannel.1 | grep link/ether` en cada nodo (hay que esperar a que Flannel haya creado `flannel.1` tras el primer arranque).

```bash
# En el control plane
sudo cp deploy/systemd/flannel-subnet.service /etc/systemd/system/
sudo cp deploy/systemd/flannel-route-control.service /etc/systemd/system/
# Edita las MACs e IPs en ambos ficheros
sudo nano /etc/systemd/system/flannel-subnet.service
sudo nano /etc/systemd/system/flannel-route-control.service
sudo systemctl daemon-reload
sudo systemctl enable --now flannel-subnet.service flannel-route-control.service

# En el worker
sudo cp deploy/systemd/flannel-subnet.service /etc/systemd/system/
sudo cp deploy/systemd/flannel-route-worker.service /etc/systemd/system/
# Edita las MACs e IPs
sudo nano /etc/systemd/system/flannel-subnet.service
sudo nano /etc/systemd/system/flannel-route-worker.service
sudo systemctl daemon-reload
sudo systemctl enable --now flannel-subnet.service flannel-route-worker.service
```

### 3. Instalar Kyverno v1.12.0

```bash
curl -sL https://github.com/kyverno/kyverno/releases/download/v1.12.0/install.yaml \
  -o /tmp/kyverno-install.yaml

# Ampliar exclusiones de namespaces (evita bloqueos en el arranque)
python3 deploy/scripts/patch-kyverno-install.py /tmp/kyverno-install.yaml

kubectl apply -f /tmp/kyverno-install.yaml --server-side --force-conflicts
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=admission-controller \
  -n kyverno --timeout=120s
```

### 4. Instalar servicios systemd adicionales

**En el control plane:**
```bash
sudo cp deploy/systemd/k8s-post-boot.service /etc/systemd/system/
sudo cp deploy/systemd/disk-cleanup-control.service /etc/systemd/system/disk-cleanup.service
sudo cp deploy/systemd/disk-cleanup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now k8s-post-boot.service disk-cleanup.timer
```

### 5. Clonar el repositorio y compilar

```bash
git clone https://github.com/00000000000001-tfm/agente-ebpf-k8s.git agente_ebpf_k8s
cd agente_ebpf_k8s

# Generar vmlinux.h del kernel actual
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Compilar agente Go
go build -o build/agent ./cmd/agent/

# Compilar sensores eBPF (opcional si usas los .bpf.o de GitHub Releases)
make -e TARGETOS=linux TARGETARCH=amd64 programas
```

### 6. Importar imágenes desde GitHub Releases

Descarga los `.tar` de la release v3.0 y en el worker:

```bash
# En el control plane
sudo nerdctl load -i agente-ebpf-v3.tar
sudo nerdctl save agente-ebpf:v3 -o /tmp/agente-ebpf-v3.tar
scp /tmp/agente-ebpf-v3.tar ubuntu@<IP-WORKER>:/tmp/

# En el worker — importar agente y PoCs
for f in agente-ebpf-v3 rs-attacker rs-listener copyfail-poc victima-test miner-poc; do
  sudo ctr -n k8s.io images import /tmp/${f}.tar
done
```

### 7. Desplegar el agente

```bash
kubectl apply -f manifests/00-namespace.yaml
kubectl apply -f manifests/01-rbac.yaml
kubectl apply -f rbac/
kubectl apply -f manifests/10-daemonset.yaml
kubectl rollout status daemonset/perpod-ebpf-agent -n security
```

### 8. Desplegar monitorización

```bash
# StorageClass para persistencia de Grafana
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
kubectl patch storageclass local-path \
  -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

# Secret SMTP — introducir manualmente, NO está en el repo
kubectl create secret generic grafana-smtp -n security \
  --from-literal=smtp_user=<tu-correo@gmail.com> \
  --from-literal=smtp_password=<contraseña-de-aplicacion-gmail>

# Desplegar Prometheus y Grafana
kubectl apply -f manifests/monitoring/
kubectl rollout status deployment/grafana -n security
kubectl rollout status deployment/prometheus -n security
```

Grafana disponible en `http://<IP-CONTROL-PLANE>:30300` (admin / ebpf-admin).

### 9. Verificar y ejecutar el pentest

```bash
bash deploy/scripts/check-health.sh
bash deploy/scripts/run-pentest.sh
```

---

## Estructura del repositorio

```bash
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
│   ├── scripts/            # check-health.sh, run-pentest.sh, patch-kyverno-install.py
│   └── systemd/            # Servicios systemd para persistencia
├── docs/
│   └── informe_proyecto.md # Informe técnico completo
├── Dockerfile              # Build completo (requiere clang/llvm)
├── Dockerfile.prebuilt     # Build con binarios precompilados
└── Makefile
```

---

## Credenciales por defecto

| Servicio | Usuario | Contraseña |
|---|---|---|
| Grafana | admin | ebpf-admin |

> Las credenciales SMTP **no están en el repo** — introducirlas manualmente en el paso 8.

---

## Documentación técnica

Ver `docs/informe_proyecto.md` para la documentación completa: decisiones de diseño, incidencias encontradas durante el desarrollo y el incidente de puesta en producción, y soluciones aplicadas.
