#!/usr/bin/env python3
"""
patch-kyverno-install.py — Amplía las exclusiones de namespaceSelector en el
ConfigMap de Kyverno para incluir kube-node-lease y kube-flannel, evitando
que el webhook bloquee el arranque del clúster.

Uso: python3 patch-kyverno-install.py /tmp/kyverno-install.yaml
"""
import sys

if len(sys.argv) != 2:
    print(f"Uso: {sys.argv[0]} <kyverno-install.yaml>")
    sys.exit(1)

path = sys.argv[1]

with open(path) as f:
    content = f.read()

old = (
    '{\\"key\\":\\"kubernetes.io/metadata.name\\",'
    '\\"operator\\":\\"NotIn\\",'
    '\\"values\\":[\\"kyverno\\"]}],'
    '\\"matchLabels\\":null}}]'
)

new = (
    '{\\"key\\":\\"kubernetes.io/metadata.name\\",'
    '\\"operator\\":\\"NotIn\\",'
    '\\"values\\":[\\"kyverno\\"]},'
    '{\\"key\\":\\"kubernetes.io/metadata.name\\",'
    '\\"operator\\":\\"NotIn\\",'
    '\\"values\\":[\\"kube-node-lease\\"]},'
    '{\\"key\\":\\"kubernetes.io/metadata.name\\",'
    '\\"operator\\":\\"NotIn\\",'
    '\\"values\\":[\\"kube-flannel\\"]}],'
    '\\"matchLabels\\":null}}]'
)

if old not in content:
    print("WARN: patron no encontrado — puede que la version de Kyverno sea diferente")
    print("Revisa manualmente el campo data.webhooks en el ConfigMap kyverno")
    sys.exit(0)

content = content.replace(old, new, 1)

with open(path, "w") as f:
    f.write(content)

print(f"OK: exclusiones ampliadas en {path}")
print("Namespaces excluidos: kube-system, kyverno, kube-node-lease, kube-flannel")
