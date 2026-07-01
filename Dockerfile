FROM golang:1.24-bookworm AS builder
ARG TARGETOS TARGETARCH
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm make pkg-config git ca-certificates build-essential \
    libelf-dev zlib1g-dev bpftool libbpf-dev && rm -rf /var/lib/apt/lists/*

COPY go.mod ./
RUN go mod download || true

COPY cmd/ cmd/
COPY internal/ internal/
COPY bpf/ bpf/
COPY Makefile .

RUN go mod tidy

RUN make -e TARGETOS=linux TARGETARCH=amd64 programas

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /opt/agent
COPY --from=builder /src/build/agent ./agent
COPY --from=builder /src/build/monitor.bpf.o ./monitor.bpf.o
COPY --from=builder /src/build/privilege_escalation.bpf.o ./privilege_escalation.bpf.o
COPY --from=builder /src/build/reverse_shell_detector.bpf.o ./reverse_shell_detector.bpf.o
COPY --from=builder /src/build/copy_fail.bpf.o ./copy_fail.bpf.o
COPY --from=builder /src/build/dns_exfil.bpf.o ./dns_exfil.bpf.o
COPY --from=builder /src/build/cryptominer.bpf.o ./cryptominer.bpf.o

USER 65532:65532
ENTRYPOINT ["/opt/agent/agent"]
