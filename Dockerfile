# ── Build stage ──
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /tito ./cmd/tito

# ── Runtime stage ──
FROM alpine:3.19

RUN apk add --no-cache ca-certificates git python3 py3-pip && \
    pip3 install --break-system-packages semgrep && \
    adduser -D -h /home/tito tito

COPY --from=builder /tito /usr/local/bin/tito

USER tito
WORKDIR /workspace

ENTRYPOINT ["tito"]
CMD ["--help"]

LABEL org.opencontainers.image.title="TITO" \
      org.opencontainers.image.description="Threat In, Threat Out — Automated threat modeling" \
      org.opencontainers.image.source="https://github.com/Leathal1/TITO" \
      org.opencontainers.image.vendor="Leathal1" \
      org.opencontainers.image.licenses="MIT"
