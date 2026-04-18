# syntax=docker/dockerfile:1.6

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /workspace

ARG TARGETOS
ARG TARGETARCH

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-$(go env GOOS)} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
    go build -trimpath -ldflags="-s -w" -o manager ./main.go

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot

ARG VCS_REF=unknown
ARG VERSION=unknown
ARG BUILD_DATE=unknown
LABEL maintainer="courseproduction@bcit.ca"
LABEL org.opencontainers.image.description="Kubernetes operator that reconciles HAProxy configuration via the Dataplane API."
LABEL org.opencontainers.image.source="https://github.com/bcit-tlu/haproxy-operator" \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.title="haproxy-operator"

WORKDIR /

COPY --from=builder /workspace/manager .

USER 65532:65532

ENTRYPOINT ["/manager"]
