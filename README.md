# haproxy-operator

Kubernetes operator that reconciles HAProxy configuration via the [Dataplane API](https://www.haproxy.com/documentation/dataplaneapi/latest/).

Designed for a GitOps workflow where infrastructure operators commit `haproxy.cfg` changes to a private GitHub repository. [FluxCD](https://fluxcd.io/) watches the repo and syncs the config into a Kubernetes Secret. The operator detects changes, validates the configuration, and applies it to a production HAProxy load balancer — fully automated, with accept/reject feedback via Kubernetes Events.

## Architecture

```
┌─────────────────────────┐      poll            ┌──────────────────────┐
│  GitHub Repo            │◄────────────────────│  FluxCD              │
│  (haproxy.cfg)          │   GitRepository     │  (K8s cluster)       │
└─────────────────────────┘                     │  Kustomization       │
                                                │  → K8s Secret        │
                                                └──────────┬───────────┘
                                                           │ watch
                                                ┌──────────▼───────────┐
                                                │  haproxy-operator    │
                                                │  1. Detect change    │
                                                │  2. Validate config  │
                                                │  3. Apply via DPAPI  │
                                                │  4. Emit K8s Event   │
                                                └──────────┬───────────┘
                                                           │ mTLS (SPIRE)
                                                ┌──────────▼───────────┐
                                                │  HAProxy LB          │
                                                │  (Dataplane API)     │
                                                └──────────────────────┘
```

## Features

- **GitOps-native**: FluxCD polls Git and syncs haproxy.cfg into a Kubernetes Secret
- **One-way architecture**: Clusters are not publicly accessible — Flux pulls from GitHub; no direct cluster-to-external communication is required
- **Config validation**: Pre-validates `haproxy.cfg` via the Dataplane API `only_validate` endpoint before applying
- **SPIFFE/SPIRE mTLS**: Automatic workload identity and certificate rotation between K8s and the bare-metal load balancer
- **Vault PKI (VSO)**: Alternative to SPIRE — VaultPKISecret issues the operator's mTLS client cert (destination keys `ca.crt`/`tls.crt`/`tls.key`) and VaultStaticSecret syncs Dataplane Basic Auth; both rotate automatically
- **Static TLS**: Alternative to SPIRE/VSO — mount cert files from a pre-provisioned Secret (`dataplane.tls.existingSecret`)
- **Typed failure handling**: Dataplane errors are classified (ConfigRejected / AuthError / TLSConnectionError / ConnectionError / ConflictError / RateLimited / DataplaneServerError). Only deterministic rejections suppress the desired config hash — transient failures retry the same bytes with bounded exponential backoff
- **Patch-scoped status**: Secret annotations are written via merge patch, so Flux-owned annotations are never clobbered; Event/annotation messages are sanitized and bounded
- **Credential-aware readiness**: `/readyz` proves the mounted credentials and an authenticated Dataplane read; `/healthz` stays process-local
- **Environment promotion**: `latest` (dev) → `stable` (production) using Flux Kustomize overlays
- **Kubernetes Events**: Accept/reject status emitted as Events on the config Secret for observability
- **Leader election**: Safe multi-replica deployment with controller-runtime leader election

## Modes

| Mode | Source | Use Case |
|------|--------|----------|
| `k8s` (default) | Kubernetes Secret | Production — Flux syncs config from Git into a Secret |
| `local` | File on disk | Development — watches a local `haproxy.cfg` file |

## Quick Start (Local Development)

```bash
docker compose up --build
```

This starts HAProxy with the Dataplane API, the operator in `local` mode, and sample backend services. Edit `dev/external-haproxy-service/haproxy.cfg` and the operator automatically validates and applies changes.

Verify:
```bash
curl http://localhost:8080    # Traffic through HAProxy
curl http://localhost:8404    # HAProxy stats
```

## Configuration

| Flag / Env Var | Default | Description |
|---|---|---|
| `--mode` / `MODE` | `k8s` | Run mode: `k8s` or `local` |
| `--namespace` / `WATCH_NAMESPACE` | `haproxy-operator` | K8s namespace to watch |
| `--secret-name` / `SECRET_NAME` | `haproxy-config` | Secret containing haproxy.cfg |
| `--secret-key` / `SECRET_KEY` | `haproxy.cfg` | Key within the Secret |
| `--certs-secret-names` / `CERTS_SECRET_NAMES` | — | Comma-separated TLS Secrets pushed to Dataplane `ssl_certificates` storage as `<name>.pem` before config validation |
| `--dataplane-url` / `DATAPLANE_URL` | `https://haproxy:5555/v3` | Dataplane API base URL |
| `--spire-socket` / `SPIRE_AGENT_SOCKET` | — | SPIRE Workload API socket |
| `--leader-elect` / `LEADER_ELECT` | `false` | Enable leader election |

See `charts/haproxy-operator/values.yaml` for the full set of Helm values.

## Metrics

Prometheus metrics are served on `--metrics-bind-address` (default `:9090`). In addition to the reconcile counters/gauges (`haproxy_operator_reconcile_*`, `haproxy_operator_config_hash`, `haproxy_operator_last_successful_apply_timestamp_seconds`), the operator exports both ends of the Dataplane mTLS session's certificate expiry:

| Metric | Labels | Source |
|---|---|---|
| `haproxy_operator_dataplane_server_cert_expiry_timestamp_seconds` | `gateway` (Dataplane hostname) | `NotAfter` of the server leaf presented on the latest TLS handshake — tracks the gateway's vault-agent-renewed leaf |
| `haproxy_operator_dataplane_client_cert_expiry_timestamp_seconds` | — | `NotAfter` of the mounted client certificate file, re-parsed every 5m — tracks VSO `VaultPKISecret` rotation |

## Security

### SPIFFE/SPIRE

When SPIRE is enabled (`spire.enabled=true`), the operator obtains X.509 SVIDs from the local SPIRE Agent for mTLS with the Dataplane API. No manual certificate distribution required — both the operator pod and the HAProxy host authenticate via their SPIFFE identities.

### Static TLS Certificates

When SPIRE is not enabled, the operator mounts TLS certificates from a Kubernetes Secret (`haproxy-operator-tls`). Pre-provision this Secret with `ca.crt`, `tls.crt`, and `tls.key` for mTLS communication with the Dataplane API.

### Frontend Certificate Sync

`--certs-secret-names` lists `kubernetes.io/tls` Secrets (same watch namespace, e.g. VSO-synced from a Vault KV path) whose `tls.crt` + `tls.key` (+ optional `ca.crt` chain) are pushed to the gateway's Dataplane `ssl_certificates` storage as `<secret-name>.pem`. Syncs run before every config validation so a `haproxy.cfg` may safely reference `crt <ssl_certs_dir>/<name>.pem`, and secret updates trigger a reload via the storage API even when the config is unchanged. Requires the Dataplane API to have `ssl_certs_dir` configured.

TLS Secrets stay strictly read-only for the operator — sync bookkeeping (`haproxy.operator/cert-sync`, a per-cert `{hash,time}` JSON map) is recorded on the config Secret, and the chart's RBAC confines Secret `update`/`patch` to that object. A re-push is skipped when the remote leaf serial and size match *and* the recorded bundle hash still matches; a restart falls back to the annotation (or, worst case, one extra GET+push cycle).

## Project Structure

```
├── main.go                          # Entrypoint
├── internal/
│   ├── config/                      # Config loader, hasher, validator
│   ├── controller/                  # K8s Secret reconciler
│   ├── haproxy/                     # Dataplane API client (mTLS, basic auth)
│   ├── local/                       # Local file-watching runner
│   ├── spire/                       # SPIFFE/SPIRE Workload API integration
│   └── status/                      # K8s Event reporter
├── charts/haproxy-operator/         # Helm chart (OCI → GHCR)
├── dev/                             # Local development assets
├── .github/workflows/               # CI/CD (test, build, sign, scan, publish)
└── docker-compose.yaml              # Local dev environment
```

## CI/CD

- **Go tests** + `go vet` on every PR
- **Helm lint** + kubeconform schema validation
- **Docker image** built, pushed to GHCR, signed with Cosign (keyless), scanned with Trivy
- **Helm chart** packaged as OCI, pushed to GHCR, signed with Cosign
- **Release Please** for automated semver and changelog
