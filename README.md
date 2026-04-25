# haproxy-operator

Kubernetes operator that reconciles HAProxy configuration via the [Dataplane API](https://www.haproxy.com/documentation/dataplaneapi/latest/).

Designed for a GitOps workflow where infrastructure operators commit `haproxy.cfg` changes to a private GitHub repository. [FluxCD](https://fluxcd.io/) watches the repo and syncs the config into a Kubernetes Secret. The operator detects changes, validates the configuration, and applies it to a production HAProxy load balancer — fully automated, with accept/reject feedback via Kubernetes Events.

## Architecture

```
┌─────────────────────────┐   poll / webhook    ┌──────────────────────┐
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

- **GitOps-native**: FluxCD handles Git polling, webhooks, and Secret synchronization
- **Config validation**: Pre-validates `haproxy.cfg` via the Dataplane API `only_validate` endpoint before applying
- **SPIFFE/SPIRE mTLS**: Automatic workload identity and certificate rotation between K8s and the bare-metal load balancer
- **Vault integration**: VSO (Vault Secrets Operator) for PKI certificate issuance and credential syncing
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
| `--dataplane-url` / `DATAPLANE_URL` | `https://haproxy:5555/v3` | Dataplane API base URL |
| `--spire-socket` / `SPIRE_AGENT_SOCKET` | — | SPIRE Workload API socket |
| `--leader-elect` / `LEADER_ELECT` | `false` | Enable leader election |

See `charts/haproxy-operator/values.yaml` for the full set of Helm values.

## Security

### SPIFFE/SPIRE

When SPIRE is enabled (`spire.enabled=true`), the operator obtains X.509 SVIDs from the local SPIRE Agent for mTLS with the Dataplane API. No manual certificate distribution required — both the operator pod and the HAProxy host authenticate via their SPIFFE identities.

### Vault PKI (via VSO)

When Vault is enabled (`vault.enabled=true`), the Helm chart creates VSO `VaultPKISecret` CRs that issue and auto-rotate TLS certificates from the `pki-sica-v2` intermediate CA.

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
