# Flux Integration

This directory contains example Flux manifests for deploying the haproxy-operator
and its configuration pipeline. These are **not** deployed directly — they serve
as templates for your `flux-fleet` repository.

## Architecture

```
┌─────────────────────────┐   poll / webhook    ┌──────────────────────┐
│  GitHub Repo            │◄────────────────────│  FluxCD              │
│  (haproxy-configs/)     │   GitRepository     │  (K8s cluster)       │
│  └── haproxy.cfg        │                     │                      │
│  └── kustomization.yaml │                     │  Kustomization       │
└─────────────────────────┘                     │  → K8s Secret        │
                                                └──────────┬───────────┘
                                                           │
                                                ┌──────────▼───────────┐
                                                │  haproxy-operator    │
                                                │  watches Secret      │
                                                │  validates config    │
                                                │  applies via DPAPI   │
                                                └──────────┬───────────┘
                                                           │ mTLS (SPIRE)
                                                ┌──────────▼───────────┐
                                                │  HAProxy LB          │
                                                │  (Dataplane API)     │
                                                └──────────────────────┘
```

## Environment Promotion

- **latest** (dev): Flux watches the `main` branch of the config repo.
  Operator pushes to a research/dev load balancer for testing.
- **stable** (production): Flux watches a `release` branch or tagged refs.
  Operator pushes to the production load balancer.

Promotion flow: merge/tag `main` → `release` branch, Flux reconciles
the stable cluster automatically.

## Webhook for Immediate Reconciliation

The `receiver.yaml` configures a Flux webhook Receiver that triggers
immediate GitRepository reconciliation when a GitHub push event arrives,
rather than waiting for the polling interval.

## Files

- `git-repository.yaml` — FluxCD GitRepository pointing at the private config repo
- `kustomization.yaml` — FluxCD Kustomization that syncs haproxy.cfg into a K8s Secret
- `receiver.yaml` — Webhook Receiver for immediate reconciliation on push
- `helmrelease.yaml` — HelmRelease for deploying the operator itself
- `helm-repository.yaml` — OCI HelmRepository for the operator chart
