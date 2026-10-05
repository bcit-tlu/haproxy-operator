# haproxy-operator

Deploys the HAProxy Dataplane config operator: watches a Secret carrying
`haproxy.cfg`, validates it against the gateway's Dataplane API over mTLS,
and applies it.

## Dataplane mTLS: two trust decisions, not one

The operator↔gateway connection is mutual TLS with **independent** sides:

| Side | What it is | Sourced from |
|---|---|---|
| Client identity | The certificate the operator *presents* (`tls.crt`/`tls.key`) | `dataplane.tls.existingSecret`, or issued by Vault via `vault.pki` (a `VaultPKISecret`), or SPIRE |
| Server trust | The CA bundle the operator uses to *verify the gateway* (`ca.crt`) | `dataplane.serverCA` — see below |

These are deliberately decoupled
([bcit-tlu/haproxy-operator#39](https://github.com/bcit-tlu/haproxy-operator/issues/39)):
the client certificate and the gateway's server certificate may be issued by
**different** Vault issuers. The server CA is therefore mounted from its own
volume at `/etc/haproxy-operator/server-ca/` and never derived from the
client-cert Secret.

## `dataplane.serverCA` — server trust source

Exactly one source may be configured; the chart fails otherwise:

```yaml
dataplane:
  serverCA:
    vaultPKI: { enabled: true }              # rendered VaultDynamicSecret
    configMap: { name: gw-ca, key: ca.crt }  # existing ConfigMap
    secretKeyRef: { name: gw-ca, key: ca.crt } # existing Secret
```

- **`vaultPKI`** (requires `vault.enabled`) — renders a `VaultDynamicSecret`
  that `GET`s `<mount>/cert/ca` (default `pki-haproxy/cert/ca`, the issuing
  intermediate PEM — a plain read the operator's existing Vault policy
  already permits) into `<secretName>` (default `<release>-server-ca`) as
  `ca.crt`, refreshed every `refreshAfter` (default `1h`). The pod restarts
  on rotation via `rolloutRestartTargets`.
- **`configMap`** — mounts `configMap.name` projecting `key` (default
  `ca.crt`) into the server-ca volume.
- **`secretKeyRef`** — mounts `secretKeyRef.name` projecting `key` (default
  `ca.crt`).

**Defaults when nothing is set:**

- `vault.enabled: true` → `vaultPKI` (the fleet path).
- `vault.enabled: false` → `secretKeyRef` on
  `dataplane.tls.existingSecret`'s `ca.crt` — the historical single-source
  layout, so static installs are unchanged.

`serverCA` is ignored entirely when `spire.enabled` (SPIFFE bundles carry
both directions).

**Interaction with `dataplane.caCertPath`:** the managed volume always
projects the CA as `/etc/haproxy-operator/server-ca/ca.crt` (the
`caCertPath` default). Pointing `caCertPath` anywhere else without an
explicit `serverCA` source keeps the legacy behavior — no `server-ca`
volume is created and the path must be backed by your own mount (e.g. a
key inside the TLS Secret) — while an *explicit* source combined with a
mismatched `caCertPath` fails at template time.

**Rotation:** the operator rebuilds its trust pool from the CA file on
every TLS handshake, so Secret/ConfigMap source rotations take effect on
new connections without a pod restart. The `vaultPKI` source also sets
`rolloutRestartTargets` so an issuer rotation restarts the deployment
outright.

## Migration note (vault#69 — dedicated client CA)

Today the client certificate and the gateway server certificate share the
`pki-haproxy` intermediate, so pointing `caCertPath` at a key inside the
client-cert Secret happens to work. Once
[bcit-tlu/vault#69](https://github.com/bcit-tlu/vault/issues/69) issues the
operator client cert from a dedicated client CA, that Secret will carry the
wrong trust anchor — always configure `dataplane.serverCA` (or rely on the
`vaultPKI` default) rather than deriving server trust from the client
Secret.
