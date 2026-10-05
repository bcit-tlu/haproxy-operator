# Contributing

## Workflow

- Feature branch → PR to `main`; PR titles follow conventional-commit format.
- Run the local CI-equivalent checks before requesting review:
  `go test -race ./...`, `go vet ./...`, `gofmt -w .`, `helm lint charts/haproxy-operator`.
- [Release Please](https://github.com/googleapis/release-please) owns all
  versioning: merged conventional commits accumulate on its release PR, and
  merging that PR cuts the tag, changelog entry, image, and chart. Never edit
  versions or the changelog by hand.

## Dependency updates

Dependencies are kept current by Dependabot (`.github/dependabot.yml`), which
opens one grouped minor/patch PR per ecosystem (`gomod`, `github-actions`,
`docker`) each week; major bumps arrive ungrouped.

- Grouped minor/patch PRs with green CI may be merged by any maintainer.
- Major bumps and Go toolchain bumps need a human review — check the
  dependency's release notes for API changes before merging.
- The `go` directive in `go.mod` is the single source of truth for the Go
  toolchain: `actions/setup-go` reads it via `go-version-file`, and CI passes
  it to the Docker build as the `GO_VERSION` build arg. When bumping Go, change
  `go.mod` only — the `ARG GO_VERSION` default in the Dockerfile is just the
  local-build fallback.
- `sigs.k8s.io/controller-runtime`, `k8s.io/api`, `k8s.io/apimachinery`, and
  `k8s.io/client-go` move together; the `k8s.io` minor should track the fleet's
  Kubernetes minor (RKE2 — check `kubectl version` against the clusters).
