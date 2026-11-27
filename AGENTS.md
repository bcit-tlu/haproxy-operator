# AGENTS.md

Tooling: every CLI this repo needs comes from `shell.nix`; run commands via `nix-shell --run` (or `direnv allow`) before concluding a tool is missing.

## Setup Commands

- Install Go dependencies: `go mod download`
- Build: `go build -o bin/manager ./main.go`
- Run tests: `go test -race ./...`
- Vet: `go vet ./...`
- Local dev (Docker Compose): `docker compose up --build`

## Code Style

- Follow standard Go conventions (gofmt, goimports)
- Use type annotations; avoid `any` except for JSON serialization maps
- Follow conventional commit format
- Keep packages focused: one responsibility per package

## Testing Guidelines

- Write unit tests for all new functions
- Use the standard `testing` package
- Run `go test -race ./...` before committing
- Aim for >80% coverage on new code

## Project Structure

- `/main.go` — Entrypoint and flag parsing
- `/internal/config/` — Config loading, hashing, and validation
- `/internal/controller/` — K8s Secret reconciler (controller-runtime)
- `/internal/haproxy/` — Dataplane API client
- `/internal/local/` — Local file-watching runner
- `/internal/spire/` — SPIFFE/SPIRE Workload API integration
- `/internal/status/` — K8s Event reporter
- `/charts/haproxy-operator/` — Helm chart
- `/dev/` — Local development assets

## Development Workflow

- Default PR loop (no need to be asked): after every push, wait until all checks — including Devin Review and github-code-quality — have finished, fix and resolve every thread (≤3 rounds), and only then report or admin-merge. An instruction to "admin-merge" never skips this wait.
- Create feature branches from `main`
- Do issue/PR work in a git worktree, not the main checkout: `git fetch origin && git worktree add .worktrees/<name> -b <type>/<issue>-<slug> origin/main` (`.worktrees/` is gitignored)
- Keep the main checkout on a clean, up-to-date `main`; after the PR merges, `git worktree remove .worktrees/<name>` (`git worktree prune` clears stale registrations)
- Use pull requests for code review
- CI runs: go test, go vet, helm lint, Docker build
- Release Please manages versioning and changelogs
