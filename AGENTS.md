# AGENTS.md

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
- `/flux/` — Example Flux manifests
- `/dev/` — Local development assets

## Development Workflow

- Create feature branches from `main`
- Use pull requests for code review
- CI runs: go test, go vet, helm lint, Docker build
- Release Please manages versioning and changelogs
