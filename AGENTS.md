# AGENTS.md

## Repository: kube-workspaces/proxy

Workspace reverse proxy for the kube-workspaces platform. Built with Go stdlib `net/http`.

## Structure

| Directory | Purpose |
|-----------|---------|
| `cmd/proxy/main.go` | Proxy entrypoint |
| `internal/auth/` | Auth middleware (validates kw-session, checks namespace access) |
| `internal/k8s/client.go` | Kubernetes client (Image/workspace lookups, QPS 50/Burst 100) |
| `internal/proxy/proxy.go` | Reverse proxy handler (`/proxy/{ns}/{name}/...`) |

## Commands

```
go build -o bin/kube-workspaces-proxy ./cmd/proxy/    # build
go run ./cmd/proxy/ --port=8091                       # run locally
```

## Key Notes

- Go version: 1.26 (see `go.mod`)
- Independent service handling `/proxy/{ns}/{name}/...` requests
- Validates `kw-session` HMAC-SHA256 cookies (same as API)
- AuthConfig cached 30s; User CRs looked up fresh per request (instant revocation)
- When auth is disabled, all requests pass through
- Image CRs cached 30s, workspace image lookups cached 10s
- K8s client QPS 50, Burst 100 (prevents rate limiting delays)
- Sets `kw-proxy-prefix` cookie on HTML responses
- Supports `audioPort` routing for `/audio/` requests
- Proxied apps MUST use relative URLs or support configurable base URL paths

## Docker Image

Published to: `kubeworkspaces/proxy`

## CI

- `.github/workflows/ci.yml` — build + vet
- `.github/workflows/docker.yml` — build & push Docker image
