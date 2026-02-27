# AGENTS.md

Caddy2 HTTP middleware plugin (`http.handlers.ipban`) that detects malicious scanners and bans source IPs via in-memory store and optional Linux ipset.

## Build & Test
```bash
go build ./...                              # compile
go test ./...                               # all tests
go test -v -run TestRuleManagerFileReload   # single test
go test -race ./...                         # race detector
go vet ./...                                # static analysis
```
No linter or Makefile — use standard `go` commands only.

## Architecture
Single Go package. Request flow: `ServeHTTP → clientIP → isPublicIP? → isAllowed? → Store.IsBanned? → RuleManager.Match? → ban+block / next`.
- **ipban.go** — Caddy module entry; wires RuleManager, Store, IPSet.
- **rule_manager.go** — Loads/watches local file (fsnotify) and remote URL (ETag/304); `sync.RWMutex` for concurrency.
- **rules.go** — Rule JSON schema (sing-box inspired), compiled matching (path, path_prefix, path_keyword, path_regex, user_agent_keyword, user_agent_regex).
- **store.go** — In-memory banned-IP map with TTL expiry and optional JSON persistence; own `sync.RWMutex`.
- **ipset.go** — Linux `ipset` CLI wrapper; gracefully degrades on macOS/no perms.
- **defaults.go** — Built-in rules when no rule_file/rule_url configured.
- **caddyfile.go** — Caddyfile directive parsing.

## Code Style
Go 1.23, flat package `ipban`. Imports: stdlib first, then `github.com/caddyserver/caddy/v2` and `go.uber.org/zap`. Use `caddy.Duration` for durations, `zap.Logger` for logging. Errors use `fmt.Errorf("ipban: …")` prefix. Concurrency via `sync.RWMutex` — readers RLock, writers Lock. No interfaces beyond Caddy's; no generics. See also `CLAUDE.md`.
