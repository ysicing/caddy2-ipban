# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Caddy2 HTTP middleware plugin that detects malicious scanning requests and blocks source IPs. Supports rule-based detection (local file, remote URL, or built-in defaults), in-process banning with optional persistence, and Linux ipset kernel-level blocking.

Module ID: `http.handlers.ipban`

## Build & Test

```bash
go build ./...          # compile
go test ./...           # run all tests
go test -v -run TestRuleManagerFileReload  # single test (file reload takes ~2s due to fsnotify debounce)
go test -race ./...     # race detector
go vet ./...            # static analysis
```

No linter is configured. No Makefile — standard `go` commands only.

## Architecture

### Request Flow

```
ServeHTTP → clientIP(r) → isPublicIP? → isAllowed? → store.IsBanned? → ruleMgr.Match? → ban + block / next
```

Private/loopback IPs and allowlisted IPs are skipped. Blocked requests get a random 4xx status code. Any request matching a rule is immediately banned. Banned IPs are stored in-memory (Store) and optionally added to Linux ipset.

### Key Components

- **IPBan** (`ipban.go`) — Caddy module entry point. Implements `caddyhttp.MiddlewareHandler`. Wires together RuleManager, Store, and IPSet. Registers the `ipban` Caddyfile directive.
- **RuleManager** (`rule_manager.go`) — Manages rule lifecycle. Loads from local file and/or remote URL, merges both sources. Local file watched via fsnotify with 500ms debounce. Remote URL refreshed on interval using ETag conditional requests (`If-None-Match` / 304). Remote rules cached locally for offline startup fallback.
- **Rules** (`rules.go`) — Rule JSON format definition (sing-box inspired), compiled rule matching, and HTTP fetch logic. Rules support: `path`, `path_prefix`, `path_keyword`, `path_regex`, `user_agent_keyword`, `user_agent_regex`.
- **Store** (`store.go`) — In-memory banned IP map with `sync.RWMutex`. Supports TTL-based expiry, periodic cleanup, and JSON file persistence.
- **IPSet** (`ipset.go`) — Wraps Linux `ipset` CLI. Gracefully degrades when unavailable (macOS, no permissions).
- **Defaults** (`defaults.go`) — Built-in `RuleFile` used when no rule_source is configured.
- **Caddyfile** (`caddyfile.go`) — Caddyfile unmarshaling and interface guards.

### Rule Sources (priority)

`fileRules` and `urlRules` are stored separately and both checked on every request. If `rule_source` is not configured, built-in defaults from `defaults.go` are loaded into `fileRules`.

### Concurrency Model

RuleManager uses `sync.RWMutex` — readers (ServeHTTP) take RLock, writers (file reload, URL refresh) take full Lock. Store has its own independent RWMutex. Store cleanup goroutine uses `caddy.Context` for lifecycle management.

## Caddy Extension Best Practices

This project follows Caddy module development conventions:

- **Goroutine lifecycle**: All background goroutines must accept `context.Context` from `caddy.Context` and exit on `ctx.Done()`. Never use custom stop channels — Caddy cancels the context automatically on module unload.
- **HTTP clients**: Use a dedicated package-level `http.Client` with explicit `Timeout`. Never use `http.DefaultClient` (global state, no timeout). See `httpClient` in `rules.go`.
- **UsagePool**: Shared resources (like `RuleManager`) use `caddy.UsagePool` for ref-counting across config reloads. Multiple sites with identical configs share one instance.
- **Module overlap**: During config reloads, new modules start before old ones stop. Design for concurrent old/new instances.
- **Provision vs Cleanup**: `Provision()` sets up resources and starts goroutines. `Cleanup()` releases resources. Context cancellation handles goroutine shutdown.
- **Logging**: Always use `ctx.Logger()` (zap), never Go's `log` package.
- **Interface guards**: Compile-time checks in `caddyfile.go` ensure all required interfaces are implemented.

## Caddyfile Options

```
rule_source, refresh_interval,
status_codes, ban_duration,
allow
```

## Rule JSON Format

```json
{
  "version": 1,
  "rules": [{ "path": [], "path_prefix": [], "path_keyword": [],
               "path_regex": [], "user_agent_keyword": [],
               "user_agent_regex": [] }]
}
```

See `rules.example.json` for a complete example.
