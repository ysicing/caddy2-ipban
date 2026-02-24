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
ServeHTTP → clientIP(r) → store.IsBanned? → ruleMgr.Match(path, ua)? → ban + block / next
```

Blocked requests get a random 4xx status code. Banned IPs are stored in-memory (Store) and optionally added to Linux ipset.

### Key Components

- **IPBan** (`ipban.go`) — Caddy module entry point. Implements `caddyhttp.MiddlewareHandler`. Wires together RuleManager, Store, and IPSet. Registers the `ipban` Caddyfile directive.
- **RuleManager** (`rule_manager.go`) — Manages rule lifecycle. Loads from local file and/or remote URL, merges both sources. Local file watched via fsnotify with 500ms debounce. Remote URL refreshed on interval using ETag conditional requests (`If-None-Match` / 304). Remote rules cached locally for offline startup fallback.
- **Rules** (`rules.go`) — Rule JSON format definition (sing-box inspired), compiled rule matching, and HTTP fetch logic. Rules support: `path`, `path_prefix`, `path_keyword`, `path_regex`, `user_agent_keyword`, `user_agent_regex`, `invert`.
- **Store** (`store.go`) — In-memory banned IP map with `sync.RWMutex`. Supports TTL-based expiry and JSON file persistence.
- **IPSet** (`ipset.go`) — Wraps Linux `ipset` CLI. Gracefully degrades when unavailable (macOS, no permissions).
- **Defaults** (`defaults.go`) — Built-in `RuleFile` used when no rule_file/rule_url is configured.
- **Caddyfile** (`caddyfile.go`) — Caddyfile unmarshaling and interface guards.

### Rule Sources (priority)

`fileRules` and `urlRules` are stored separately and both checked on every request. If neither `rule_file` nor `rule_url` is configured, built-in defaults from `defaults.go` are loaded into `fileRules`.

### Concurrency Model

RuleManager uses `sync.RWMutex` — readers (ServeHTTP) take RLock, writers (file reload, URL refresh) take full Lock. Store has its own independent RWMutex.

## Caddyfile Options

```
rule_file, rule_url, refresh_interval, cache_dir,
ipset_name, persist_file, status_codes, ban_duration
```

## Rule JSON Format

```json
{
  "version": 1,
  "rules": [{ "path": [], "path_prefix": [], "path_keyword": [],
               "path_regex": [], "user_agent_keyword": [],
               "user_agent_regex": [], "invert": false }]
}
```

See `rules.example.json` for a complete example.
