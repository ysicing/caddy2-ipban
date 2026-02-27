# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-02-27

### Added
- Default ban duration of 7 days (previously 0 = permanent with no default)

### Changed
- Request matching now immediately bans on first hit; threshold and time window removed
- `BanDuration` field changed to pointer type to distinguish "not set" from zero value
- `ipset.go` simplified to pure ipset backend only; nft/iptables code removed
- `IPSet.Destruct()` no longer manages firewall rules cleanup

### Removed
- `Threshold` and `ThresholdWindow` configuration options
- `threshold` and `threshold_window` Caddyfile directives
- `Store.RecordHit()` and `Store.ClearHits()` methods
- `hitRecord` struct and `hitsMu`/`hits`/`hitsFullLogged` fields from `Store`
- `maxHitEntries` constant
- nftables backend: `initNft()`, `removeNftTable()`, `nftElementCmd()`, `nftFamily()`, `nftAddrType()`, `nftSaddr()`
- iptables backend: `iptablesRuleArgs()`, `fwCmd()`, `ensureIptablesRule()`, `removeIptablesRule()`
- `useNft` and `iptablesManaged` fields from `IPSet` struct

### Security
- Removed `maxHitEntries` memory limit (no longer needed without hit tracking)

## [1.1.0] - 2026-02-27

### Added
- nftables (`nft`) native set backend as priority kernel-level IP blocking, with automatic fallback to ipset+iptables when nft is unavailable
- `initNft()` creates nftables table/set/chain/rule via `nft -f -` stdin to avoid shell escaping issues
- `removeNftTable()` for clean nftables teardown on module unload
- `nftElementCmd()` shared helper for Add/Del nft element operations
- nft branches in `Add()`, `Del()`, `AddBatch()` for nftables element management
- `TestIPSetNftHelpers`, `TestIPSetInitFallback`, `TestIPSetDestructNftPath`, `TestIPSetDestructIpsetPath` tests

### Changed
- `init()` refactored into `initNft()` and `initIpset()`, trying nftables first then falling back to ipset
- `Destruct()` selects cleanup path based on active backend (`removeNftTable` vs `removeIptablesRule`)
- `IPSet` struct gains `useNft` field to track which backend is active
- `initNft` script includes `flush chain` to prevent duplicate drop rules after unclean shutdown
- `AddBatch` nft path uses `strings.Builder` with `Grow()` pre-allocation for reduced allocations

### Fixed
- `initNft` now logs Debug message on failure before falling back to ipset

### Removed
- Dead `buf.Len() == 0` check in `AddBatch` ipset path (unreachable after `len(ips) == 0` guard)

## [1.0.0] - 2026-02-26

### Added
- Caddy2 HTTP middleware plugin for detecting malicious scanning requests and blocking source IPs
- Rule-based detection supporting local file, remote URL, and built-in default rules
- In-process IP banning with optional JSON file persistence
- Linux ipset kernel-level blocking with automatic detection and graceful degradation
- Admin API endpoints: `GET /ipban/banned` and `POST /ipban/unban`
- Threshold-based banning with configurable hit count and sliding time window
- IP allowlist supporting both individual IPs and CIDR ranges
- Remote rule refresh with ETag conditional requests and local cache fallback
- Local rule file hot-reload via fsnotify with 500ms debounce
- IPSet batch worker for coalescing kernel-level additions under burst traffic
- Atomic file writes (temp + rename + fsync) for crash-safe persistence
- `UsagePool` sharing of RuleManager, Store, and IPSet across multiple sites
- Configurable ban duration, status codes, refresh interval, and threshold window
- Caddyfile directive support with full configuration options

### Changed
- Unified `rule_source` configuration replacing separate `rule_file` and `rule_url` options
- Store uses dual-lock design: `RWMutex` for ban records, `Mutex` for hit tracking
- `saveGen` generation counter to prevent debounceSave/Cleanup double-write races
- `QueueAdd` uses `atomic.Bool` stopped flag to prevent send-on-closed-channel panic
- `parseAllowlist` extracted as shared helper for Provision and tests
- `ClearHits` called only after successful `ban()` to preserve hit counts on failure
- `r.UserAgent()` cached to local variable in ServeHTTP hot path
- `truncateField` respects UTF-8 byte boundaries when truncating strings
- `NewStore` defaults logger to `zap.NewNop()` when nil, eliminating scattered nil checks
- `setActiveStore` and `setActiveIPSet` lifecycle decoupled for independent cleanup
- Remote rule loading uses cache-first strategy with 5s short timeout fallback
- ETag persisted to `.etag` sidecar file for cross-restart continuity
- `RuleManager.watchFile` accepts `*fsnotify.Watcher` parameter to prevent data race on Stop
- `filepath.Abs` used for fsnotify to prevent watching entire working directory

### Fixed
- `Store.Stop()` and `RuleManager.Stop()` now reset cancel fields to nil for clean restart
- `onExpire` callback set once in storePool constructor, preventing multi-site overwrite
- Data race between `RuleManager.Stop()` setting `watcher = nil` and `watchFile()` reading it
- Validate() removed unreachable empty StatusCodes check (Provision guarantees non-empty)
- Test helper `newTestIPBan` now sets `ThresholdWindow` to prevent zero-window counter reset

### Security
- ipset command injection prevention via `validIPSetName` regex and `net.ParseIP` validation
- Memory exhaustion protection with `maxBanEntries` and `maxHitEntries` limits
- Remote rule response size limited to 10MB via `io.LimitReader`
- Admin API request body limited to 1024 bytes
- Log injection prevention via `sanitizeLogField` stripping control characters
- Persisted ban records validated on load, invalid IPs skipped
- Cache and persistence files written with `0600` permissions
- HTTP client with explicit 30s timeout and 3-redirect limit
