package ipban

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// RuleManager loads rules from local files and remote URLs,
// watches local file changes via fsnotify, and periodically refreshes
// remote rules using ETag conditional requests with local caching.
type RuleManager struct {
	mu        sync.RWMutex
	fileRules []*compiledRule
	urlRules  []*compiledRule
	logger    *zap.Logger
	cancel    context.CancelFunc
	watcher   *fsnotify.Watcher
	debounce  *time.Timer

	filePath string
	url      string
	etag     string // last ETag from remote
	cacheDir string // directory for caching remote rules
	interval time.Duration
}

// NewRuleManager creates a manager that loads and watches rules.
// cacheDir is used to persist remote rules locally; empty disables caching.
func NewRuleManager(filePath, url, cacheDir string, interval time.Duration, logger *zap.Logger) (*RuleManager, error) {
	// Resolve to absolute path so fsnotify watches a specific directory,
	// not "." (which would fire on every file in the working directory).
	if filePath != "" {
		abs, err := filepath.Abs(filePath)
		if err != nil {
			return nil, fmt.Errorf("resolve rule file path: %w", err)
		}
		filePath = abs
	}
	rm := &RuleManager{
		filePath: filePath,
		url:      url,
		cacheDir: cacheDir,
		interval: interval,
		logger:   logger,
	}
	if err := rm.loadAll(); err != nil {
		return nil, err
	}
	return rm, nil
}

// Start begins background watchers.
// Uses context.Background() intentionally: RuleManager instances are shared via
// UsagePool across multiple Caddy modules, so their lifecycle is managed by
// reference counting (Destruct), not by any single module's context.
func (rm *RuleManager) Start() {
	rm.mu.Lock()
	if rm.cancel != nil {
		rm.mu.Unlock()
		return // already started
	}
	ctx, cancel := context.WithCancel(context.Background())
	rm.cancel = cancel
	rm.mu.Unlock()

	if rm.filePath != "" {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			rm.logger.Error("fsnotify init failed, file hot-reload disabled", zap.Error(err))
		} else {
			rm.watcher = w
			// Watch the directory instead of the file itself so that
			// rename-based saves (vim, nano, IDE) don't break the watch.
			dir := filepath.Dir(rm.filePath)
			if err := w.Add(dir); err != nil {
				rm.logger.Error("fsnotify watch failed", zap.String("dir", dir), zap.Error(err))
				_ = w.Close()
				rm.watcher = nil
			} else {
				go rm.watchFile(ctx, w)
			}
		}
	}
	if rm.url != "" && rm.interval > 0 {
		go rm.refreshURL(ctx)
	}
}

// Stop terminates background goroutines and closes the file watcher.
func (rm *RuleManager) Stop() {
	rm.mu.Lock()
	cancel := rm.cancel
	rm.cancel = nil
	watcher := rm.watcher
	rm.watcher = nil
	rm.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if watcher != nil {
		_ = watcher.Close()
	}
}

// Destruct implements caddy.Destructor for UsagePool ref-counting.
func (rm *RuleManager) Destruct() error {
	rm.Stop()
	return nil
}

// Match checks if a request matches any loaded rule.
// Path and UA are lowercased once here to avoid per-rule allocations.
func (rm *RuleManager) Match(path, ua string) bool {
	lp := toLowerFast(path)
	lua := toLowerFast(ua)
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	for _, cr := range rm.fileRules {
		if cr.matchRequest(lp, lua, path, ua) {
			return true
		}
	}
	for _, cr := range rm.urlRules {
		if cr.matchRequest(lp, lua, path, ua) {
			return true
		}
	}
	return false
}

func (rm *RuleManager) loadAll() error {
	// Load local file rules
	if rm.filePath != "" {
		rules, err := loadFromFile(rm.filePath)
		if err != nil {
			return err
		}
		rm.fileRules = rules
	}

	// Load remote rules: prefer local cache to avoid blocking startup,
	// then let the background refresher update asynchronously.
	if rm.url != "" {
		cached := rm.loadCache()
		if cached != nil {
			// Cache hit — use cached rules + etag immediately.
			// The background refreshURL goroutine will update on the next tick.
			rm.urlRules = cached.rules
			rm.etag = cached.etag
			rm.logger.Info("remote rules loaded from cache",
				zap.String("url", rm.url), zap.Int("rules", len(cached.rules)))
		} else {
			// No cache — must fetch synchronously, but with a short timeout
			// to avoid blocking Caddy startup for 30s on network failure.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := fetchFromURL(ctx, rm.url, "")
			if err != nil {
				if rm.filePath != "" {
					rm.logger.Warn("remote rules unavailable, no cache, using local only",
						zap.String("url", rm.url), zap.Error(err))
				} else {
					return err
				}
			} else {
				rm.urlRules = result.rules
				rm.etag = result.etag
				rm.saveCache(result.data, result.etag)
			}
		}
	}

	// No sources configured — use built-in defaults
	if rm.filePath == "" && rm.url == "" {
		rules, err := compileRuleFile(&defaultRuleFile)
		if err != nil {
			return err
		}
		rm.fileRules = rules
	}
	return nil
}

// --- file watcher ---

func (rm *RuleManager) watchFile(ctx context.Context, w *fsnotify.Watcher) {
	target := filepath.Clean(rm.filePath)

	reload := func() {
		if ctx.Err() != nil {
			return // context cancelled, skip reload
		}
		rules, err := loadFromFile(rm.filePath)
		if err != nil {
			if os.IsNotExist(err) {
				// Transient during editor rename-based saves; keep existing rules.
				rm.logger.Warn("rule file missing, keeping previous rules",
					zap.String("file", rm.filePath))
				return
			}
			rm.logger.Error("rule file reload failed", zap.Error(err))
			return
		}
		rm.mu.Lock()
		rm.fileRules = rules
		rm.mu.Unlock()
		rm.logger.Info("rule file reloaded",
			zap.String("file", rm.filePath), zap.Int("rules", len(rules)))
	}

	for {
		select {
		case <-ctx.Done():
			if rm.debounce != nil {
				rm.debounce.Stop()
			}
			return
		case event, ok := <-w.Events:
			if !ok {
				return
			}
			// Directory watcher fires for all files; filter to our target.
			if filepath.Clean(event.Name) != target {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			if rm.debounce != nil {
				rm.debounce.Stop()
			}
			rm.debounce = time.AfterFunc(500*time.Millisecond, reload)
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			rm.logger.Error("fsnotify error", zap.Error(err))
		}
	}
}

// --- remote refresh with ETag ---

func (rm *RuleManager) refreshURL(ctx context.Context) {
	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rm.mu.RLock()
			currentEtag := rm.etag
			rm.mu.RUnlock()

			result, err := fetchFromURL(ctx, rm.url, currentEtag)
			if err != nil {
				rm.logger.Warn("remote rule refresh failed",
					zap.String("url", rm.url), zap.Error(err))
				continue
			}
			if !result.changed {
				rm.logger.Debug("remote rules unchanged (304)")
				continue
			}
			rm.mu.Lock()
			rm.etag = result.etag
			rm.urlRules = result.rules
			rm.mu.Unlock()
			rm.saveCache(result.data, result.etag)
			rm.logger.Info("remote rules refreshed",
				zap.String("url", rm.url), zap.Int("rules", len(result.rules)))
		}
	}
}

// --- local cache for remote rules ---

func (rm *RuleManager) cachePath() string {
	if rm.cacheDir == "" || rm.url == "" {
		return ""
	}
	h := sha256.Sum256([]byte(rm.url))
	name := fmt.Sprintf("ipban_remote_rules_%x.json", h[:8])
	return filepath.Join(rm.cacheDir, name)
}

func (rm *RuleManager) saveCache(data []byte, etag string) {
	p := rm.cachePath()
	if p == "" || len(data) == 0 {
		return
	}
	if err := os.MkdirAll(rm.cacheDir, 0700); err != nil {
		rm.logger.Warn("cache dir create failed", zap.Error(err))
		return
	}
	if err := atomicWriteFile(p, data, 0600); err != nil {
		rm.logger.Warn("cache write failed", zap.Error(err))
	}
	// Persist ETag alongside cache so restarts can use conditional requests.
	if etag != "" {
		_ = atomicWriteFile(p+".etag", []byte(etag), 0600)
	}
}

type cacheResult struct {
	rules []*compiledRule
	etag  string
}

func (rm *RuleManager) loadCache() *cacheResult {
	p := rm.cachePath()
	if p == "" {
		return nil
	}
	rules, err := loadFromFile(p)
	if err != nil {
		return nil
	}
	etag := ""
	if data, err := os.ReadFile(p + ".etag"); err == nil {
		etag = string(data)
	}
	return &cacheResult{rules: rules, etag: etag}
}

// toLowerFast returns the lowercase version of s.
// For pure ASCII strings (the common case for URL paths and UAs),
// it avoids heap allocation by checking if the string is already lowercase.
func toLowerFast(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s // already lowercase, zero alloc
}
