package ipban

import (
	"context"
	"os"
	"path/filepath"
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

	filePath  string
	url       string
	etag      string // last ETag from remote
	cacheDir  string // directory for caching remote rules
	interval  time.Duration
}

// NewRuleManager creates a manager that loads and watches rules.
// cacheDir is used to persist remote rules locally; empty disables caching.
func NewRuleManager(filePath, url, cacheDir string, interval time.Duration, logger *zap.Logger) (*RuleManager, error) {
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
func (rm *RuleManager) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	rm.cancel = cancel

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
				w.Close()
				rm.watcher = nil
			} else {
				go rm.watchFile(ctx)
			}
		}
	}
	if rm.url != "" && rm.interval > 0 {
		go rm.refreshURL(ctx)
	}
}

// Stop terminates background goroutines and closes the file watcher.
func (rm *RuleManager) Stop() {
	if rm.cancel != nil {
		rm.cancel()
	}
	if rm.watcher != nil {
		rm.watcher.Close()
	}
}

// Destruct implements caddy.Destructor for UsagePool ref-counting.
func (rm *RuleManager) Destruct() error {
	rm.Stop()
	return nil
}

// Match checks if a request matches any loaded rule.
func (rm *RuleManager) Match(path, ua string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	for _, cr := range rm.fileRules {
		if cr.matchRequest(path, ua) {
			return true
		}
	}
	for _, cr := range rm.urlRules {
		if cr.matchRequest(path, ua) {
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

	// Load remote rules: try fetch, fall back to cache
	if rm.url != "" {
		result, err := fetchFromURL(rm.url, "")
		if err != nil {
			// Try loading from local cache
			if rules := rm.loadCache(); rules != nil {
				rm.urlRules = rules
				rm.logger.Warn("remote rules unavailable, loaded from cache",
					zap.String("url", rm.url), zap.Error(err))
			} else if rm.filePath != "" {
				rm.logger.Warn("remote rules unavailable, no cache, using local only",
					zap.String("url", rm.url), zap.Error(err))
			} else {
				return err
			}
		} else {
			rm.urlRules = result.rules
			rm.etag = result.etag
			rm.saveCache(result.data)
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

func (rm *RuleManager) watchFile(ctx context.Context) {
	target := filepath.Clean(rm.filePath)

	reload := func() {
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
		case event, ok := <-rm.watcher.Events:
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
		case err, ok := <-rm.watcher.Errors:
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

			result, err := fetchFromURL(rm.url, currentEtag)
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
			rm.saveCache(result.data)
			rm.logger.Info("remote rules refreshed",
				zap.String("url", rm.url), zap.Int("rules", len(result.rules)))
		}
	}
}

// --- local cache for remote rules ---

func (rm *RuleManager) cachePath() string {
	if rm.cacheDir == "" {
		return ""
	}
	return filepath.Join(rm.cacheDir, "ipban_remote_rules.json")
}

func (rm *RuleManager) saveCache(data []byte) {
	p := rm.cachePath()
	if p == "" || len(data) == 0 {
		return
	}
	if err := os.MkdirAll(rm.cacheDir, 0755); err != nil {
		rm.logger.Warn("cache dir create failed", zap.Error(err))
		return
	}
	if err := atomicWriteFile(p, data, 0644); err != nil {
		rm.logger.Warn("cache write failed", zap.Error(err))
	}
}

func (rm *RuleManager) loadCache() []*compiledRule {
	p := rm.cachePath()
	if p == "" {
		return nil
	}
	rules, err := loadFromFile(p)
	if err != nil {
		return nil
	}
	return rules
}
