package ipban

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(IPBan{})
	httpcaddyfile.RegisterHandlerDirective("ipban", parseCaddyfile)
}

// IPBan is a Caddy HTTP handler that detects malicious scanning
// requests and blocks the source IPs.
//
// It can be used globally or per-site:
//
//	# Global (all sites)
//	{
//	    order ipban first
//	}
//	:443 {
//	    ipban { ... }
//	}
//
//	# Per-site
//	example.com {
//	    ipban { ... }
//	}
type IPBan struct {
	// RuleFile is a local JSON rule file path. Auto-reloaded on change.
	RuleFile string `json:"rule_file,omitempty"`
	// RuleURL is a remote JSON rule URL. Periodically refreshed.
	RuleURL string `json:"rule_url,omitempty"`
	// RefreshInterval for remote rule refresh. Default: 1h.
	RefreshInterval caddy.Duration `json:"refresh_interval,omitempty"`
	// CacheDir for caching remote rules locally. Default: Caddy data dir.
	CacheDir string `json:"cache_dir,omitempty"`
	// IPSetName enables ipset-based kernel blocking. Empty = disabled.
	IPSetName string `json:"ipset_name,omitempty"`
	// PersistFile enables file-based ban persistence. Empty = disabled.
	PersistFile string `json:"persist_file,omitempty"`
	// StatusCodes to randomly return. Default: [400,403,404,429].
	StatusCodes []int `json:"status_codes,omitempty"`
	// BanDuration is how long an IP stays banned. 0 = permanent.
	BanDuration caddy.Duration `json:"ban_duration,omitempty"`

	ruleMgr *RuleManager
	store   *Store
	ipset   *IPSet
	logger  *zap.Logger
	ruleKey string // key for shared RuleManager pool
}

// rulePool allows multiple sites with identical rule configs to share
// a single RuleManager (one set of goroutines, one fsnotify watcher).
var rulePool = caddy.NewUsagePool()

// CaddyModule returns the Caddy module information.
func (IPBan) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ipban",
		New: func() caddy.Module { return new(IPBan) },
	}
}

// Provision sets up the module.
func (m *IPBan) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if len(m.StatusCodes) == 0 {
		m.StatusCodes = []int{400, 403, 404, 429}
	}

	interval := time.Duration(m.RefreshInterval)
	if interval == 0 {
		interval = 1 * time.Hour
	}

	cacheDir := m.CacheDir
	if cacheDir == "" && m.RuleURL != "" {
		// Default: use Caddy's data directory
		cacheDir = caddy.AppDataDir()
	}

	m.ruleKey = fmt.Sprintf("rules:%s:%s:%s:%d", m.RuleFile, m.RuleURL, cacheDir, interval)
	val, _, err := rulePool.LoadOrNew(m.ruleKey, func() (caddy.Destructor, error) {
		rm, err := NewRuleManager(m.RuleFile, m.RuleURL, cacheDir, interval, m.logger)
		if err != nil {
			return nil, err
		}
		rm.Start()
		return rm, nil
	})
	if err != nil {
		return fmt.Errorf("ipban: init rules: %v", err)
	}
	m.ruleMgr = val.(*RuleManager)

	m.store, err = NewStore(m.PersistFile)
	if err != nil {
		return fmt.Errorf("ipban: init store: %v", err)
	}

	m.ipset = NewIPSet(m.IPSetName)
	if m.IPSetName != "" && !m.ipset.Available() {
		m.logger.Warn("ipset not available, using in-process blocking only",
			zap.String("ipset_name", m.IPSetName))
	}

	src := "defaults"
	if m.RuleFile != "" {
		src = m.RuleFile
	}
	if m.RuleURL != "" {
		src += " + " + m.RuleURL
	}
	m.logger.Info("ipban ready",
		zap.String("rules", src),
		zap.Bool("ipset", m.ipset.Available()),
		zap.Bool("persist", m.PersistFile != ""))
	return nil
}

// Validate ensures the configuration is valid.
func (m *IPBan) Validate() error {
	for _, code := range m.StatusCodes {
		if code < 400 || code > 499 {
			return fmt.Errorf("ipban: status code %d is not a 4xx code", code)
		}
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *IPBan) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientIP(r)

	if m.store.IsBanned(ip) {
		return m.block(w)
	}

	if m.ruleMgr.Match(r.URL.Path, r.UserAgent()) {
		reason := fmt.Sprintf("path:%s ua:%s", r.URL.Path, r.UserAgent())
		m.ban(ip, reason)
		return m.block(w)
	}

	return next.ServeHTTP(w, r)
}

// Cleanup implements caddy.CleanerUpper.
func (m *IPBan) Cleanup() error {
	if m.ruleKey != "" {
		_, _ = rulePool.Delete(m.ruleKey)
	}
	if m.store != nil {
		m.store.Cleanup()
	}
	return nil
}

func (m *IPBan) ban(ip, reason string) {
	dur := time.Duration(m.BanDuration)
	m.store.Ban(ip, reason, dur)
	if m.ipset.Available() {
		if err := m.ipset.Add(ip); err != nil {
			m.logger.Error("ipset add failed", zap.String("ip", ip), zap.Error(err))
		}
	}
	m.logger.Info("ip banned", zap.String("ip", ip), zap.String("reason", reason))
}

func (m *IPBan) block(w http.ResponseWriter) error {
	code := m.StatusCodes[rand.Intn(len(m.StatusCodes))]
	w.WriteHeader(code)
	_, _ = w.Write([]byte(http.StatusText(code)))
	return nil
}

func clientIP(r *http.Request) string {
	// Use Caddy's client_ip var which respects trusted_proxies config.
	if val := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey); val != nil {
		if ip, ok := val.(string); ok && ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
