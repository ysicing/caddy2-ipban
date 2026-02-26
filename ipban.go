package ipban

import (
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"path/filepath"
	"strings"
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
	// RuleSource is a local file path or remote URL for rules.
	// Starts with http:// or https:// → remote URL (ETag + periodic refresh).
	// Otherwise → local file (fsnotify hot-reload).
	// Empty → built-in default rules.
	RuleSource string `json:"rule_source,omitempty"`
	// RefreshInterval for remote rule refresh. Default: 8h.
	RefreshInterval caddy.Duration `json:"refresh_interval,omitempty"`
	// IPSetName enables ipset-based kernel blocking. Empty = disabled.
	IPSetName string `json:"ipset_name,omitempty"`
	// StatusCodes to randomly return. Default: [451].
	StatusCodes []int `json:"status_codes,omitempty"`
	// BanDuration is how long an IP stays banned. 0 = permanent.
	BanDuration caddy.Duration `json:"ban_duration,omitempty"`
	// Allowlist is a list of IPs or CIDRs that are never banned.
	Allowlist []string `json:"allowlist,omitempty"`
	// Threshold is the number of malicious hits before banning. Default: 3.
	Threshold int `json:"threshold,omitempty"`
	// ThresholdWindow is the time window for counting hits. Default: 24h.
	ThresholdWindow caddy.Duration `json:"threshold_window,omitempty"`

	ruleMgr   *RuleManager
	store     *Store
	ipset     *IPSet
	logger    *zap.Logger
	ruleKey   string // key for shared RuleManager pool
	allowNets []*net.IPNet
}

// rulePool allows multiple sites with identical rule configs to share
// a single RuleManager (one set of goroutines, one fsnotify watcher).
var rulePool = caddy.NewUsagePool()

// storePool allows all sites to share a single ban Store.
// A malicious IP banned on one site is banned everywhere.
var storePool = caddy.NewUsagePool()

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
		m.StatusCodes = []int{451}
	}
	if m.Threshold <= 0 {
		m.Threshold = 3
	}
	if time.Duration(m.ThresholdWindow) == 0 {
		m.ThresholdWindow = caddy.Duration(24 * time.Hour)
	}

	for _, entry := range m.Allowlist {
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			ip := net.ParseIP(entry)
			if ip == nil {
				return fmt.Errorf("ipban: invalid allowlist entry %q", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		m.allowNets = append(m.allowNets, n)
	}

	interval := time.Duration(m.RefreshInterval)
	if interval == 0 {
		interval = 8 * time.Hour
	}

	cacheDir := ""
	filePath := ""
	urlStr := ""
	if isRemoteSource(m.RuleSource) {
		urlStr = m.RuleSource
		cacheDir = caddy.AppDataDir()
	} else if m.RuleSource != "" {
		filePath = m.RuleSource
	}

	m.ruleKey = fmt.Sprintf("rules:%s:%d", m.RuleSource, interval)
	val, _, err := rulePool.LoadOrNew(m.ruleKey, func() (caddy.Destructor, error) {
		rm, err := NewRuleManager(filePath, urlStr, cacheDir, interval, m.logger)
		if err != nil {
			return nil, err
		}
		rm.Start()
		return rm, nil
	})
	if err != nil {
		return fmt.Errorf("ipban: init rules: %w", err)
	}
	m.ruleMgr = val.(*RuleManager)

	// Store is shared across all sites via storePool — malicious IPs are banned globally.
	// Persists to <caddy_data_dir>/ipban_bans.json.
	persistPath := filepath.Join(caddy.AppDataDir(), "ipban_bans.json")
	storeVal, _, err := storePool.LoadOrNew("store", func() (caddy.Destructor, error) {
		s, err := NewStore(persistPath, m.logger)
		if err != nil {
			return nil, err
		}
		s.StartCleanup(5 * time.Minute)
		return s, nil
	})
	if err != nil {
		return fmt.Errorf("ipban: init store: %w", err)
	}
	m.store = storeVal.(*Store)

	m.ipset = NewIPSet(m.IPSetName)
	if m.IPSetName != "" && !m.ipset.Available() {
		m.logger.Warn("ipset not available, using in-process blocking only",
			zap.String("ipset_name", m.IPSetName))
	}

	src := "defaults"
	if m.RuleSource != "" {
		src = m.RuleSource
	}
	m.logger.Info("ipban ready",
		zap.String("rules", src),
		zap.Bool("ipset", m.ipset.Available()),
		zap.Bool("persist", m.store.filePath != ""))
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

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || !isPublicIPParsed(parsedIP) || m.isAllowedParsed(parsedIP) {
		return next.ServeHTTP(w, r)
	}

	if m.store.IsBanned(ip) {
		return m.block(w)
	}

	if m.ruleMgr.Match(r.URL.Path, r.UserAgent()) {
		reason := truncatedReason(r.URL.Path, r.UserAgent())
		host := r.Host
		window := time.Duration(m.ThresholdWindow)
		count := m.store.RecordHit(ip, window)
		if count >= m.Threshold {
			m.ban(ip, reason, host)
			m.store.ClearHits(ip)
		}
		return m.block(w)
	}

	return next.ServeHTTP(w, r)
}

// Cleanup implements caddy.CleanerUpper.
func (m *IPBan) Cleanup() error {
	if m.ruleKey != "" {
		_, _ = rulePool.Delete(m.ruleKey)
	}
	_, _ = storePool.Delete("store")
	return nil
}

func (m *IPBan) ban(ip, reason, host string) {
	dur := time.Duration(m.BanDuration)
	m.store.Ban(ip, reason, host, dur)
	if m.ipset.Available() {
		go func(ipStr string) {
			if err := m.ipset.Add(ipStr); err != nil {
				m.logger.Error("ipset add failed", zap.String("ip", ipStr), zap.Error(err))
			}
		}(ip)
	}
	m.logger.Info("ip banned", zap.String("ip", ip), zap.String("reason", reason))
}

func (m *IPBan) block(w http.ResponseWriter) error {
	code := m.StatusCodes[rand.IntN(len(m.StatusCodes))]
	w.WriteHeader(code)
	_, _ = w.Write([]byte(http.StatusText(code)))
	return nil
}

// isPublicIP returns true if the IP string is a public (globally routable) address.
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return isPublicIPParsed(ip)
}

// docPrefix is RFC 3849 documentation-only IPv6 range, not covered by net.IP.IsPrivate().
var docPrefix = net.IPNet{
	IP:   net.ParseIP("2001:db8::"),
	Mask: net.CIDRMask(32, 128),
}

// isPublicIPParsed checks a pre-parsed IP to avoid redundant parsing on the hot path.
func isPublicIPParsed(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !docPrefix.Contains(ip)
}

// isAllowed checks if the IP matches any allowlist entry.
func (m *IPBan) isAllowed(ipStr string) bool {
	if len(m.allowNets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return m.isAllowedParsed(ip)
}

// isAllowedParsed checks a pre-parsed IP against the allowlist.
func (m *IPBan) isAllowedParsed(ip net.IP) bool {
	for _, n := range m.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// truncatedReason builds a ban reason string, truncating path and UA to prevent
// log injection and excessive log/persistence size.
func truncatedReason(path, ua string) string {
	const maxLen = 256
	if len(path) > maxLen {
		path = path[:maxLen] + "..."
	}
	if len(ua) > maxLen {
		ua = ua[:maxLen] + "..."
	}
	return "path:" + path + " ua:" + ua
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

// isRemoteSource returns true if the source string looks like a URL.
func isRemoteSource(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
