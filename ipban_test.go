package ipban

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestCompiledRuleMatch(t *testing.T) {
	r := Rule{
		Path:             []string{"/.env", "/.git/config"},
		PathPrefix:       []string{"/wp-admin/", "/phpmyadmin"},
		PathKeyword:      []string{"passwd"},
		UserAgentKeyword: []string{"sqlmap", "nikto"},
	}
	cr, err := compileRule(r)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		ua   string
		want bool
	}{
		{"/.env", "", true},
		{"/.ENV", "", true},
		{"/.git/config", "", true},
		{"/wp-admin/index.php", "", true},
		{"/phpmyadmin/setup", "", true},
		{"/etc/passwd", "", true},
		{"/index.html", "", false},
		{"/api/v1/users", "", false},
		{"/anything", "sqlmap/1.0", true},
		{"/anything", "Mozilla/5.0 Nikto", true},
		{"/anything", "Mozilla/5.0 (Windows)", false},
	}
	for _, tt := range tests {
		if got := cr.matchRequest(tt.path, tt.ua); got != tt.want {
			t.Errorf("match(%q, %q) = %v, want %v", tt.path, tt.ua, got, tt.want)
		}
	}
}

func TestCompiledRuleRegex(t *testing.T) {
	r := Rule{
		PathRegex:      []string{`\.php\d?$`},
		UserAgentRegex: []string{`(?i)python-requests`},
	}
	cr, err := compileRule(r)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.matchRequest("/test.php", "") {
		t.Error("should match .php path")
	}
	if !cr.matchRequest("/test.php5", "") {
		t.Error("should match .php5 path")
	}
	if cr.matchRequest("/test.html", "") {
		t.Error("should not match .html path")
	}
	if !cr.matchRequest("/ok", "Python-Requests/2.28") {
		t.Error("should match python-requests UA")
	}
}

func TestCompiledRuleInvert(t *testing.T) {
	r := Rule{Path: []string{"/health"}, Invert: true}
	cr, _ := compileRule(r)
	if cr.matchRequest("/health", "") {
		t.Error("/health should NOT match (inverted)")
	}
	if !cr.matchRequest("/other", "") {
		t.Error("/other should match (inverted)")
	}
}

func TestRuleManagerLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")

	rf := RuleFile{
		Version: 1,
		Rules:   []Rule{{Path: []string{"/blocked"}}},
	}
	data, _ := json.Marshal(rf)
	os.WriteFile(path, data, 0644)

	rm, err := NewRuleManager(path, "", "", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer rm.Stop()

	if !rm.Match("/blocked", "") {
		t.Error("should match /blocked")
	}
	if rm.Match("/ok", "") {
		t.Error("should not match /ok")
	}
}

func TestRuleManagerDefaults(t *testing.T) {
	rm, err := NewRuleManager("", "", "", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if !rm.Match("/.env", "") {
		t.Error("defaults should match /.env")
	}
	if !rm.Match("/anything", "sqlmap/1.0") {
		t.Error("defaults should match sqlmap UA")
	}
	if rm.Match("/index.html", "Mozilla/5.0") {
		t.Error("defaults should not match normal request")
	}
}

func TestRuleManagerFileReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")

	rf := RuleFile{Version: 1, Rules: []Rule{{Path: []string{"/v1"}}}}
	data, _ := json.Marshal(rf)
	os.WriteFile(path, data, 0644)

	rm, err := NewRuleManager(path, "", "", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	rm.Start()
	defer rm.Stop()

	if !rm.Match("/v1", "") {
		t.Error("should match /v1")
	}

	// Update file
	rf.Rules = []Rule{{Path: []string{"/v2"}}}
	data, _ = json.Marshal(rf)
	os.WriteFile(path, data, 0644)

	// Wait for fsnotify + 500ms debounce
	time.Sleep(2 * time.Second)

	if !rm.Match("/v2", "") {
		t.Error("should match /v2 after reload")
	}
}

func TestRuleManagerRemoteWithETag(t *testing.T) {
	// Serve rules with ETag support
	rf := RuleFile{Version: 1, Rules: []Rule{{Path: []string{"/remote-blocked"}}}}
	data, _ := json.Marshal(rf)
	etag := `"test-etag-123"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(data)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	rm, err := NewRuleManager("", srv.URL, cacheDir, time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer rm.Stop()

	if !rm.Match("/remote-blocked", "") {
		t.Error("should match /remote-blocked")
	}

	// Verify cache file was written
	cachePath := filepath.Join(cacheDir, "ipban_remote_rules.json")
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Error("cache file should exist")
	}

	// Second fetch should get 304 (ETag match)
	result, err := fetchFromURL(srv.URL, etag)
	if err != nil {
		t.Fatal(err)
	}
	if result.changed {
		t.Error("second fetch should return 304 (not changed)")
	}
}

func TestRuleManagerCacheFallback(t *testing.T) {
	// Pre-populate cache
	cacheDir := t.TempDir()
	rf := RuleFile{Version: 1, Rules: []Rule{{Path: []string{"/cached"}}}}
	data, _ := json.Marshal(rf)
	os.WriteFile(filepath.Join(cacheDir, "ipban_remote_rules.json"), data, 0644)

	// Use an unreachable URL — should fall back to cache
	rm, err := NewRuleManager("", "http://127.0.0.1:1/unreachable", cacheDir, time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer rm.Stop()

	if !rm.Match("/cached", "") {
		t.Error("should match /cached from cache fallback")
	}
}

func TestStore(t *testing.T) {
	t.Run("ban and check", func(t *testing.T) {
		s, _ := NewStore("")
		if s.IsBanned("1.2.3.4") {
			t.Error("should not be banned initially")
		}
		s.Ban("1.2.3.4", "test", 0)
		if !s.IsBanned("1.2.3.4") {
			t.Error("should be banned after Ban()")
		}
	})

	t.Run("ban with expiry", func(t *testing.T) {
		s, _ := NewStore("")
		s.Ban("1.2.3.4", "test", 1*time.Millisecond)
		time.Sleep(5 * time.Millisecond)
		if s.IsBanned("1.2.3.4") {
			t.Error("should have expired")
		}
	})

	t.Run("persistence", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bans.json")
		s1, _ := NewStore(path)
		s1.Ban("10.0.0.1", "test", 0)
		// Wait for debounced save to complete
		time.Sleep(2 * time.Second)

		s2, err := NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if !s2.IsBanned("10.0.0.1") {
			t.Error("ban should survive reload")
		}
	})
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		clientIPVar string // simulates Caddy's client_ip var
		want       string
	}{
		{"remote only", "192.168.1.1:1234", "", "192.168.1.1"},
		{"remote no port", "192.168.1.1", "", "192.168.1.1"},
		{"caddy client_ip", "10.0.0.1:80", "1.2.3.4", "1.2.3.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.clientIPVar != "" {
				ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
					caddyhttp.ClientIPVarKey: tt.clientIPVar,
				})
				r = r.WithContext(ctx)
			}
			if got := clientIP(r); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func newTestIPBan(t *testing.T) *IPBan {
	t.Helper()
	rm, err := NewRuleManager("", "", "", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	store, _ := NewStore("")
	return &IPBan{
		StatusCodes: []int{403},
		ruleMgr:     rm,
		store:       store,
		ipset:       NewIPSet(""),
		logger:      zap.NewNop(),
	}
}

func TestServeHTTP_BlocksMaliciousPath(t *testing.T) {
	m := newTestIPBan(t)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		return nil
	})
	r := httptest.NewRequest("GET", "/.env", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	w := httptest.NewRecorder()
	_ = m.ServeHTTP(w, r, next)
	if w.Code != 403 {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestServeHTTP_AllowsNormalRequest(t *testing.T) {
	m := newTestIPBan(t)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		return nil
	})
	r := httptest.NewRequest("GET", "/index.html", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	w := httptest.NewRecorder()
	_ = m.ServeHTTP(w, r, next)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServeHTTP_BlocksBannedIP(t *testing.T) {
	m := newTestIPBan(t)
	m.store.Ban("1.2.3.4", "test", 0)

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		return nil
	})
	r := httptest.NewRequest("GET", "/anything", nil)
	r.RemoteAddr = "1.2.3.4:5678"
	w := httptest.NewRecorder()
	_ = m.ServeHTTP(w, r, next)
	if w.Code != 403 {
		t.Errorf("expected 403, got %d", w.Code)
	}
}
