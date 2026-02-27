package ipban

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
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
		lp := strings.ToLower(tt.path)
		lua := strings.ToLower(tt.ua)
		if got := cr.matchRequest(lp, lua, tt.path, tt.ua); got != tt.want {
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
	if !cr.matchRequest(strings.ToLower("/test.php"), "", "/test.php", "") {
		t.Error("should match .php path")
	}
	if !cr.matchRequest(strings.ToLower("/test.php5"), "", "/test.php5", "") {
		t.Error("should match .php5 path")
	}
	if cr.matchRequest(strings.ToLower("/test.html"), "", "/test.html", "") {
		t.Error("should not match .html path")
	}
	if !cr.matchRequest(strings.ToLower("/ok"), strings.ToLower("Python-Requests/2.28"), "/ok", "Python-Requests/2.28") {
		t.Error("should match python-requests UA")
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
	cachePath := rm.cachePath()
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Error("cache file should exist")
	}

	// Second fetch should get 304 (ETag match)
	result, err := fetchFromURL(context.Background(), srv.URL, etag)
	if err != nil {
		t.Fatal(err)
	}
	if result.changed {
		t.Error("second fetch should return 304 (not changed)")
	}
}

func TestRuleManagerCacheFallback(t *testing.T) {
	// Pre-populate cache with the correct hashed filename
	cacheDir := t.TempDir()
	unreachableURL := "http://127.0.0.1:1/unreachable"
	rf := RuleFile{Version: 1, Rules: []Rule{{Path: []string{"/cached"}}}}
	data, _ := json.Marshal(rf)
	// Compute the expected cache path
	h := sha256.Sum256([]byte(unreachableURL))
	cacheName := fmt.Sprintf("ipban_remote_rules_%x.json", h[:8])
	os.WriteFile(filepath.Join(cacheDir, cacheName), data, 0644)

	// Use an unreachable URL — should fall back to cache
	rm, err := NewRuleManager("", unreachableURL, cacheDir, time.Hour, zap.NewNop())
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
		s, _ := NewStore("", nil)
		if s.IsBanned("198.51.100.1") {
			t.Error("should not be banned initially")
		}
		s.Ban("198.51.100.1", "test", "", 0)
		if !s.IsBanned("198.51.100.1") {
			t.Error("should be banned after Ban()")
		}
	})

	t.Run("ban with expiry", func(t *testing.T) {
		s, _ := NewStore("", nil)
		s.Ban("198.51.100.1", "test", "", 1*time.Millisecond)
		time.Sleep(5 * time.Millisecond)
		if s.IsBanned("198.51.100.1") {
			t.Error("should have expired")
		}
	})

	t.Run("persistence", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bans.json")
		s1, _ := NewStore(path, nil)
		s1.Ban("10.0.0.1", "test", "", 0)
		// Wait for debounced save to complete
		time.Sleep(2 * time.Second)

		s2, err := NewStore(path, nil)
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
		name        string
		remoteAddr  string
		clientIPVar string // simulates Caddy's client_ip var
		want        string
	}{
		{"remote only", "192.168.1.1:1234", "", "192.168.1.1"},
		{"remote no port", "192.168.1.1", "", "192.168.1.1"},
		{"caddy client_ip", "10.0.0.1:80", "198.51.100.1", "198.51.100.1"},
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

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false}, // RFC 3849 documentation range
		{"2400:cb00::1", true},
		{"0.0.0.0", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := ip != nil && isPublicIPParsed(ip)
		if got != tt.want {
			t.Errorf("isPublicIPParsed(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestAllowlist(t *testing.T) {
	m := newTestIPBan(t)
	m.Allowlist = []string{"8.8.8.0/24", "198.51.100.1"}
	nets, err := parseAllowlist(m.Allowlist)
	if err != nil {
		t.Fatal(err)
	}
	m.allowNets = nets

	if !m.isAllowedParsed(net.ParseIP("8.8.8.1")) {
		t.Error("8.8.8.1 should be allowed (in 8.8.8.0/24)")
	}
	if !m.isAllowedParsed(net.ParseIP("198.51.100.1")) {
		t.Error("198.51.100.1 should be allowed (exact match)")
	}
	if m.isAllowedParsed(net.ParseIP("9.9.9.9")) {
		t.Error("9.9.9.9 should not be allowed")
	}
}

func TestServeHTTP_SkipsPrivateIP(t *testing.T) {
	m := newTestIPBan(t)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		return nil
	})
	// Private IP accessing malicious path should pass through
	r := httptest.NewRequest("GET", "/.env", nil)
	r.RemoteAddr = "192.168.1.1:5678"
	w := httptest.NewRecorder()
	_ = m.ServeHTTP(w, r, next)
	if w.Code != 200 {
		t.Errorf("private IP should pass through, got %d", w.Code)
	}
}

func TestThreshold(t *testing.T) {
	m := newTestIPBan(t)
	m.Threshold = 3
	m.ThresholdWindow = caddy.Duration(1 * time.Hour)

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		return nil
	})

	ip := "203.0.113.1" // public IP from TEST-NET-3

	// First two hits should block but NOT ban
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/.env", nil)
		r.RemoteAddr = ip + ":5678"
		w := httptest.NewRecorder()
		_ = m.ServeHTTP(w, r, next)
		if w.Code != 403 {
			t.Errorf("hit %d: expected 403, got %d", i+1, w.Code)
		}
		if m.store.IsBanned(ip) {
			t.Errorf("hit %d: should NOT be banned yet", i+1)
		}
	}

	// Third hit should trigger the ban
	r := httptest.NewRequest("GET", "/.env", nil)
	r.RemoteAddr = ip + ":5678"
	w := httptest.NewRecorder()
	_ = m.ServeHTTP(w, r, next)
	if w.Code != 403 {
		t.Errorf("hit 3: expected 403, got %d", w.Code)
	}
	if !m.store.IsBanned(ip) {
		t.Error("hit 3: should be banned now")
	}
}

func TestStoreRecordHit(t *testing.T) {
	s, _ := NewStore("", nil)

	if c := s.RecordHit("198.51.100.1", time.Hour); c != 1 {
		t.Errorf("first hit = %d, want 1", c)
	}
	if c := s.RecordHit("198.51.100.1", time.Hour); c != 2 {
		t.Errorf("second hit = %d, want 2", c)
	}

	// Window expiry
	s2, _ := NewStore("", nil)
	s2.RecordHit("198.51.100.1", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if c := s2.RecordHit("198.51.100.1", 1*time.Millisecond); c != 1 {
		t.Errorf("after window expiry = %d, want 1", c)
	}
}

func newTestIPBan(t *testing.T) *IPBan {
	t.Helper()
	rm, err := NewRuleManager("", "", "", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	store, _ := NewStore("", nil)
	return &IPBan{
		StatusCodes:     []int{403},
		statusBodies:    [][]byte{[]byte(http.StatusText(http.StatusForbidden))},
		Threshold:       1,
		ThresholdWindow: caddy.Duration(24 * time.Hour),
		ruleMgr:         rm,
		store:           store,
		ipset:           NewIPSetManager("", "", nil),
		logger:          zap.NewNop(),
	}
}

func TestServeHTTP_BlocksMaliciousPath(t *testing.T) {
	m := newTestIPBan(t)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		return nil
	})
	r := httptest.NewRequest("GET", "/.env", nil)
	r.RemoteAddr = "198.51.100.1:5678"
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
	r.RemoteAddr = "198.51.100.1:5678"
	w := httptest.NewRecorder()
	_ = m.ServeHTTP(w, r, next)
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServeHTTP_BlocksBannedIP(t *testing.T) {
	m := newTestIPBan(t)
	m.store.Ban("198.51.100.1", "test", "", 0)

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		return nil
	})
	r := httptest.NewRequest("GET", "/anything", nil)
	r.RemoteAddr = "198.51.100.1:5678"
	w := httptest.NewRecorder()
	_ = m.ServeHTTP(w, r, next)
	if w.Code != 403 {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestSanitizeLogField(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"normal text", "normal text"},
		{"has\nnewline", "hasnewline"},
		{"has\rcarriage", "hascarriage"},
		{"has\ttab", "hastab"},
		{"clean", "clean"},
		{"", ""},
		{"\x00\x01\x02", ""},
		{"a\x00b\x01c", "abc"},
	}
	for _, tt := range tests {
		if got := sanitizeLogField(tt.in); got != tt.want {
			t.Errorf("sanitizeLogField(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		m       IPBan
		wantErr bool
	}{
		{"valid", IPBan{StatusCodes: []int{403}}, false},
		{"empty status codes ok after provision", IPBan{}, false},
		{"non-4xx code", IPBan{StatusCodes: []int{500}}, true},
		{"negative ban_duration", IPBan{StatusCodes: []int{403}, BanDuration: caddy.Duration(-time.Hour)}, true},
		{"negative threshold_window", IPBan{StatusCodes: []int{403}, ThresholdWindow: caddy.Duration(-time.Hour)}, true},
		{"negative refresh_interval", IPBan{StatusCodes: []int{403}, RefreshInterval: caddy.Duration(-time.Hour)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStoreMaxBanEntries(t *testing.T) {
	s, _ := NewStore("", nil)
	for i := 0; i < maxBanEntries; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		if !s.Ban(ip, "test", "", 0) {
			t.Fatalf("Ban should succeed at entry %d", i)
		}
	}
	if s.Ban("99.99.99.99", "test", "", 0) {
		t.Error("Ban should fail when table is full")
	}
	if !s.Ban("10.0.0.0", "updated", "", 0) {
		t.Error("Re-banning existing IP should succeed even when full")
	}
}

func TestStoreMaxHitEntries(t *testing.T) {
	s, _ := NewStore("", nil)
	for i := 0; i < maxHitEntries; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		s.RecordHit(ip, time.Hour)
	}
	if c := s.RecordHit("99.99.99.99", time.Hour); c != 0 {
		t.Errorf("RecordHit should return 0 when full, got %d", c)
	}
}

func TestStoreCleanupExpired(t *testing.T) {
	s, _ := NewStore("", nil)
	var expiredIPs []string
	s.SetOnExpire(func(ip string) {
		expiredIPs = append(expiredIPs, ip)
	})

	s.Ban("1.1.1.1", "test", "", 1*time.Millisecond)
	s.Ban("2.2.2.2", "test", "", 0)
	time.Sleep(5 * time.Millisecond)

	s.Cleanup()

	if s.IsBanned("1.1.1.1") {
		t.Error("1.1.1.1 should be cleaned up")
	}
	if !s.IsBanned("2.2.2.2") {
		t.Error("2.2.2.2 should still be banned (permanent)")
	}
	if len(expiredIPs) != 1 || expiredIPs[0] != "1.1.1.1" {
		t.Errorf("onExpire should be called for 1.1.1.1, got %v", expiredIPs)
	}
}

func TestToLowerFast(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"/already/lower", "/already/lower"},
		{"/HAS/UPPER", "/has/upper"},
		{"/Mixed/Case", "/mixed/case"},
		{"", ""},
		{"/.env", "/.env"},
	}
	for _, tt := range tests {
		if got := toLowerFast(tt.in); got != tt.want {
			t.Errorf("toLowerFast(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
