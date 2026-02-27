package ipban

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestStoreUnban(t *testing.T) {
	s, err := NewStore("", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s.Ban("1.2.3.4", "test", "example.com", time.Hour)
	if !s.IsBanned("1.2.3.4") {
		t.Fatal("expected IP to be banned")
	}
	if !s.Unban("1.2.3.4") {
		t.Fatal("Unban should return true for banned IP")
	}
	if s.IsBanned("1.2.3.4") {
		t.Fatal("expected IP to be unbanned")
	}
	if s.Unban("1.2.3.4") {
		t.Fatal("Unban should return false for non-banned IP")
	}
}

func TestStoreUnbanClearsHits(t *testing.T) {
	s, err := NewStore("", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s.RecordHit("1.2.3.4", time.Hour)
	s.RecordHit("1.2.3.4", time.Hour)
	s.Ban("1.2.3.4", "test", "example.com", time.Hour)
	s.Unban("1.2.3.4")

	// After unban, hit counter should be cleared — next hit starts at 1.
	count := s.RecordHit("1.2.3.4", time.Hour)
	if count != 1 {
		t.Fatalf("expected hit count 1 after unban, got %d", count)
	}
}

func TestStoreListBanned(t *testing.T) {
	s, err := NewStore("", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s.Ban("1.1.1.1", "r1", "a.com", time.Hour)
	s.Ban("2.2.2.2", "r2", "b.com", time.Hour)
	// Ban with already-expired duration to verify filtering.
	s.Ban("3.3.3.3", "r3", "c.com", 0)
	s.mu.Lock()
	past := time.Now().Add(-time.Second)
	s.records["3.3.3.3"].ExpiresAt = &past
	s.mu.Unlock()

	list := s.ListBanned()
	if len(list) != 2 {
		t.Fatalf("expected 2 active bans, got %d", len(list))
	}
	ips := map[string]bool{}
	for _, r := range list {
		ips[r.IP] = true
	}
	if !ips["1.1.1.1"] || !ips["2.2.2.2"] {
		t.Fatalf("unexpected IPs in list: %v", ips)
	}
}

func TestAdminHandleList(t *testing.T) {
	s, err := NewStore("", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s.Ban("10.0.0.1", "test", "x.com", time.Hour)
	setActiveStore(s)
	defer setActiveStore(nil)

	api := AdminAPI{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ipban/banned", nil)
	if err := api.handleList(w, r); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var records []*BanRecord
	if err := json.Unmarshal(w.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].IP != "10.0.0.1" {
		t.Fatalf("unexpected response: %s", w.Body.String())
	}
}

func TestAdminHandleUnban(t *testing.T) {
	s, err := NewStore("", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s.Ban("10.0.0.2", "test", "x.com", time.Hour)
	setActiveStore(s)
	defer setActiveStore(nil)

	api := AdminAPI{}

	// Unban existing IP.
	body := bytes.NewBufferString(`{"ip":"10.0.0.2"}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ipban/unban", body)
	if err := api.handleUnban(w, r); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if s.IsBanned("10.0.0.2") {
		t.Fatal("IP should be unbanned")
	}

	// Unban non-existent IP should still succeed (best-effort ipset cleanup).
	body = bytes.NewBufferString(`{"ip":"10.0.0.3"}`)
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/ipban/unban", body)
	err = api.handleUnban(w, r)
	if err != nil {
		t.Fatalf("unexpected error for non-banned IP: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAdminHandleUnbanValidation(t *testing.T) {
	s, err := NewStore("", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	setActiveStore(s)
	defer setActiveStore(nil)

	api := AdminAPI{}

	tests := []struct {
		name   string
		method string
		body   string
	}{
		{"wrong method", http.MethodGet, `{"ip":"1.2.3.4"}`},
		{"bad json", http.MethodPost, `not json`},
		{"invalid ip", http.MethodPost, `{"ip":"not-an-ip"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tt.method, "/ipban/unban", bytes.NewBufferString(tt.body))
			err := api.handleUnban(w, r)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestAdminNoStore(t *testing.T) {
	setActiveStore(nil)
	api := AdminAPI{}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ipban/banned", nil)
	err := api.handleList(w, r)
	if err == nil {
		t.Fatal("expected error when store is nil")
	}
}

func TestAdminHandleListMethodNotAllowed(t *testing.T) {
	s, _ := NewStore("", zap.NewNop())
	setActiveStore(s)
	defer setActiveStore(nil)

	api := AdminAPI{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ipban/banned", nil)
	err := api.handleList(w, r)
	if err == nil {
		t.Fatal("expected error for POST on /ipban/banned")
	}
}

func TestIPSetDel(t *testing.T) {
	// IPSet with no name — Del should be a no-op.
	s := NewIPSet("", nil)
	if err := s.Del("1.2.3.4"); err != nil {
		t.Fatalf("Del on unavailable ipset should be no-op, got: %v", err)
	}
	// Invalid IP should return error when available (can't test real ipset in CI).
	s2 := &IPSet{name: "test", available: true}
	if err := s2.Del("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestIPSetManagerRouting(t *testing.T) {
	m := NewIPSetManager("", "", nil)
	// Both unavailable — operations should be no-ops.
	if m.Available() {
		t.Fatal("empty manager should not be available")
	}
	m.QueueAdd("1.2.3.4")
	m.QueueAdd("2001:db8::1")
	if err := m.Del("1.2.3.4"); err != nil {
		t.Fatalf("Del on unavailable manager should be no-op, got: %v", err)
	}
	if err := m.AddBatch([]string{"1.2.3.4", "2001:db8::1"}); err != nil {
		t.Fatalf("AddBatch on unavailable manager should be no-op, got: %v", err)
	}
}

func TestIPSetManagerRouteV6(t *testing.T) {
	m := NewIPSetManager("", "", nil)
	// IPv4 routes to v4
	if got := m.route("1.2.3.4"); got != m.v4 {
		t.Error("IPv4 should route to v4")
	}
	// IPv6 routes to v6
	if got := m.route("2001:db8::1"); got != m.v6 {
		t.Error("IPv6 should route to v6")
	}
	// IPv4-mapped IPv6 routes to v4
	if got := m.route("::ffff:1.2.3.4"); got != m.v4 {
		t.Error("IPv4-mapped IPv6 should route to v4")
	}
	// Invalid IP falls back to v4
	if got := m.route("not-an-ip"); got != m.v4 {
		t.Error("invalid IP should fallback to v4")
	}
}

func TestIPSetNftHelpers(t *testing.T) {
	tests := []struct {
		ipv6     bool
		family   string
		addrType string
		saddr    string
	}{
		{false, "ip", "ipv4_addr", "ip saddr"},
		{true, "ip6", "ipv6_addr", "ip6 saddr"},
	}
	for _, tt := range tests {
		s := &IPSet{ipv6: tt.ipv6}
		if got := s.nftFamily(); got != tt.family {
			t.Errorf("nftFamily(ipv6=%v): got %q, want %q", tt.ipv6, got, tt.family)
		}
		if got := s.nftAddrType(); got != tt.addrType {
			t.Errorf("nftAddrType(ipv6=%v): got %q, want %q", tt.ipv6, got, tt.addrType)
		}
		if got := s.nftSaddr(); got != tt.saddr {
			t.Errorf("nftSaddr(ipv6=%v): got %q, want %q", tt.ipv6, got, tt.saddr)
		}
	}
}

func TestIPSetInitFallback(t *testing.T) {
	// On macOS/CI where neither nft nor ipset is available,
	// init should return false and available should be false.
	s := NewIPSet("test_fallback", nil)
	if s.Available() {
		t.Skip("nft or ipset is available on this system, skipping fallback test")
	}
	if s.useNft {
		t.Error("useNft should be false when nft is unavailable")
	}
}

func TestIPSetDestructNftPath(t *testing.T) {
	// Destruct with useNft=true but available=false should not panic.
	s := &IPSet{name: "test", useNft: true, available: false}
	if err := s.Destruct(); err != nil {
		t.Fatal(err)
	}
}

func TestIPSetDestructIpsetPath(t *testing.T) {
	// Destruct with useNft=false and available=false should not panic.
	s := &IPSet{name: "test", useNft: false, available: false}
	if err := s.Destruct(); err != nil {
		t.Fatal(err)
	}
}
