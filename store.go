package ipban

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// BanRecord represents a single banned IP entry.
type BanRecord struct {
	IP        string     `json:"ip"`
	Reason    string     `json:"reason"`
	Host      string     `json:"host,omitempty"`
	BannedAt  time.Time  `json:"banned_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// maxBanEntries limits the records map size to prevent unbounded memory growth.
const maxBanEntries = 100000

// Store manages banned IPs with optional file persistence.
// Shared across sites via UsagePool — a malicious IP banned on one site is banned everywhere.
type Store struct {
	mu        sync.RWMutex
	records   map[string]*BanRecord
	filePath  string
	saveTimer *time.Timer
	logger    *zap.Logger
	cancel    context.CancelFunc
	onExpire  func(ip string) // called outside lock when an expired IP is removed
	saveGen   uint64          // incremented on each debounceSave; lets Cleanup invalidate pending callbacks
}

// NewStore creates a store, loading persisted data if filePath is set.
func NewStore(filePath string, logger *zap.Logger) (*Store, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &Store{
		records:  make(map[string]*BanRecord),
		filePath: filePath,
		logger:   logger,
	}
	if filePath != "" {
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return s, nil
}

// IsBanned checks whether an IP is currently banned.
// Expired entries are not deleted here — the background Cleanup goroutine handles that.
// This keeps IsBanned as a pure read operation (RLock only) on the hot path.
func (s *Store) IsBanned(ip string) bool {
	s.mu.RLock()
	r, ok := s.records[ip]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	expired := r.ExpiresAt != nil && time.Now().After(*r.ExpiresAt)
	s.mu.RUnlock()
	return !expired
}

// Ban adds an IP to the blacklist. Returns false if the ban table is full.
func (s *Store) Ban(ip, reason, host string, duration time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Prevent unbounded growth — skip if at capacity and IP is not already banned.
	if _, exists := s.records[ip]; !exists && len(s.records) >= maxBanEntries {
		s.logger.Warn("ban table full, cannot ban new IP",
			zap.String("ip", ip), zap.Int("limit", maxBanEntries))
		return false
	}
	now := time.Now()
	r := &BanRecord{IP: ip, Reason: reason, Host: host, BannedAt: now}
	if duration > 0 {
		exp := now.Add(duration)
		r.ExpiresAt = &exp
	}
	s.records[ip] = r
	s.debounceSave()
	return true
}

// Unban removes an IP from the ban list.
// Returns true if the IP was actually banned.
func (s *Store) Unban(ip string) bool {
	s.mu.Lock()
	_, ok := s.records[ip]
	if ok {
		delete(s.records, ip)
		s.debounceSave()
	}
	s.mu.Unlock()
	return ok
}

// ListBanned returns all currently active (non-expired) ban records.
// Returns copies to prevent external mutation of internal state.
func (s *Store) ListBanned() []BanRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	result := make([]BanRecord, 0, len(s.records))
	for _, r := range s.records {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		result = append(result, *r)
	}
	return result
}

// debounceSave schedules a debounced save. Must be called while holding s.mu.Lock().
func (s *Store) debounceSave() {
	if s.filePath == "" {
		return
	}
	if s.saveTimer != nil {
		s.saveTimer.Stop()
	}
	s.saveGen++
	gen := s.saveGen
	s.saveTimer = time.AfterFunc(time.Second, func() {
		s.mu.Lock()
		// If generation changed, Cleanup (or another debounceSave) already
		// cancelled us and will handle persistence — skip this write.
		if s.saveGen != gen {
			s.mu.Unlock()
			return
		}
		s.saveTimer = nil
		s.mu.Unlock()
		if err := s.save(); err != nil {
			s.logger.Warn("persist save failed", zap.Error(err))
		}
	})
}

// SetOnExpire registers a callback invoked (outside the lock) when an expired IP is removed.
func (s *Store) SetOnExpire(fn func(ip string)) {
	s.mu.Lock()
	s.onExpire = fn
	s.mu.Unlock()
}

// HasPersistence reports whether the store is configured with file persistence.
func (s *Store) HasPersistence() bool {
	return s.filePath != ""
}

// Cleanup removes expired entries, syncs ipset removal, and persists the result.
func (s *Store) Cleanup() {
	s.mu.Lock()
	if s.saveTimer != nil {
		s.saveTimer.Stop()
		s.saveTimer = nil
	}
	s.saveGen++ // invalidate any in-flight debounceSave callback
	now := time.Now()
	var expiredIPs []string
	for ip, r := range s.records {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			delete(s.records, ip)
			if s.onExpire != nil {
				expiredIPs = append(expiredIPs, ip)
			}
		}
	}
	onExpire := s.onExpire
	s.mu.Unlock()

	// Remove expired IPs from ipset outside the lock.
	for _, ip := range expiredIPs {
		onExpire(ip)
	}

	if s.filePath != "" {
		if err := s.save(); err != nil {
			s.logger.Warn("cleanup persist save failed", zap.Error(err))
		}
	}
}

// StartCleanup begins a background goroutine that periodically removes expired entries.
// Uses its own context because Store is shared via UsagePool — its lifecycle is
// managed by reference counting, not by any single module's context.
func (s *Store) StartCleanup(interval time.Duration) {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return // already started
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.mu.Unlock()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Cleanup()
			}
		}
	}()
}

// Stop terminates the cleanup goroutine and pending save timer.
func (s *Store) Stop() {
	s.mu.Lock()
	if s.saveTimer != nil {
		s.saveTimer.Stop()
		s.saveTimer = nil
	}
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Destruct implements caddy.Destructor for UsagePool ref-counting.
func (s *Store) Destruct() error {
	s.Stop()
	s.Cleanup()
	return nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	var records []*BanRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	now := time.Now()
	for _, r := range records {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		if net.ParseIP(r.IP) == nil {
			s.logger.Warn("skipping invalid IP in persisted ban data", zap.String("ip", r.IP))
			continue
		}
		s.records[r.IP] = r
	}
	return nil
}

func (s *Store) save() error {
	s.mu.RLock()
	records := make([]*BanRecord, 0, len(s.records))
	now := time.Now()
	for _, r := range s.records {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		records = append(records, r)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.filePath, data, 0600)
}

// atomicWriteFile writes data to a temp file then renames it into place,
// preventing corruption on crash or partial write.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
