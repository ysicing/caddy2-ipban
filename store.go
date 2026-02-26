package ipban

import (
	"context"
	"encoding/json"
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

// hitRecord tracks malicious request counts for threshold-based banning.
type hitRecord struct {
	count    int
	firstHit time.Time
	window   time.Duration
}

// maxHitEntries limits the hits map size to prevent memory exhaustion
// from distributed scanning attacks using many unique source IPs.
const maxHitEntries = 100000

// Store manages banned IPs with optional file persistence.
// Shared across sites via UsagePool — a malicious IP banned on one site is banned everywhere.
type Store struct {
	mu        sync.RWMutex
	records   map[string]*BanRecord
	hits      map[string]*hitRecord
	filePath  string
	saveTimer *time.Timer
	logger    *zap.Logger
	cancel    context.CancelFunc
}

// NewStore creates a store, loading persisted data if filePath is set.
func NewStore(filePath string, logger *zap.Logger) (*Store, error) {
	s := &Store{
		records:  make(map[string]*BanRecord),
		hits:     make(map[string]*hitRecord),
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
// Expired entries are lazily deleted to prevent memory leaks.
func (s *Store) IsBanned(ip string) bool {
	s.mu.RLock()
	r, ok := s.records[ip]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	expired := r.ExpiresAt != nil && time.Now().After(*r.ExpiresAt)
	s.mu.RUnlock()

	if expired {
		s.mu.Lock()
		if r, ok := s.records[ip]; ok && r.ExpiresAt != nil && time.Now().After(*r.ExpiresAt) {
			delete(s.records, ip)
		}
		s.mu.Unlock()
		return false
	}
	return true
}

// Ban adds an IP to the blacklist.
func (s *Store) Ban(ip, reason, host string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &BanRecord{IP: ip, Reason: reason, Host: host, BannedAt: time.Now()}
	if duration > 0 {
		exp := time.Now().Add(duration)
		r.ExpiresAt = &exp
	}
	s.records[ip] = r
	s.debounceSave()
}

// debounceSave schedules a debounced save. Must be called while holding s.mu.Lock().
func (s *Store) debounceSave() {
	if s.filePath == "" {
		return
	}
	if s.saveTimer != nil {
		s.saveTimer.Stop()
	}
	s.saveTimer = time.AfterFunc(time.Second, func() {
		if err := s.save(); err != nil && s.logger != nil {
			s.logger.Warn("persist save failed", zap.Error(err))
		}
	})
}

// RecordHit increments the hit counter for an IP within a sliding window.
// Returns the current count. If the window has elapsed, the counter resets.
func (s *Store) RecordHit(ip string, window time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	h, ok := s.hits[ip]
	if !ok || now.Sub(h.firstHit) > h.window {
		// Prevent unbounded growth from distributed scanning attacks.
		// When full, silently drop new entries to avoid false-positive bans.
		if !ok && len(s.hits) >= maxHitEntries {
			return 0
		}
		s.hits[ip] = &hitRecord{count: 1, firstHit: now, window: window}
		return 1
	}
	h.count++
	return h.count
}

// ClearHits removes the hit counter for an IP (called after banning).
func (s *Store) ClearHits(ip string) {
	s.mu.Lock()
	delete(s.hits, ip)
	s.mu.Unlock()
}

// Cleanup removes expired entries and persists the result.
func (s *Store) Cleanup() {
	s.mu.Lock()
	if s.saveTimer != nil {
		s.saveTimer.Stop()
	}
	now := time.Now()
	for ip, r := range s.records {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			delete(s.records, ip)
		}
	}
	for ip, h := range s.hits {
		if now.Sub(h.firstHit) > h.window {
			delete(s.hits, ip)
		}
	}
	s.mu.Unlock()

	if s.filePath != "" {
		if err := s.save(); err != nil && s.logger != nil {
			s.logger.Warn("cleanup persist save failed", zap.Error(err))
		}
	}
}

// StartCleanup begins a background goroutine that periodically removes expired entries.
// Uses its own context because Store is shared via UsagePool — its lifecycle is
// managed by reference counting, not by any single module's context.
func (s *Store) StartCleanup(interval time.Duration) {
	if s.cancel != nil {
		return // already started
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
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

// Stop terminates the cleanup goroutine.
func (s *Store) Stop() {
	if s.cancel != nil {
		s.cancel()
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
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
