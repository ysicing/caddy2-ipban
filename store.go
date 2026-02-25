package ipban

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// BanRecord represents a single banned IP entry.
type BanRecord struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Store manages banned IPs with optional file persistence.
type Store struct {
	mu        sync.RWMutex
	records   map[string]*BanRecord
	filePath  string
	saveTimer *time.Timer
}

// NewStore creates a store, loading persisted data if filePath is set.
func NewStore(filePath string) (*Store, error) {
	s := &Store{
		records:  make(map[string]*BanRecord),
		filePath: filePath,
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
	expired := !r.ExpiresAt.IsZero() && time.Now().After(r.ExpiresAt)
	s.mu.RUnlock()

	if expired {
		s.mu.Lock()
		if r, ok := s.records[ip]; ok && !r.ExpiresAt.IsZero() && time.Now().After(r.ExpiresAt) {
			delete(s.records, ip)
		}
		s.mu.Unlock()
		return false
	}
	return true
}

// Ban adds an IP to the blacklist.
func (s *Store) Ban(ip, reason string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &BanRecord{IP: ip, Reason: reason, BannedAt: time.Now()}
	if duration > 0 {
		r.ExpiresAt = time.Now().Add(duration)
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
		s.mu.RLock()
		defer s.mu.RUnlock()
		_ = s.save()
	})
}

// Cleanup removes expired entries and persists the result.
func (s *Store) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveTimer != nil {
		s.saveTimer.Stop()
	}
	now := time.Now()
	for ip, r := range s.records {
		if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			delete(s.records, ip)
		}
	}
	if s.filePath != "" {
		_ = s.save()
	}
}

// StartCleanup begins a background goroutine that periodically removes expired entries.
// The goroutine exits when ctx is cancelled (standard Caddy lifecycle pattern).
func (s *Store) StartCleanup(ctx context.Context, interval time.Duration) {
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
		if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			continue
		}
		s.records[r.IP] = r
	}
	return nil
}

func (s *Store) save() error {
	records := make([]*BanRecord, 0, len(s.records))
	now := time.Now()
	for _, r := range s.records {
		if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			continue
		}
		records = append(records, r)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.filePath, data, 0644)
}

// atomicWriteFile writes data to a temp file then renames it into place,
// preventing corruption on crash or partial write.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
