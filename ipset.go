package ipban

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ipsetTimeout is the maximum time allowed for a single ipset command.
const ipsetTimeout = 10 * time.Second

// validIPSetName restricts ipset names to safe characters only.
var validIPSetName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// IPSet wraps the Linux ipset command for kernel-level IP blocking.
// Supports batched async adds via a background worker to avoid
// forking thousands of processes under burst traffic.
type IPSet struct {
	name      string
	ipv6      bool // true for IPv6 (hash:ip family inet6)
	available bool
	logger    *zap.Logger

	// Batching: QueueAdd sends IPs here; the worker flushes via AddBatch.
	banCh    chan string
	stopped  atomic.Bool // set by Stop() before closing banCh
	stopOnce sync.Once
	done     chan struct{}
}

// newIPSet creates an IPSet handle for a specific address family.
// If the set doesn't exist it tries to create one.
func newIPSet(name string, ipv6 bool, logger *zap.Logger) *IPSet {
	s := &IPSet{name: name, ipv6: ipv6, logger: logger}
	if name != "" {
		if !validIPSetName.MatchString(name) {
			return s // available remains false
		}
		s.available = s.init()
	}
	return s
}

// NewIPSet creates an IPv4 IPSet handle. If the set doesn't exist it tries to create one.
// Names containing invalid characters are rejected (available=false).
func NewIPSet(name string, logger *zap.Logger) *IPSet {
	return newIPSet(name, false, logger)
}

// Available reports whether ipset can be used.
func (s *IPSet) Available() bool { return s.available }

// Start launches the background batch worker. No-op if ipset is unavailable.
func (s *IPSet) Start() {
	if !s.available {
		return
	}
	s.banCh = make(chan string, 1024)
	s.done = make(chan struct{})
	go s.batchWorker()
}

// Stop shuts down the batch worker and flushes pending IPs.
func (s *IPSet) Stop() {
	s.stopOnce.Do(func() {
		if s.banCh != nil {
			s.stopped.Store(true)
			close(s.banCh)
			<-s.done // wait for worker to drain and exit
		}
	})
}

// Destruct implements caddy.Destructor for UsagePool ref-counting.
func (s *IPSet) Destruct() error {
	s.Stop()
	return nil
}

// QueueAdd enqueues an IP for batched addition to the kernel set.
// Non-blocking: if the channel is full, the IP is dropped (still banned in-memory).
// The IP must already be validated by the caller (ServeHTTP path validates via net.ParseIP).
func (s *IPSet) QueueAdd(ip string) {
	if !s.available || s.banCh == nil || s.stopped.Load() {
		return
	}
	// Recover from send-on-closed-channel during the tiny window between
	// stopped.Load() and close(banCh) in Stop().
	defer func() { recover() }()
	select {
	case s.banCh <- ip:
	default:
		if s.logger != nil {
			s.logger.Warn("ipset batch channel full, dropping add",
				zap.String("ip", ip))
		}
	}
}

// batchWorker collects IPs from banCh and flushes them via AddBatch
// every 2 seconds or when 100 IPs accumulate, whichever comes first.
func (s *IPSet) batchWorker() {
	defer close(s.done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var pending []string

	flush := func() {
		if len(pending) == 0 {
			return
		}
		if err := s.AddBatch(pending); err != nil && s.logger != nil {
			s.logger.Warn("ipset batch add failed", zap.Error(err), zap.Int("count", len(pending)))
		}
		pending = pending[:0]
	}

	for {
		select {
		case ip, ok := <-s.banCh:
			if !ok {
				flush()
				return
			}
			pending = append(pending, ip)
			if len(pending) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Add inserts an IP into the set. No-op if unavailable.
// The IP is validated before passing to the command.
func (s *IPSet) Add(ip string) error {
	if !s.available {
		return nil
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("ipset: invalid IP %q", ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "ipset", "add", s.name, ip, "-exist").Run()
}

// Del removes an IP from the set. No-op if unavailable.
func (s *IPSet) Del(ip string) error {
	if !s.available {
		return nil
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("ipset: invalid IP %q", ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "ipset", "del", s.name, ip, "-exist").Run()
}

// AddBatch inserts multiple IPs in a single process.
// No-op if unavailable or ips is empty.
// Invalid IPs are silently skipped as a defense-in-depth measure.
func (s *IPSet) AddBatch(ips []string) error {
	if !s.available || len(ips) == 0 {
		return nil
	}
	var buf strings.Builder
	for _, ip := range ips {
		if net.ParseIP(ip) != nil {
			buf.WriteString("add ")
			buf.WriteString(s.name)
			buf.WriteByte(' ')
			buf.WriteString(ip)
			buf.WriteString(" -exist\n")
		}
	}
	if buf.Len() == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ipset", "restore")
	cmd.Stdin = strings.NewReader(buf.String())
	return cmd.Run()
}

// IPSetManager wraps a v4 and v6 IPSet pair, routing operations by address family.
type IPSetManager struct {
	v4 *IPSet
	v6 *IPSet
}

// NewIPSetManager creates an IPSetManager with separate v4/v6 ipset instances.
func NewIPSetManager(nameV4, nameV6 string, logger *zap.Logger) *IPSetManager {
	return &IPSetManager{
		v4: newIPSet(nameV4, false, logger),
		v6: newIPSet(nameV6, true, logger),
	}
}

// Available reports whether at least one of v4/v6 ipset can be used.
func (m *IPSetManager) Available() bool {
	return m.v4.Available() || m.v6.Available()
}

// Start launches background batch workers for both sets.
func (m *IPSetManager) Start() {
	m.v4.Start()
	m.v6.Start()
}

// Stop shuts down both batch workers.
func (m *IPSetManager) Stop() {
	m.v4.Stop()
	m.v6.Stop()
}

// Destruct implements caddy.Destructor for UsagePool ref-counting.
func (m *IPSetManager) Destruct() error {
	_ = m.v4.Destruct()
	_ = m.v6.Destruct()
	return nil
}

// route returns the appropriate IPSet for the given IP string.
// IPv4 and IPv4-mapped IPv6 addresses route to v4.
func (m *IPSetManager) route(ip string) *IPSet {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return m.v4 // fallback; callers validate before reaching here
	}
	if parsed.To4() != nil {
		return m.v4
	}
	return m.v6
}

// QueueAdd enqueues an IP for batched addition, routing to the correct set.
func (m *IPSetManager) QueueAdd(ip string) {
	m.route(ip).QueueAdd(ip)
}

// Add inserts an IP into the correct set.
func (m *IPSetManager) Add(ip string) error {
	return m.route(ip).Add(ip)
}

// Del removes an IP from the correct set.
func (m *IPSetManager) Del(ip string) error {
	return m.route(ip).Del(ip)
}

// AddBatch inserts multiple IPs, splitting them across v4/v6 sets.
func (m *IPSetManager) AddBatch(ips []string) error {
	var v4ips, v6ips []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			v4ips = append(v4ips, ip)
		} else {
			v6ips = append(v6ips, ip)
		}
	}
	var firstErr error
	if err := m.v4.AddBatch(v4ips); err != nil {
		firstErr = err
	}
	if err := m.v6.AddBatch(v6ips); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (s *IPSet) init() bool {
	if _, err := exec.LookPath("ipset"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	// Check if set exists (-t = headers only, avoids dumping all entries)
	if err := exec.CommandContext(ctx, "ipset", "list", s.name, "-t").Run(); err == nil {
		return true
	}
	// Try to create it with maxelem matching maxBanEntries to avoid silent failures.
	ctx2, cancel2 := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel2()
	args := []string{"create", s.name, "hash:ip", "maxelem", "131072"}
	if s.ipv6 {
		args = append(args, "family", "inet6")
	}
	return exec.CommandContext(ctx2, "ipset", args...).Run() == nil
}
