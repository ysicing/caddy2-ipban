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
	available bool
	logger    *zap.Logger

	// Batching: QueueAdd sends IPs here; the worker flushes via AddBatch.
	banCh    chan string
	stopped  atomic.Bool // set by Stop() before closing banCh
	stopOnce sync.Once
	done     chan struct{}
}

// NewIPSet creates an IPSet handle. If the set doesn't exist it tries to create one.
// Names containing invalid characters are rejected (available=false).
func NewIPSet(name string, logger *zap.Logger) *IPSet {
	s := &IPSet{name: name, logger: logger}
	if name != "" {
		if !validIPSetName.MatchString(name) {
			return s // available remains false
		}
		s.available = s.init()
	}
	return s
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
func (s *IPSet) QueueAdd(ip string) {
	if !s.available || s.banCh == nil || s.stopped.Load() {
		return
	}
	if net.ParseIP(ip) == nil {
		return
	}
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

// Add inserts an IP into the set. No-op if ipset is unavailable.
// The IP is validated before passing to the ipset command.
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

// Del removes an IP from the set. No-op if ipset is unavailable.
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

// AddBatch inserts multiple IPs via `ipset restore` in a single process.
// No-op if ipset is unavailable or ips is empty.
func (s *IPSet) AddBatch(ips []string) error {
	if !s.available || len(ips) == 0 {
		return nil
	}
	var buf strings.Builder
	for _, ip := range ips {
		if net.ParseIP(ip) != nil {
			fmt.Fprintf(&buf, "add %s %s -exist\n", s.name, ip)
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
	// Try to create it
	ctx2, cancel2 := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel2()
	return exec.CommandContext(ctx2, "ipset", "create", s.name, "hash:ip").Run() == nil
}
