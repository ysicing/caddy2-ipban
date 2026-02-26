package ipban

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ipsetTimeout is the maximum time allowed for a single ipset command.
const ipsetTimeout = 10 * time.Second

// validIPSetName restricts ipset names to safe characters only.
var validIPSetName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// IPSet wraps the Linux ipset command for kernel-level IP blocking.
type IPSet struct {
	name      string
	available bool
}

// NewIPSet creates an IPSet handle. If the set doesn't exist it tries to create one.
// Names containing invalid characters are rejected (available=false).
func NewIPSet(name string) *IPSet {
	s := &IPSet{name: name}
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
