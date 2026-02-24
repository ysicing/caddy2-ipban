package ipban

import (
	"net"
	"os/exec"
)

// IPSet wraps the Linux ipset command for kernel-level IP blocking.
type IPSet struct {
	name      string
	available bool
}

// NewIPSet creates an IPSet handle. If the set doesn't exist it tries to create one.
func NewIPSet(name string) *IPSet {
	s := &IPSet{name: name}
	if name != "" {
		s.available = s.init()
	}
	return s
}

// Available reports whether ipset can be used.
func (s *IPSet) Available() bool { return s.available }

// Add inserts an IP into the set. No-op if ipset is unavailable.
func (s *IPSet) Add(ip string) error {
	if !s.available {
		return nil
	}
	// Normalize: strip port, handle IPv6 brackets
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	return exec.Command("ipset", "add", s.name, host, "-exist").Run()
}

func (s *IPSet) init() bool {
	if _, err := exec.LookPath("ipset"); err != nil {
		return false
	}
	// Check if set exists
	if err := exec.Command("ipset", "list", s.name).Run(); err == nil {
		return true
	}
	// Try to create it
	return exec.Command("ipset", "create", s.name, "hash:ip").Run() == nil
}
