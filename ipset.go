package ipban

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
)

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
	return exec.Command("ipset", "add", s.name, ip, "-exist").Run()
}

func (s *IPSet) init() bool {
	if _, err := exec.LookPath("ipset"); err != nil {
		return false
	}
	// Check if set exists (-t = headers only, avoids dumping all entries)
	if err := exec.Command("ipset", "list", s.name, "-t").Run(); err == nil {
		return true
	}
	// Try to create it
	return exec.Command("ipset", "create", s.name, "hash:ip").Run() == nil
}
