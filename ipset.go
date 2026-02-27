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

// ipsetTimeout is the maximum time allowed for a single ipset/nft command.
const ipsetTimeout = 10 * time.Second

// nftTableName is the nftables table used for IP banning.
const nftTableName = "ipban_caddy"

// validIPSetName restricts ipset names to safe characters only.
var validIPSetName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// IPSet wraps the Linux ipset command for kernel-level IP blocking.
// Supports batched async adds via a background worker to avoid
// forking thousands of processes under burst traffic.
// Automatically manages iptables/ip6tables rules to DROP traffic from banned IPs.
type IPSet struct {
	name      string
	ipv6      bool // true for IPv6 (hash:ip family inet6 + ip6tables)
	available bool
	useNft    bool // true when using nftables backend
	logger    *zap.Logger

	// iptables rule management (ipset backend only)
	iptablesManaged bool // true if we added the iptables rule

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
// Removes the nftables table or iptables rule depending on backend.
func (s *IPSet) Destruct() error {
	s.Stop()
	if s.useNft {
		s.removeNftTable()
	} else {
		s.removeIptablesRule()
	}
	return nil
}

// QueueAdd enqueues an IP for batched addition to the kernel set.
// Non-blocking: if the channel is full, the IP is dropped (still banned in-memory).
// The IP must already be validated by the caller (ServeHTTP path validates via net.ParseIP).
func (s *IPSet) QueueAdd(ip string) {
	if !s.available || s.banCh == nil || s.stopped.Load() {
		return
	}
	if net.ParseIP(ip) == nil {
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

// nftElementCmd executes an nft element operation (add/delete) via stdin.
func (s *IPSet) nftElementCmd(ctx context.Context, action, ip string) error {
	script := fmt.Sprintf("%s element %s %s %s { %s }\n", action, s.nftFamily(), nftTableName, s.name, ip)
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	return cmd.Run()
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
	if s.useNft {
		return s.nftElementCmd(ctx, "add", ip)
	}
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
	if s.useNft {
		return s.nftElementCmd(ctx, "delete", ip)
	}
	return exec.CommandContext(ctx, "ipset", "del", s.name, ip, "-exist").Run()
}

// AddBatch inserts multiple IPs in a single process.
// No-op if unavailable or ips is empty.
// All IPs are assumed pre-validated by callers (QueueAdd validates via net.ParseIP).
func (s *IPSet) AddBatch(ips []string) error {
	if !s.available || len(ips) == 0 {
		return nil
	}
	if s.useNft {
		family := s.nftFamily()
		var buf strings.Builder
		buf.Grow(60 + len(ips)*18)
		buf.WriteString("add element ")
		buf.WriteString(family)
		buf.WriteByte(' ')
		buf.WriteString(nftTableName)
		buf.WriteByte(' ')
		buf.WriteString(s.name)
		buf.WriteString(" { ")
		for i, ip := range ips {
			if i > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(ip)
		}
		buf.WriteString(" }\n")
		ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(buf.String())
		return cmd.Run()
	}
	var buf strings.Builder
	for _, ip := range ips {
		buf.WriteString("add ")
		buf.WriteString(s.name)
		buf.WriteByte(' ')
		buf.WriteString(ip)
		buf.WriteString(" -exist\n")
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ipset", "restore")
	cmd.Stdin = strings.NewReader(buf.String())
	return cmd.Run()
}

func (s *IPSet) init() bool {
	if s.initNft() {
		return true
	}
	return s.initIpset()
}

// nftFamily returns the nftables family string for this set.
func (s *IPSet) nftFamily() string {
	if s.ipv6 {
		return "ip6"
	}
	return "ip"
}

// nftAddrType returns the nftables address type for this set.
func (s *IPSet) nftAddrType() string {
	if s.ipv6 {
		return "ipv6_addr"
	}
	return "ipv4_addr"
}

// nftSaddr returns the nftables source address match expression.
func (s *IPSet) nftSaddr() string {
	if s.ipv6 {
		return "ip6 saddr"
	}
	return "ip saddr"
}

// initNft tries to set up nftables-based blocking. Returns true on success.
func (s *IPSet) initNft() bool {
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	family := s.nftFamily()
	// Check if our set already exists
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	if exec.CommandContext(ctx, "nft", "list", "set", family, nftTableName, s.name).Run() == nil {
		s.useNft = true
		return true
	}
	// Create table, set, chain, and rule via stdin.
	// flush chain ensures no duplicate drop rules from prior unclean shutdown.
	script := fmt.Sprintf(
		"add table %s %s\nadd set %s %s %s { type %s; }\nadd chain %s %s input { type filter hook input priority -1; policy accept; }\nflush chain %s %s input\nadd rule %s %s input %s @%s drop\n",
		family, nftTableName,
		family, nftTableName, s.name, s.nftAddrType(),
		family, nftTableName,
		family, nftTableName,
		family, nftTableName, s.nftSaddr(), s.name,
	)
	ctx2, cancel2 := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel2()
	cmd := exec.CommandContext(ctx2, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if err := cmd.Run(); err != nil {
		if s.logger != nil {
			s.logger.Debug("nftables init failed, falling back to ipset",
				zap.String("family", family), zap.Error(err))
		}
		return false
	}
	s.useNft = true
	if s.logger != nil {
		s.logger.Info("nftables set and rule created", zap.String("family", family), zap.String("set", s.name))
	}
	return true
}

// initIpset tries to set up ipset-based blocking. Returns true on success.
func (s *IPSet) initIpset() bool {
	if _, err := exec.LookPath("ipset"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	// Check if set exists (-t = headers only, avoids dumping all entries)
	if err := exec.CommandContext(ctx, "ipset", "list", s.name, "-t").Run(); err == nil {
		s.ensureIptablesRule()
		return true
	}
	// Try to create it with maxelem matching maxBanEntries to avoid silent failures.
	ctx2, cancel2 := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel2()
	args := []string{"create", s.name, "hash:ip", "maxelem", "131072"}
	if s.ipv6 {
		args = append(args, "family", "inet6")
	}
	if exec.CommandContext(ctx2, "ipset", args...).Run() != nil {
		return false
	}
	s.ensureIptablesRule()
	return true
}

// iptablesRuleArgs returns the iptables arguments for the DROP rule referencing this ipset.
// The action parameter should be "-C" (check), "-I" (insert), or "-D" (delete).
func (s *IPSet) iptablesRuleArgs(action string) []string {
	return []string{action, "INPUT", "-m", "set", "--match-set", s.name, "src", "-j", "DROP"}
}

// fwCmd returns the firewall command for this set's address family.
func (s *IPSet) fwCmd() string {
	if s.ipv6 {
		return "ip6tables"
	}
	return "iptables"
}

// ensureIptablesRule adds an iptables/ip6tables DROP rule referencing this ipset if not already present.
func (s *IPSet) ensureIptablesRule() {
	fw := s.fwCmd()
	if _, err := exec.LookPath(fw); err != nil {
		if s.logger != nil {
			s.logger.Debug(fw+" not found, skipping firewall rule")
		}
		return
	}
	// Check if rule already exists
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	if exec.CommandContext(ctx, fw, s.iptablesRuleArgs("-C")...).Run() == nil {
		if s.logger != nil {
			s.logger.Debug(fw+" rule already exists", zap.String("set", s.name))
		}
		return
	}
	// Add the rule
	ctx2, cancel2 := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel2()
	if err := exec.CommandContext(ctx2, fw, s.iptablesRuleArgs("-I")...).Run(); err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to add "+fw+" rule", zap.String("set", s.name), zap.Error(err))
		}
		return
	}
	s.iptablesManaged = true
	if s.logger != nil {
		s.logger.Info(fw+" DROP rule added", zap.String("set", s.name))
	}
}

// removeNftTable deletes the nftables table (which removes all sets, chains, and rules within it).
func (s *IPSet) removeNftTable() {
	family := s.nftFamily()
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	if err := exec.CommandContext(ctx, "nft", "delete", "table", family, nftTableName).Run(); err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to remove nftables table", zap.String("family", family), zap.Error(err))
		}
		return
	}
	if s.logger != nil {
		s.logger.Info("nftables table removed", zap.String("family", family))
	}
}

// removeIptablesRule removes the iptables/ip6tables DROP rule if we added it.
func (s *IPSet) removeIptablesRule() {
	if !s.iptablesManaged {
		return
	}
	fw := s.fwCmd()
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	if err := exec.CommandContext(ctx, fw, s.iptablesRuleArgs("-D")...).Run(); err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to remove "+fw+" rule", zap.String("set", s.name), zap.Error(err))
		}
		return
	}
	s.iptablesManaged = false
	if s.logger != nil {
		s.logger.Info(fw+" DROP rule removed", zap.String("set", s.name))
	}
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
// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) route to v4.
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
