package ipban

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// RuleFile is the top-level JSON structure, inspired by sing-box rule format.
type RuleFile struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Rule defines a single matching rule.
type Rule struct {
	// Path matches exact request paths (case-insensitive).
	Path []string `json:"path,omitempty"`
	// PathPrefix matches request path prefixes (case-insensitive).
	PathPrefix []string `json:"path_prefix,omitempty"`
	// PathKeyword matches if the path contains any keyword (case-insensitive).
	PathKeyword []string `json:"path_keyword,omitempty"`
	// PathRegex matches the path against regular expressions.
	PathRegex []string `json:"path_regex,omitempty"`
	// UserAgentKeyword matches if User-Agent contains any keyword (case-insensitive).
	UserAgentKeyword []string `json:"user_agent_keyword,omitempty"`
	// UserAgentRegex matches User-Agent against regular expressions.
	UserAgentRegex []string `json:"user_agent_regex,omitempty"`
	// Invert negates the match result.
	Invert bool `json:"invert,omitempty"`
}

// compiledRule is a Rule with pre-compiled regexes and pre-lowercased patterns.
type compiledRule struct {
	rule           Rule
	pathRegex      []*regexp.Regexp
	userAgentRegex []*regexp.Regexp

	// Pre-computed for hot-path matching (avoid per-request allocations).
	pathMap          map[string]bool // O(1) exact path lookup
	pathPrefixLower  []string
	pathKeywordLower []string
	uaKeywordLower   []string
}

func compileRule(r Rule) (*compiledRule, error) {
	cr := &compiledRule{rule: r}

	// Pre-lowercase string patterns to avoid per-request allocations.
	cr.pathMap = make(map[string]bool, len(r.Path))
	for _, p := range r.Path {
		cr.pathMap[strings.ToLower(p)] = true
	}
	cr.pathPrefixLower = make([]string, len(r.PathPrefix))
	for i, p := range r.PathPrefix {
		cr.pathPrefixLower[i] = strings.ToLower(p)
	}
	cr.pathKeywordLower = make([]string, len(r.PathKeyword))
	for i, kw := range r.PathKeyword {
		cr.pathKeywordLower[i] = strings.ToLower(kw)
	}
	cr.uaKeywordLower = make([]string, len(r.UserAgentKeyword))
	for i, kw := range r.UserAgentKeyword {
		cr.uaKeywordLower[i] = strings.ToLower(kw)
	}

	for _, p := range r.PathRegex {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("invalid path_regex %q: %w", p, err)
		}
		cr.pathRegex = append(cr.pathRegex, re)
	}
	for _, p := range r.UserAgentRegex {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("invalid user_agent_regex %q: %w", p, err)
		}
		cr.userAgentRegex = append(cr.userAgentRegex, re)
	}
	return cr, nil
}

func (cr *compiledRule) matchRequest(path, ua string) bool {
	matched := cr.matchInner(path, ua)
	if cr.rule.Invert {
		return !matched
	}
	return matched
}

func (cr *compiledRule) matchInner(path, ua string) bool {
	lp := strings.ToLower(path)
	if cr.pathMap[lp] {
		return true
	}
	for _, p := range cr.pathPrefixLower {
		if strings.HasPrefix(lp, p) {
			return true
		}
	}
	for _, kw := range cr.pathKeywordLower {
		if strings.Contains(lp, kw) {
			return true
		}
	}
	for _, re := range cr.pathRegex {
		if re.MatchString(path) {
			return true
		}
	}
	if ua != "" {
		lua := strings.ToLower(ua)
		for _, kw := range cr.uaKeywordLower {
			if strings.Contains(lua, kw) {
				return true
			}
		}
		for _, re := range cr.userAgentRegex {
			if re.MatchString(ua) {
				return true
			}
		}
	}
	return false
}

// compileRuleFile compiles all rules in a RuleFile.
func compileRuleFile(rf *RuleFile) ([]*compiledRule, error) {
	var out []*compiledRule
	for i := range rf.Rules {
		cr, err := compileRule(rf.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", i, err)
		}
		out = append(out, cr)
	}
	return out, nil
}

func parseAndCompile(data []byte) ([]*compiledRule, error) {
	var rf RuleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if rf.Version != 1 {
		return nil, fmt.Errorf("unsupported rule version: %d", rf.Version)
	}
	return compileRuleFile(&rf)
}

func loadFromFile(path string) ([]*compiledRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseAndCompile(data)
}

// fetchResult holds the result of a remote rule fetch.
type fetchResult struct {
	rules   []*compiledRule
	etag    string
	data    []byte // raw JSON for caching
	changed bool   // false if 304 Not Modified
}

// fetchFromURL downloads rules, using ETag for conditional requests.
func fetchFromURL(url, lastETag string) (*fetchResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "caddy-ipban/1.0")
	req.Header.Set("Accept", "application/json")
	if lastETag != "" {
		req.Header.Set("If-None-Match", lastETag)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return &fetchResult{changed: false}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, err
	}
	rules, err := parseAndCompile(data)
	if err != nil {
		return nil, err
	}
	return &fetchResult{
		rules:   rules,
		etag:    resp.Header.Get("ETag"),
		data:    data,
		changed: true,
	}, nil
}
