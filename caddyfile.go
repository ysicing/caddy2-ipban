package ipban

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	ipban {
//	    rule_source /etc/caddy/rules.json  OR  https://example.com/rules.json
//	    refresh_interval 1h
//	    ipset_name blacklist
//	    status_codes 400 403 404 429
//	    ban_duration 24h
//	    allow 10.0.0.0/8 192.168.0.0/16
//	    threshold 3
//	    threshold_window 1h
//	}
func (m *IPBan) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "rule_source":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.RuleSource = d.Val()
		case "refresh_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid refresh_interval: %s", d.Val())
			}
			m.RefreshInterval = caddy.Duration(dur)
		case "ipset_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.IPSetName = d.Val()
		case "status_codes":
			for d.NextArg() {
				code, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid status code: %s", d.Val())
				}
				m.StatusCodes = append(m.StatusCodes, code)
			}
		case "ban_duration":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid ban_duration: %s", d.Val())
			}
			m.BanDuration = caddy.Duration(dur)
		case "allow":
			for d.NextArg() {
				for _, entry := range strings.Fields(d.Val()) {
					m.Allowlist = append(m.Allowlist, entry)
				}
			}
			if len(m.Allowlist) == 0 {
				return d.ArgErr()
			}
		case "threshold":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil || n < 1 {
				return d.Errf("invalid threshold: %s", d.Val())
			}
			m.Threshold = n
		case "threshold_window":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid threshold_window: %s", d.Val())
			}
			m.ThresholdWindow = caddy.Duration(dur)
		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m IPBan
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards
var (
	_ caddy.Module                = (*IPBan)(nil)
	_ caddy.Provisioner           = (*IPBan)(nil)
	_ caddy.Validator             = (*IPBan)(nil)
	_ caddy.CleanerUpper          = (*IPBan)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPBan)(nil)
	_ caddyfile.Unmarshaler       = (*IPBan)(nil)
)
