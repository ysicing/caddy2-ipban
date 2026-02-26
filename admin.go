package ipban

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

var (
	activeStore    *Store
	activeIPSet    *IPSet
	activeGlobalMu sync.RWMutex
)

func init() {
	caddy.RegisterModule(AdminAPI{})
}

// AdminAPI provides admin endpoints for managing banned IPs.
//
// Endpoints:
//
//	GET  /ipban/banned  — list all currently banned IPs
//	POST /ipban/unban   — unban an IP: {"ip": "1.2.3.4"}
type AdminAPI struct{}

func (AdminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.ipban",
		New: func() caddy.Module { return new(AdminAPI) },
	}
}

func (a AdminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{Pattern: "/ipban/banned", Handler: caddy.AdminHandlerFunc(a.handleList)},
		{Pattern: "/ipban/unban", Handler: caddy.AdminHandlerFunc(a.handleUnban)},
	}
}

func (a AdminAPI) handleList(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Message: "method not allowed"}
	}
	store := getStore()
	if store == nil {
		return caddy.APIError{HTTPStatus: http.StatusServiceUnavailable, Message: "ipban not active"}
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(store.ListBanned())
}

func (a AdminAPI) handleUnban(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Message: "method not allowed"}
	}
	store := getStore()
	if store == nil {
		return caddy.APIError{HTTPStatus: http.StatusServiceUnavailable, Message: "ipban not active"}
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&req); err != nil {
		return caddy.APIError{HTTPStatus: http.StatusBadRequest, Message: "invalid JSON body"}
	}
	if net.ParseIP(req.IP) == nil {
		return caddy.APIError{HTTPStatus: http.StatusBadRequest, Message: "invalid IP address"}
	}

	unbanned := store.Unban(req.IP)

	// Always attempt ipset removal — the IP may have expired from memory
	// but still be blocked at the kernel level.
	if ipset := getIPSet(); ipset != nil {
		_ = ipset.Del(req.IP)
	}

	if !unbanned {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"not in ban list, ipset cleanup attempted"}`))
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"message":"unbanned"}`))
	return nil
}

func getStore() *Store {
	activeGlobalMu.RLock()
	defer activeGlobalMu.RUnlock()
	return activeStore
}

func getIPSet() *IPSet {
	activeGlobalMu.RLock()
	defer activeGlobalMu.RUnlock()
	return activeIPSet
}

func setActiveStore(s *Store) {
	activeGlobalMu.Lock()
	activeStore = s
	activeGlobalMu.Unlock()
}

func setActiveIPSet(ipset *IPSet) {
	activeGlobalMu.Lock()
	activeIPSet = ipset
	activeGlobalMu.Unlock()
}

// Interface guard
var _ caddy.AdminRouter = AdminAPI{}
