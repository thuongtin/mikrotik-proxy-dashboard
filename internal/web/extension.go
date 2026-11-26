//go:build !private

package web

import (
	"net/http"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/i18n"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
)

// These hooks let an edition add tunnel profiles (see
// proxy.RegisterTunnelProtocol) and the API that manages their tunnels.
// The core edition has none, so they do nothing.

// extension is the edition's state on the server.
type extension struct{}

// extensionRoutes registers the edition's API endpoints.
func (s *Server) extensionRoutes() {}

// syncTunnels starts and stops tunnels to match the saved assignments.
// It runs under opMu.
func (s *Server) syncTunnels() {}

// checkTunnelProfile reports whether a validated tunnel profile can be
// saved, answering the request itself when it cannot.
func (s *Server) checkTunnelProfile(http.ResponseWriter, *i18n.Translator, *proxy.Proxy) bool {
	return true
}

// tunnelTestBlocked reports whether a profile cannot be tested now, answering
// the request itself when so.
func (s *Server) tunnelTestBlocked(http.ResponseWriter, *i18n.Translator, *proxy.Proxy) bool {
	return false
}
