package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/auth"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/config"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/i18n"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/mikrotik"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/singbox"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
)

const (
	// maxBodyBytes caps every request body.
	maxBodyBytes = 1 << 20
	// maxNameRunes caps device nicknames and proxy names.
	maxNameRunes = 64

	// The frontend only loads its own script and stylesheet. Inline style
	// attributes are still used by the markup, inline scripts are not.
	contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; " +
		"form-action 'self'; frame-ancestors 'none'"
)

// Steps reported in error responses so the UI can say which part failed.
const (
	stepLease       = "lease"
	stepAddressList = "address-list"
	stepIPv6        = "ipv6"
	stepState       = "state"
	stepSingbox     = "singbox"
	stepFlush       = "flush"
	stepRouter      = "router"
)

// Server coordinates HTTP API routing and embedded frontend serving.
type Server struct {
	cfg        *config.Config
	authMgr    *auth.AuthManager
	state      *state.State
	supervisor *singbox.Supervisor
	mikrotik   *mikrotik.Client
	staticFS   fs.FS
	mux        *http.ServeMux

	// opMu serializes operations that change router rules, state and the
	// sing-box configuration together, so their rollbacks cannot interleave.
	opMu sync.Mutex
	// applyConfig hands a generated configuration to sing-box.
	applyConfig func([]byte) error
}

// NewServer initializes the HTTP API and frontend router.
func NewServer(
	cfg *config.Config,
	authMgr *auth.AuthManager,
	st *state.State,
	sup *singbox.Supervisor,
	mk *mikrotik.Client,
	staticFS fs.FS,
) *Server {
	s := &Server{
		cfg:         cfg,
		authMgr:     authMgr,
		state:       st,
		supervisor:  sup,
		mikrotik:    mk,
		staticFS:    staticFS,
		mux:         http.NewServeMux(),
		applyConfig: sup.ApplyConfig,
	}

	s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
		// API messages are localized from the language cookie or header.
		h.Add("Vary", "Cookie, Accept-Language")
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// Public auth endpoints
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/auth/me", s.handleAuthMe)

	// Protected API endpoints
	s.mux.HandleFunc("/api/devices", s.requireAuth(s.requireRouter(s.handleDevices)))
	s.mux.HandleFunc("/api/devices/", s.requireAuth(s.requireRouter(s.handleDeviceByIP)))

	s.mux.HandleFunc("/api/proxies", s.requireAuth(s.handleProxies))
	s.mux.HandleFunc("/api/proxies/import", s.requireAuth(s.handleProxiesImport))
	s.mux.HandleFunc("/api/proxies/", s.requireAuth(s.handleProxyByID))

	s.mux.HandleFunc("/api/system/status", s.requireAuth(s.requireRouter(s.handleSystemStatus)))
	s.mux.HandleFunc("/api/system/reconcile", s.requireAuth(s.requireRouter(s.handleSystemReconcile)))
	s.mux.HandleFunc("/api/system/flush-all", s.requireAuth(s.requireRouter(s.handleSystemFlushAll)))
	s.mux.HandleFunc("/api/system/logs", s.requireAuth(s.handleSystemLogs))

	// Embedded Static Frontend
	if s.staticFS != nil {
		fileServer := http.FileServer(http.FS(s.staticFS))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.jsonError(w, http.StatusNotFound, i18n.FromRequest(r).T("api.not_found"))
				return
			}

			// Check if file exists in static FS
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			f, err := s.staticFS.Open(path)
			if err != nil {
				// Fallback to index.html for SPA client-side routing
				r.URL.Path = "/"
			} else {
				_ = f.Close()
			}

			fileServer.ServeHTTP(w, r)
		})
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authMgr.VerifyRequest(r) {
			s.jsonError(w, http.StatusUnauthorized, i18n.FromRequest(r).T("api.unauthorized"))
			return
		}
		next(w, r)
	}
}

// requireRouter answers 503 when the RouterOS client could not be created at
// startup (bad MIKROTIK_URL or CA file), instead of failing deeper down.
func (s *Server) requireRouter(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.mikrotik == nil {
			s.jsonError(w, http.StatusServiceUnavailable, i18n.FromRequest(r).T("api.router_unavailable"))
			return
		}
		next(w, r)
	}
}

func (s *Server) json(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, msg string) {
	s.json(w, status, map[string]string{"error": msg})
}

// stepError is the body of a failed multi-step operation. Applied tells the UI
// whether the requested change took effect despite the failure.
type stepError struct {
	Error   string `json:"error"`
	Step    string `json:"step"`
	Applied bool   `json:"applied"`
}

func (s *Server) jsonStepError(w http.ResponseWriter, step string, applied bool, msg string) {
	s.json(w, http.StatusInternalServerError, stepError{Error: msg, Step: step, Applied: applied})
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	s.jsonError(w, http.StatusMethodNotAllowed, i18n.FromRequest(r).T("api.method_not_allowed"))
}

// decodeJSON reads a JSON body into dst and writes the error response itself.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		tr := i18n.FromRequest(r)
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.jsonError(w, http.StatusRequestEntityTooLarge, tr.T("api.body_too_large"))
		} else {
			s.jsonError(w, http.StatusBadRequest, tr.T("api.body_invalid"))
		}
		return false
	}
	return true
}

// opContext returns a context for an operation that must not stop halfway
// because the browser went away: a half-applied assignment is worse than a
// finished one nobody is waiting for.
func opContext(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), timeout)
}

// normalizeMAC accepts a 48-bit MAC address and returns it lower-case and
// colon-separated, the form used in state and in router rule comments.
func normalizeMAC(raw string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return hw.String(), true
}

// cleanName validates a nickname or proxy name: valid UTF-8, bounded length,
// no control characters. The trimmed value is returned.
func cleanName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxNameRunes {
		return "", false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return name, true
}

// scrubName makes an imported name safe instead of rejecting the whole entry.
func scrubName(raw string) string {
	var b strings.Builder
	count := 0
	for _, r := range strings.TrimSpace(strings.ToValidUTF8(raw, "")) {
		if unicode.IsControl(r) {
			continue
		}
		if count >= maxNameRunes {
			break
		}
		b.WriteRune(r)
		count++
	}
	return strings.TrimSpace(b.String())
}

// Auth Handlers
type loginReq struct {
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r, http.MethodPost)
		return
	}

	var req loginReq
	if !s.decodeJSON(w, r, &req) {
		return
	}

	clientIP := auth.GetClientIP(r)
	cookie, err := s.authMgr.Login(req.Password, clientIP)
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, loginErrorMessage(i18n.FromRequest(r), err))
		return
	}

	http.SetCookie(w, cookie)
	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

// loginErrorMessage turns an auth.Login error into a localized message.
func loginErrorMessage(tr *i18n.Translator, err error) string {
	var locked *auth.LockoutError
	switch {
	case errors.As(err, &locked):
		return tr.T("api.login.locked_out", "count", locked.RemainingSeconds())
	case errors.Is(err, auth.ErrInvalidPassword):
		return tr.T("api.login.invalid_password")
	case errors.Is(err, auth.ErrNoPasswordConfig):
		return tr.T("api.login.no_password")
	default:
		return tr.T("api.login.failed", "err", err)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r, http.MethodPost)
		return
	}
	http.SetCookie(w, s.authMgr.ClearSessionCookie())
	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, r, http.MethodGet)
		return
	}
	authenticated := s.authMgr.VerifyRequest(r)
	s.json(w, http.StatusOK, map[string]bool{"authenticated": authenticated})
}

// Device Handlers
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, r, http.MethodGet)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	devices, err := s.mikrotik.GetDevices(ctx, s.cfg.LanCIDR, s.state)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, i18n.FromRequest(r).T("api.devices.read_failed", "err", err))
		return
	}

	s.json(w, http.StatusOK, devices)
}

func (s *Server) handleDeviceByIP(w http.ResponseWriter, r *http.Request) {
	tr := i18n.FromRequest(r)
	path := strings.TrimPrefix(r.URL.Path, "/api/devices/")
	parts := strings.Split(path, "/")

	// Validate target IP
	parsedIP := net.ParseIP(parts[0])
	if parsedIP == nil {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.device.ip_invalid"))
		return
	}
	// Use the canonical text form as the key everywhere.
	ip := parsedIP.String()

	_, lanNet, err := net.ParseCIDR(s.cfg.LanCIDR)
	if err != nil {
		// Without a valid LAN range the target cannot be checked, so refuse.
		s.jsonError(w, http.StatusInternalServerError, tr.T("api.device.lan_cidr_invalid"))
		return
	}
	if !lanNet.Contains(parsedIP) || s.isReservedLANAddress(parsedIP, lanNet) {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.device.ip_outside_lan"))
		return
	}

	if len(parts) != 2 {
		s.jsonError(w, http.StatusNotFound, tr.T("api.not_found"))
		return
	}

	switch parts[1] {
	case "assignment":
		switch r.Method {
		case http.MethodPut:
			s.handleAssignDevice(w, r, ip)
		case http.MethodDelete:
			s.handleUnassignDevice(w, r, ip)
		default:
			s.methodNotAllowed(w, r, http.MethodPut, http.MethodDelete)
		}

	case "nickname":
		if r.Method != http.MethodPut {
			s.methodNotAllowed(w, r, http.MethodPut)
			return
		}
		var req struct {
			Nickname string `json:"nickname"`
		}
		if !s.decodeJSON(w, r, &req) {
			return
		}
		nickname, ok := cleanName(req.Nickname)
		if !ok {
			s.jsonError(w, http.StatusBadRequest, tr.T("api.device.nickname_invalid", "max", maxNameRunes))
			return
		}
		if err := s.state.SetDeviceNickname(ip, nickname); err != nil {
			s.jsonError(w, http.StatusInternalServerError, tr.T("api.device.nickname_save_failed", "err", err))
			return
		}
		s.json(w, http.StatusOK, map[string]bool{"success": true})

	case "flush":
		if r.Method != http.MethodPost {
			s.methodNotAllowed(w, r, http.MethodPost)
			return
		}
		mac := ""
		if dev := s.state.GetDevice(ip); dev != nil {
			mac = dev.MAC
		}
		ctx, cancel := opContext(r, 10*time.Second)
		defer cancel()
		if err := s.mikrotik.FlushDeviceConnections(ctx, ip, mac); err != nil {
			s.jsonStepError(w, stepFlush, false, tr.T("api.device.flush_failed", "err", err))
			return
		}
		s.json(w, http.StatusOK, map[string]bool{"success": true})

	default:
		s.jsonError(w, http.StatusNotFound, tr.T("api.not_found"))
	}
}

// isReservedLANAddress reports addresses that are never a client device: the
// network and broadcast addresses, the first host (the usual gateway) and the
// router address from MIKROTIK_URL when it lies inside the LAN.
func (s *Server) isReservedLANAddress(ip net.IP, lan *net.IPNet) bool {
	ip4 := ip.To4()
	network := lan.IP.To4()
	if ip4 == nil || network == nil || len(lan.Mask) != net.IPv4len {
		return false
	}
	broadcast := make(net.IP, net.IPv4len)
	firstHost := make(net.IP, net.IPv4len)
	copy(firstHost, network)
	for i := range network {
		broadcast[i] = network[i] | ^lan.Mask[i]
	}
	firstHost[3]++
	if ones, _ := lan.Mask.Size(); ones < 31 {
		if ip4.Equal(network) || ip4.Equal(broadcast) || ip4.Equal(firstHost) {
			return true
		}
	}
	if u, err := url.Parse(s.routerURL()); err == nil {
		if routerIP := net.ParseIP(u.Hostname()); routerIP != nil && routerIP.Equal(ip4) {
			return true
		}
	}
	return false
}

// routerURL returns MIKROTIK_URL with a scheme, the way the client reads it.
func (s *Server) routerURL() string {
	raw := strings.TrimSpace(s.cfg.MikroTikURL)
	if raw != "" && !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return raw
}

type assignReq struct {
	MAC      string `json:"mac"`
	Nickname string `json:"nickname"`
	ProxyID  string `json:"proxyId"`
}

func (s *Server) handleAssignDevice(w http.ResponseWriter, r *http.Request, ip string) {
	var req assignReq
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if req.ProxyID == "" {
		s.handleUnassignDevice(w, r, ip)
		return
	}

	tr := i18n.FromRequest(r)
	nickname, ok := cleanName(req.Nickname)
	if !ok {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.device.nickname_invalid", "max", maxNameRunes))
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	prev := s.state.GetDevice(ip)
	wasAssigned := prev != nil && prev.ProxyID != ""

	// The MAC drives the IPv6 block rules. Without one the device could keep
	// leaking over IPv6, so the assignment is refused instead of half-applied.
	rawMAC := req.MAC
	if rawMAC == "" && prev != nil {
		rawMAC = prev.MAC
	}
	if rawMAC == "" {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.device.mac_missing"))
		return
	}
	mac, ok := normalizeMAC(rawMAC)
	if !ok {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.device.mac_invalid"))
		return
	}

	if s.state.GetProxy(req.ProxyID) == nil {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.device.proxy_missing"))
		return
	}

	ctx, cancel := opContext(r, 20*time.Second)
	defer cancel()

	// The saved MAC differs when the device was re-registered with a new one.
	prevMAC := ""
	if prev != nil {
		prevMAC, _ = normalizeMAC(prev.MAC)
	}
	macChanged := prevMAC != "" && prevMAC != mac

	// undoRouter puts a device that was direct before this request back to
	// direct. A device that was already assigned keeps its router entries:
	// removing them would send its traffic out directly. Only the IPv6 rules
	// added for a new MAC are taken back, unless another device needs them.
	undoRouter := func() error {
		if !wasAssigned {
			return s.removeRouterAssignment(ip, mac)
		}
		if macChanged && !s.macUsedByOther(mac, ip) {
			rbCtx, rbCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer rbCancel()
			if err := s.mikrotik.RemoveIPv6BlockRules(rbCtx, mac); err != nil {
				return fmt.Errorf("remove IPv6 block rules of %s: %w", mac, err)
			}
		}
		return nil
	}

	// 1. Ensure static DHCP lease
	if err := s.mikrotik.EnsureStaticLease(ctx, ip, mac); err != nil {
		s.jsonStepError(w, stepLease, false, tr.T("api.assign.lease_failed", "err", err))
		return
	}

	// 2. Add to PROXY_DEVICES address-list
	if err := s.mikrotik.EnsureProxyAddressList(ctx, ip, mac); err != nil {
		s.jsonStepError(w, stepAddressList, false, tr.T("api.assign.address_list_failed", "err", err))
		return
	}

	// 3. Ensure IPv6 MAC block rules (fail-closed)
	if err := s.mikrotik.EnsureIPv6BlockRules(ctx, mac); err != nil {
		msg := tr.T("api.assign.ipv6_failed", "err", err)
		s.jsonStepError(w, stepIPv6, false, withRollbackNote(tr, msg, undoRouter()))
		return
	}

	// 4. Update persistent state
	if err := s.state.SetDeviceAssignment(ip, mac, nickname, req.ProxyID); err != nil {
		msg := tr.T("api.assign.state_failed", "err", err)
		rbErr := errors.Join(s.restoreAssignment(ip, prev), undoRouter())
		s.jsonStepError(w, stepState, false, withRollbackNote(tr, msg, rbErr))
		return
	}

	// 5. Regenerate & apply sing-box configuration
	if err := s.reloadSingbox(); err != nil {
		msg := tr.T("api.assign.singbox_failed", "err", err)
		rbErr := errors.Join(s.restoreAssignment(ip, prev), undoRouter())
		if rbErr == nil {
			// Bring sing-box back in line with the restored state.
			if reloadErr := s.reloadSingbox(); reloadErr != nil {
				rbErr = fmt.Errorf("reload previous sing-box config: %w", reloadErr)
			}
		}
		s.jsonStepError(w, stepSingbox, false, withRollbackNote(tr, msg, rbErr))
		return
	}

	// 6. The old MAC no longer belongs to this device: drop its IPv6 block
	// rules, unless another assigned device still uses that MAC.
	var cleanupMsg string
	if wasAssigned && macChanged && !s.macUsedByOther(prevMAC, ip) {
		if err := s.mikrotik.RemoveIPv6BlockRules(ctx, prevMAC); err != nil {
			cleanupMsg = tr.T("api.assign.old_mac_cleanup_failed", "mac", prevMAC, "err", err)
		}
	}

	// 7. Flush active connections so device traffic immediately routes through proxy
	if err := s.mikrotik.FlushDeviceConnections(ctx, ip, mac); err != nil {
		msg := tr.T("api.assign.flush_failed", "err", err)
		if cleanupMsg != "" {
			msg += " " + cleanupMsg
		}
		s.jsonStepError(w, stepFlush, true, msg)
		return
	}
	if cleanupMsg != "" {
		s.jsonStepError(w, stepIPv6, true, cleanupMsg)
		return
	}

	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

// macUsedByOther reports whether an assigned device other than ip has mac.
func (s *Server) macUsedByOther(mac, ip string) bool {
	for _, d := range s.state.GetAssignedDevices() {
		if d.IP == ip {
			continue
		}
		if other, ok := normalizeMAC(d.MAC); ok && other == mac {
			return true
		}
	}
	return false
}

func (s *Server) handleUnassignDevice(w http.ResponseWriter, r *http.Request, ip string) {
	tr := i18n.FromRequest(r)
	s.opMu.Lock()
	defer s.opMu.Unlock()

	dev := s.state.GetDevice(ip)
	mac := ""
	if dev != nil {
		mac = dev.MAC
	}

	ctx, cancel := opContext(r, 20*time.Second)
	defer cancel()

	// 1. Remove from PROXY_DEVICES. Nothing has changed yet if this fails.
	if err := s.mikrotik.RemoveProxyAddressList(ctx, ip); err != nil {
		s.jsonStepError(w, stepAddressList, false, tr.T("api.unassign.address_list_failed", "err", err))
		return
	}

	// 2. Remove IPv6 MAC block rules. On failure the device is put back so
	// the router and the saved assignment keep describing the same thing.
	if err := s.mikrotik.RemoveIPv6BlockRules(ctx, mac); err != nil {
		msg := tr.T("api.unassign.ipv6_failed", "err", err)
		var rbErr error
		if dev != nil && dev.ProxyID != "" {
			rbCtx, rbCancel := context.WithTimeout(context.Background(), 10*time.Second)
			rbErr = s.mikrotik.EnsureProxyAddressList(rbCtx, ip, mac)
			rbCancel()
		}
		s.jsonStepError(w, stepIPv6, false, withRollbackNote(tr, msg, rbErr))
		return
	}

	// 3. Remove assignment in state
	if err := s.state.RemoveDeviceAssignment(ip); err != nil {
		s.jsonStepError(w, stepState, true, tr.T("api.unassign.state_failed", "err", err))
		return
	}

	// 4. Reload sing-box
	if err := s.reloadSingbox(); err != nil {
		s.jsonStepError(w, stepSingbox, true, tr.T("api.unassign.singbox_failed", "err", err))
		return
	}

	// 5. Flush connections so device switches cleanly to direct
	if err := s.mikrotik.FlushDeviceConnections(ctx, ip, mac); err != nil {
		s.jsonStepError(w, stepFlush, true, tr.T("api.unassign.flush_failed", "err", err))
		return
	}

	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

// removeRouterAssignment deletes the router entries that route a device
// through the proxy. The address-list entry goes first: while it exists the
// IPv6 block must stay.
func (s *Server) removeRouterAssignment(ip, mac string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.mikrotik.RemoveProxyAddressList(ctx, ip); err != nil {
		return fmt.Errorf("remove from PROXY_DEVICES: %w", err)
	}
	if err := s.mikrotik.RemoveIPv6BlockRules(ctx, mac); err != nil {
		return fmt.Errorf("remove IPv6 block rules: %w", err)
	}
	return nil
}

// restoreAssignment puts the saved settings of a device back to prev,
// including its MAC and nickname. A device that had none is forgotten again.
func (s *Server) restoreAssignment(ip string, prev *state.DeviceConfig) error {
	if err := s.state.RestoreDevice(ip, prev); err != nil {
		return fmt.Errorf("restore saved assignment: %w", err)
	}
	return nil
}

// withRollbackNote appends to msg whether the undo after a failed step worked.
func withRollbackNote(tr *i18n.Translator, msg string, rbErr error) string {
	if rbErr == nil {
		return msg + " " + tr.T("api.rollback.ok")
	}
	return msg + " " + tr.T("api.rollback.failed", "err", rbErr)
}

// proxyView is a proxy as sent to the browser: credentials are never echoed
// back, only whether they are set.
type proxyView struct {
	*proxy.Proxy
	HasPassword bool `json:"hasPassword"`
	HasUUID     bool `json:"hasUuid"`
}

func newProxyView(p *proxy.Proxy) proxyView {
	cp := p.Clone()
	v := proxyView{Proxy: cp, HasPassword: cp.Password != "", HasUUID: cp.UUID != ""}
	cp.Password = ""
	cp.UUID = ""
	return v
}

// usesUserPassAuth reports protocols where the password is optional and only
// meaningful together with a username.
func usesUserPassAuth(protocol string) bool {
	switch protocol {
	case "socks5", "http", "https":
		return true
	}
	return false
}

// Proxies Handlers
func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	tr := i18n.FromRequest(r)
	switch r.Method {
	case http.MethodGet:
		proxies := s.state.GetProxies()
		views := make([]proxyView, 0, len(proxies))
		for _, p := range proxies {
			views = append(views, newProxyView(p))
		}
		s.json(w, http.StatusOK, views)

	case http.MethodPost:
		var p proxy.Proxy
		if !s.decodeJSON(w, r, &p) {
			return
		}

		// Identity and bookkeeping fields belong to the server.
		p.ID = proxy.GenerateID()
		p.CreatedAt = time.Time{}
		p.UpdatedAt = time.Time{}
		p.LastTest = nil

		name, ok := cleanName(p.Name)
		if !ok {
			s.jsonError(w, http.StatusBadRequest, tr.T("api.proxy.name_invalid", "max", maxNameRunes))
			return
		}
		p.Name = name
		if err := p.Validate(); err != nil {
			s.jsonError(w, http.StatusBadRequest, tr.T("api.proxy.invalid", "err", err))
			return
		}

		s.opMu.Lock()
		defer s.opMu.Unlock()

		// A new proxy has no device yet, so the sing-box configuration does
		// not change and there is nothing to reload.
		if err := s.state.SaveProxy(&p); err != nil {
			s.jsonStepError(w, stepState, false, tr.T("api.proxy.save_failed", "err", err))
			return
		}
		s.json(w, http.StatusCreated, newProxyView(&p))

	default:
		s.methodNotAllowed(w, r, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleProxiesImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r, http.MethodPost)
		return
	}
	tr := i18n.FromRequest(r)

	var req struct {
		Text         string `json:"text"`
		DefaultProto string `json:"defaultProto"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}

	proxies, errs := proxy.ParseURIs(req.Text, req.DefaultProto)
	if len(proxies) == 0 && len(errs) > 0 {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.import.failed", "err", errs[0]))
		return
	}

	errStrings := make([]string, 0, len(errs))
	for _, e := range errs {
		errStrings = append(errStrings, e.Error())
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	// Imported proxies are unassigned, so sing-box needs no reload.
	imported := 0
	for _, p := range proxies {
		p.ID = proxy.GenerateID()
		p.LastTest = nil
		p.Name = scrubName(p.Name)
		if err := p.Validate(); err != nil {
			errStrings = append(errStrings, fmt.Sprintf("%s:%d: %v", p.Host, p.Port, err))
			continue
		}
		if err := s.state.SaveProxy(p); err != nil {
			errStrings = append(errStrings, tr.T("api.import.save_failed", "name", p.Name, "err", err))
			continue
		}
		imported++
	}

	if imported == 0 && len(proxies) > 0 {
		s.jsonStepError(w, stepState, false, tr.T("api.import.none", "errors", strings.Join(errStrings, "; ")))
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"imported": imported,
		"errors":   errStrings,
	})
}

func (s *Server) handleProxyByID(w http.ResponseWriter, r *http.Request) {
	tr := i18n.FromRequest(r)
	path := strings.TrimPrefix(r.URL.Path, "/api/proxies/")
	parts := strings.Split(path, "/")
	id := parts[0]

	switch {
	case len(parts) == 1:
		// Handled below.
	case len(parts) == 2 && parts[1] == "test":
		if r.Method != http.MethodPost {
			s.methodNotAllowed(w, r, http.MethodPost)
			return
		}
		s.handleProxyTest(w, r, id)
		return
	default:
		s.jsonError(w, http.StatusNotFound, tr.T("api.not_found"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		p := s.state.GetProxy(id)
		if p == nil {
			s.jsonError(w, http.StatusNotFound, tr.T("api.proxy.not_found"))
			return
		}
		s.json(w, http.StatusOK, newProxyView(p))

	case http.MethodPut:
		s.handleProxyUpdate(w, r, id)

	case http.MethodDelete:
		s.handleProxyDelete(w, r, id)

	default:
		s.methodNotAllowed(w, r, http.MethodGet, http.MethodPut, http.MethodDelete)
	}
}

func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request, id string) {
	tr := i18n.FromRequest(r)
	p := s.state.GetProxy(id)
	if p == nil {
		s.jsonError(w, http.StatusNotFound, tr.T("api.proxy.not_found"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	testOpts := proxy.TestOptions{
		SingboxPath: s.cfg.SingboxPath,
		VethIF:      s.cfg.VethIF,
		ContainerGW: s.cfg.ContainerGW,
	}
	res, err := proxy.TestProxyWithOptions(ctx, p, testOpts)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, tr.T("api.proxy.test_failed", "err", err))
		return
	}

	// Only the result is stored. Saving the whole proxy here would recreate
	// one that was deleted, or undo an edit made, while the test was running.
	if err := s.state.SetProxyTestResult(id, res); err != nil {
		if errors.Is(err, state.ErrProxyNotFound) {
			s.jsonError(w, http.StatusNotFound, tr.T("api.proxy.deleted_during_test"))
			return
		}
		s.jsonStepError(w, stepState, false, tr.T("api.proxy.test_save_failed", "err", err))
		return
	}
	s.json(w, http.StatusOK, res)
}

func (s *Server) handleProxyUpdate(w http.ResponseWriter, r *http.Request, id string) {
	tr := i18n.FromRequest(r)
	var updated proxy.Proxy
	if !s.decodeJSON(w, r, &updated) {
		return
	}

	name, ok := cleanName(updated.Name)
	if !ok {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.proxy.name_invalid", "max", maxNameRunes))
		return
	}
	updated.Name = name

	s.opMu.Lock()
	defer s.opMu.Unlock()

	existing := s.state.GetProxy(id)
	if existing == nil {
		s.jsonError(w, http.StatusNotFound, tr.T("api.proxy.not_found"))
		return
	}

	updated.ID = id
	updated.CreatedAt = existing.CreatedAt
	updated.LastTest = nil

	// The API never returns credentials, so an empty credential in an update
	// means "unchanged" as long as the protocol stays the same. For
	// username/password protocols an empty username means no authentication.
	protocol := strings.ToLower(strings.TrimSpace(updated.Protocol))
	if protocol == existing.Protocol {
		if updated.UUID == "" {
			updated.UUID = existing.UUID
		}
		if updated.Password == "" && !(usesUserPassAuth(protocol) && updated.Username == "") {
			updated.Password = existing.Password
		}
	}

	if err := updated.Validate(); err != nil {
		s.jsonError(w, http.StatusBadRequest, tr.T("api.proxy.invalid", "err", err))
		return
	}

	// A test result describes one endpoint; it stays only if that is unchanged.
	if updated.Protocol == existing.Protocol && updated.Host == existing.Host && updated.Port == existing.Port {
		updated.LastTest = existing.LastTest
	}

	if err := s.state.SaveProxy(&updated); err != nil {
		rbErr := s.state.SaveProxy(existing)
		s.jsonStepError(w, stepState, false, withRollbackNote(tr, tr.T("api.proxy.update_save_failed", "err", err), rbErr))
		return
	}

	// sing-box only carries proxies that have devices, so only those need a reload.
	if len(s.state.DevicesUsingProxy(id)) > 0 {
		if err := s.reloadSingbox(); err != nil {
			msg := tr.T("api.proxy.update_singbox_failed", "err", err)
			rbErr := s.state.SaveProxy(existing)
			if rbErr == nil {
				if reloadErr := s.reloadSingbox(); reloadErr != nil {
					rbErr = fmt.Errorf("reload previous sing-box config: %w", reloadErr)
				}
			}
			s.jsonStepError(w, stepSingbox, false, withRollbackNote(tr, msg, rbErr))
			return
		}
	}

	s.json(w, http.StatusOK, newProxyView(&updated))
}

func (s *Server) handleProxyDelete(w http.ResponseWriter, r *http.Request, id string) {
	tr := i18n.FromRequest(r)
	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.state.GetProxy(id) == nil {
		s.jsonError(w, http.StatusNotFound, tr.T("api.proxy.not_found"))
		return
	}

	// An assigned proxy is never deleted: its devices would stay in
	// PROXY_DEVICES with no outbound, cut off with no hint why. A proxy
	// without devices is not part of the sing-box config, so no reload.
	err := s.state.DeleteProxy(id)
	if errors.Is(err, state.ErrProxyInUse) {
		users := s.state.DevicesUsingProxy(id)
		labels := make([]string, 0, len(users))
		for _, d := range users {
			if d.Nickname != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", d.Nickname, d.IP))
			} else {
				labels = append(labels, d.IP)
			}
		}
		s.json(w, http.StatusConflict, map[string]interface{}{
			"error":   tr.T("api.proxy.in_use", "count", len(users), "devices", strings.Join(labels, ", ")),
			"devices": users,
		})
		return
	}
	if err != nil {
		s.jsonStepError(w, stepState, false, tr.T("api.proxy.delete_failed", "err", err))
		return
	}

	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

// System Handlers
func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, r, http.MethodGet)
		return
	}
	tr := i18n.FromRequest(r)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	supStatus := s.supervisor.GetStatus()
	leakGuard, err := s.mikrotik.GetLeakGuardStatus(ctx, s.state, mikrotik.EngineStatus{
		SingboxRunning: supStatus.Running,
		ForwardGuard:   s.cfg.ForwardGuardStatus,
	}, tr)
	if err == nil && leakGuard == nil {
		err = errors.New("no leak guard result")
	}
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, tr.T("api.system.status_failed", "err", err))
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"singbox":   supStatus,
		"leakGuard": leakGuard,
	})
}

func (s *Server) handleSystemReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r, http.MethodPost)
		return
	}
	tr := i18n.FromRequest(r)

	s.opMu.Lock()
	defer s.opMu.Unlock()

	ctx, cancel := opContext(r, 30*time.Second)
	defer cancel()

	// Both halves always run: a router error must not keep sing-box on a
	// stale configuration, and the other way round.
	routerErr := s.mikrotik.Reconcile(ctx, s.state)
	singboxErr := s.reloadSingbox()

	switch {
	case routerErr != nil && singboxErr != nil:
		s.jsonStepError(w, stepRouter, false, tr.T("api.system.reconcile_both_failed", "router", routerErr, "singbox", singboxErr))
	case routerErr != nil:
		s.jsonStepError(w, stepRouter, false, tr.T("api.system.reconcile_router_failed", "err", routerErr))
	case singboxErr != nil:
		s.jsonStepError(w, stepSingbox, false, tr.T("api.system.reconcile_singbox_failed", "err", singboxErr))
	default:
		s.json(w, http.StatusOK, map[string]bool{"success": true})
	}
}

func (s *Server) handleSystemFlushAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, r, http.MethodPost)
		return
	}

	// Hold the write lock so the flush cannot run in the middle of an
	// assignment and miss, or race with, the device being changed.
	s.opMu.Lock()
	defer s.opMu.Unlock()

	assigned := s.state.GetAssignedDevices()
	var ips []string
	for _, d := range assigned {
		ips = append(ips, d.IP)
	}

	ctx, cancel := opContext(r, 15*time.Second)
	defer cancel()

	if err := s.mikrotik.FlushAllProxyConnections(ctx, ips); err != nil {
		s.jsonStepError(w, stepFlush, false, i18n.FromRequest(r).T("api.system.flush_all_failed", "err", err))
		return
	}
	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, r, http.MethodGet)
		return
	}
	logs := s.supervisor.GetLogs()
	s.json(w, http.StatusOK, logs)
}

func (s *Server) reloadSingbox() error {
	cfgBytes, err := singbox.GenerateConfig(s.cfg, s.state)
	if err != nil {
		return err
	}
	return s.applyConfig(cfgBytes)
}
