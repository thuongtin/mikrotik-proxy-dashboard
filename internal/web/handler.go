package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/auth"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/config"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/mikrotik"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/singbox"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/state"
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
		cfg:        cfg,
		authMgr:    authMgr,
		state:      st,
		supervisor: sup,
		mikrotik:   mk,
		staticFS:   staticFS,
		mux:        http.NewServeMux(),
	}

	s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// Public auth endpoints
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/auth/me", s.handleAuthMe)

	// Protected API endpoints
	s.mux.HandleFunc("/api/devices", s.requireAuth(s.handleDevices))
	s.mux.HandleFunc("/api/devices/", s.requireAuth(s.handleDeviceByIP))

	s.mux.HandleFunc("/api/proxies", s.requireAuth(s.handleProxies))
	s.mux.HandleFunc("/api/proxies/import", s.requireAuth(s.handleProxiesImport))
	s.mux.HandleFunc("/api/proxies/", s.requireAuth(s.handleProxyByID))

	s.mux.HandleFunc("/api/system/status", s.requireAuth(s.handleSystemStatus))
	s.mux.HandleFunc("/api/system/reconcile", s.requireAuth(s.handleSystemReconcile))
	s.mux.HandleFunc("/api/system/flush-all", s.requireAuth(s.handleSystemFlushAll))
	s.mux.HandleFunc("/api/system/logs", s.requireAuth(s.handleSystemLogs))

	// Embedded Static Frontend
	if s.staticFS != nil {
		fileServer := http.FileServer(http.FS(s.staticFS))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
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
			s.jsonError(w, http.StatusUnauthorized, "Phiên đăng nhập hết hạn hoặc không hợp lệ")
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

// Auth Handlers
type loginReq struct {
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	clientIP := auth.GetClientIP(r)
	cookie, err := s.authMgr.Login(req.Password, clientIP)
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, err.Error())
		return
	}

	http.SetCookie(w, cookie)
	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.authMgr.ClearSessionCookie())
	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	authenticated := s.authMgr.VerifyRequest(r)
	s.json(w, http.StatusOK, map[string]bool{"authenticated": authenticated})
}

// Device Handlers
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	devices, err := s.mikrotik.GetDevices(ctx, s.cfg.LanCIDR, s.state)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.json(w, http.StatusOK, devices)
}

func (s *Server) handleDeviceByIP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/devices/")
	parts := strings.Split(path, "/")
	ip := parts[0]

	// Validate target IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		s.jsonError(w, http.StatusBadRequest, "Địa chỉ IP không hợp lệ")
		return
	}

	_, lanNet, err := net.ParseCIDR(s.cfg.LanCIDR)
	if err == nil && (!lanNet.Contains(parsedIP) || strings.HasSuffix(ip, ".1")) {
		s.jsonError(w, http.StatusBadRequest, "IP không nằm trong mạng LAN hoặc là IP Gateway")
		return
	}

	if len(parts) == 2 && parts[1] == "assignment" {
		switch r.Method {
		case http.MethodPut:
			s.handleAssignDevice(w, r, ip)
		case http.MethodDelete:
			s.handleUnassignDevice(w, r, ip)
		default:
			s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}

	if len(parts) == 2 && parts[1] == "nickname" && r.Method == http.MethodPut {
		var req struct {
			Nickname string `json:"nickname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, http.StatusBadRequest, "Dữ liệu không hợp lệ")
			return
		}
		if err := s.state.SetDeviceNickname(ip, req.Nickname); err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.json(w, http.StatusOK, map[string]bool{"success": true})
		return
	}

	if len(parts) == 2 && parts[1] == "flush" && r.Method == http.MethodPost {
		dev := s.state.GetDevice(ip)
		mac := ""
		if dev != nil {
			mac = dev.MAC
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		_ = s.mikrotik.FlushDeviceConnections(ctx, ip, mac)
		s.json(w, http.StatusOK, map[string]bool{"success": true})
		return
	}

	s.jsonError(w, http.StatusNotFound, "Endpoint không tồn tại")
}

type assignReq struct {
	MAC      string `json:"mac"`
	Nickname string `json:"nickname"`
	ProxyID  string `json:"proxyId"`
}

func (s *Server) handleAssignDevice(w http.ResponseWriter, r *http.Request, ip string) {
	var req assignReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Dữ liệu không hợp lệ")
		return
	}

	if req.ProxyID == "" {
		s.handleUnassignDevice(w, r, ip)
		return
	}

	p := s.state.GetProxy(req.ProxyID)
	if p == nil {
		s.jsonError(w, http.StatusBadRequest, "Proxy được chọn không tồn tại")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// If MAC is not in request, try to lookup from state
	if req.MAC == "" {
		if dev := s.state.GetDevice(ip); dev != nil && dev.MAC != "" {
			req.MAC = dev.MAC
		}
	}

	// 1. Ensure static DHCP lease
	if err := s.mikrotik.EnsureStaticLease(ctx, ip, req.MAC); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Không thể cố định DHCP lease: %v", err))
		return
	}

	// 2. Add to PROXY_DEVICES address-list
	if err := s.mikrotik.EnsureProxyAddressList(ctx, ip, req.MAC); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Không thể thêm vào PROXY_DEVICES: %v", err))
		return
	}

	// 3. Ensure IPv6 MAC block rules (fail-closed: rollback PROXY_DEVICES if IPv6 block fails)
	if req.MAC != "" {
		if err := s.mikrotik.EnsureIPv6BlockRules(ctx, req.MAC); err != nil {
			_ = s.mikrotik.RemoveProxyAddressList(ctx, ip)
			s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Không thể thiết lập quy tắc chặn IPv6 (Fail-Closed): %v", err))
			return
		}
	}

	// 4. Update persistent state
	if err := s.state.SetDeviceAssignment(ip, req.MAC, req.Nickname, req.ProxyID); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Không thể lưu trạng thái: %v", err))
		return
	}

	// 5. Regenerate & apply sing-box configuration
	if err := s.reloadSingbox(); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Cấu hình sing-box thất bại: %v", err))
		return
	}

	// 6. Flush active connections so device traffic immediately routes through proxy
	_ = s.mikrotik.FlushDeviceConnections(ctx, ip, req.MAC)

	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleUnassignDevice(w http.ResponseWriter, r *http.Request, ip string) {
	dev := s.state.GetDevice(ip)
	mac := ""
	if dev != nil {
		mac = dev.MAC
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 1. Remove from PROXY_DEVICES
	_ = s.mikrotik.RemoveProxyAddressList(ctx, ip)

	// 2. Remove IPv6 MAC block rules
	if mac != "" {
		_ = s.mikrotik.RemoveIPv6BlockRules(ctx, mac)
	}

	// 3. Remove assignment in state
	_ = s.state.RemoveDeviceAssignment(ip)

	// 4. Reload sing-box
	_ = s.reloadSingbox()

	// 5. Flush connections so device switches cleanly to direct
	_ = s.mikrotik.FlushDeviceConnections(ctx, ip, mac)

	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

// Proxies Handlers
func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		proxies := s.state.GetProxies()
		s.json(w, http.StatusOK, proxies)

	case http.MethodPost:
		var p proxy.Proxy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			s.jsonError(w, http.StatusBadRequest, "Dữ liệu không hợp lệ")
			return
		}
		if err := p.Validate(); err != nil {
			s.jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if p.ID == "" {
			p.ID = proxy.GenerateID()
		}
		if err := s.state.SaveProxy(&p); err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.reloadSingbox()
		s.json(w, http.StatusCreated, p)

	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleProxiesImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Text         string `json:"text"`
		DefaultProto string `json:"defaultProto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Dữ liệu không hợp lệ")
		return
	}

	proxies, errs := proxy.ParseURIs(req.Text, req.DefaultProto)
	if len(proxies) == 0 && len(errs) > 0 {
		s.jsonError(w, http.StatusBadRequest, fmt.Sprintf("Không thể nhập URI: %v", errs[0]))
		return
	}

	var saved []*proxy.Proxy
	for _, p := range proxies {
		if err := s.state.SaveProxy(p); err == nil {
			saved = append(saved, p)
		}
	}

	_ = s.reloadSingbox()

	var errStrings []string
	for _, e := range errs {
		errStrings = append(errStrings, e.Error())
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"imported": len(saved),
		"errors":   errStrings,
	})
}

func (s *Server) handleProxyByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/proxies/")
	parts := strings.Split(path, "/")
	id := parts[0]

	p := s.state.GetProxy(id)
	if p == nil {
		s.jsonError(w, http.StatusNotFound, "Proxy không tồn tại")
		return
	}

	if len(parts) == 2 && parts[1] == "test" && r.Method == http.MethodPost {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()

		testOpts := proxy.TestOptions{
			SingboxPath: s.cfg.SingboxPath,
			VethIF:      s.cfg.VethIF,
			ContainerGW: s.cfg.ContainerGW,
		}
		res, err := proxy.TestProxyWithOptions(ctx, p, testOpts)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.state.SaveProxy(p)
		s.json(w, http.StatusOK, res)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.json(w, http.StatusOK, p)

	case http.MethodPut:
		var updated proxy.Proxy
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			s.jsonError(w, http.StatusBadRequest, "Dữ liệu không hợp lệ")
			return
		}
		updated.ID = id
		if err := updated.Validate(); err != nil {
			s.jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.state.SaveProxy(&updated); err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.reloadSingbox()
		s.json(w, http.StatusOK, updated)

	case http.MethodDelete:
		if err := s.state.DeleteProxy(id); err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.reloadSingbox()
		s.json(w, http.StatusOK, map[string]bool{"success": true})

	default:
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// System Handlers
func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	supStatus := s.supervisor.GetStatus()
	leakGuard, _ := s.mikrotik.GetLeakGuardStatus(ctx, s.state, supStatus.Running)

	s.json(w, http.StatusOK, map[string]interface{}{
		"singbox":   supStatus,
		"leakGuard": leakGuard,
	})
}

func (s *Server) handleSystemReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if err := s.mikrotik.Reconcile(ctx, s.state); err != nil {
		s.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("Đồng bộ thất bại: %v", err))
		return
	}

	_ = s.reloadSingbox()
	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleSystemFlushAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	assigned := s.state.GetAssignedDevices()
	var ips []string
	for _, d := range assigned {
		ips = append(ips, d.IP)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	_ = s.mikrotik.FlushAllProxyConnections(ctx, ips)
	s.json(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
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
	return s.supervisor.ApplyConfig(cfgBytes)
}
