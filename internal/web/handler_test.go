package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/auth"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/config"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/mikrotik"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/singbox"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/state"
)

func setupTestServer(t *testing.T) (*Server, *httptest.Server, *http.Cookie) {
	tempDir, err := os.MkdirTemp("", "web_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	pass := "AdminPass123!"
	passHash, _ := auth.HashPassword(pass)

	cfg := &config.Config{
		DataDir:               tempDir,
		LanCIDR:               "10.88.88.0/24",
		ContainerGW:           "10.10.10.1",
		SingboxPath:           "sing-box",
		DashboardPasswordHash: passHash,
	}

	authMgr, err := auth.NewAuthManager(tempDir, passHash)
	if err != nil {
		t.Fatalf("failed to create AuthManager: %v", err)
	}

	st, err := state.Load(tempDir)
	if err != nil {
		t.Fatalf("failed to create State: %v", err)
	}

	sup := singbox.NewSupervisor("sing-box", tempDir)
	t.Cleanup(func() { sup.Stop() })

	// Mock RouterOS backend
	routerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/ip/dhcp-server/lease":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"address": "10.88.88.50", "mac-address": "00:11:22:33:44:50", "status": "bound", "dynamic": "true", ".id": "*1"},
			})
		case "/rest/ip/arp":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"address": "10.88.88.50", "mac-address": "00:11:22:33:44:50", "complete": "true"},
			})
		case "/rest/ip/firewall/address-list":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		case "/rest/ipv6/firewall/filter":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		case "/rest/ip/firewall/connection":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		case "/rest/routing/table":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"name": "via-proxy"}})
		case "/rest/ip/firewall/filter":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"comment": "proxy-dash-killswitch", "packets": "10", "bytes": "500"}})
		case "/rest/ip/firewall/nat":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"action": "dst-nat", "dst-port": "53"}})
		case "/rest/routing/rule":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"table": "via-proxy"}})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(func() { routerMock.Close() })

	mkClient, _ := mikrotik.NewClient(routerMock.URL, "admin", "pass", true)

	srv := NewServer(cfg, authMgr, st, sup, mkClient, nil)

	// Obtain session cookie
	cookie, err := authMgr.Login(pass, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to generate cookie: %v", err)
	}

	return srv, routerMock, cookie
}

func TestWebAPIAuthAndProtected(t *testing.T) {
	srv, _, cookie := setupTestServer(t)

	// 1. Unauthenticated request to /api/devices should fail with 401
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got: %d", w.Code)
	}

	// 2. Authenticated request with session cookie should return 200
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	reqAuth.AddCookie(cookie)
	wAuth := httptest.NewRecorder()
	srv.ServeHTTP(wAuth, reqAuth)
	if wAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", wAuth.Code)
	}
}

func TestWebAPIProxiesAndImport(t *testing.T) {
	srv, _, cookie := setupTestServer(t)

	// 1. Create proxy
	p := proxy.Proxy{
		Name:     "Test SOCKS5",
		Protocol: proxy.ProtoSocks5,
		Host:     "1.2.3.4",
		Port:     1080,
	}
	body, _ := json.Marshal(p)
	req := httptest.NewRequest(http.MethodPost, "/api/proxies", bytes.NewReader(body))
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got: %d (%s)", w.Code, w.Body.String())
	}

	var created proxy.Proxy
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatalf("expected proxy ID to be generated")
	}

	// 2. Batch import
	importData := map[string]string{
		"text":         "http://u:p@5.6.7.8:8080#BatchHTTP\nsocks5://9.9.9.9:1080#BatchSocks",
		"defaultProto": "http",
	}
	importBytes, _ := json.Marshal(importData)
	reqImport := httptest.NewRequest(http.MethodPost, "/api/proxies/import", bytes.NewReader(importBytes))
	reqImport.AddCookie(cookie)
	wImport := httptest.NewRecorder()
	srv.ServeHTTP(wImport, reqImport)
	if wImport.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for import, got: %d", wImport.Code)
	}

	// 3. List proxies
	reqList := httptest.NewRequest(http.MethodGet, "/api/proxies", nil)
	reqList.AddCookie(cookie)
	wList := httptest.NewRecorder()
	srv.ServeHTTP(wList, reqList)
	var list []*proxy.Proxy
	_ = json.Unmarshal(wList.Body.Bytes(), &list)
	if len(list) != 3 {
		t.Fatalf("expected 3 proxies, got: %d", len(list))
	}
}

func TestWebAPIDeviceAssignment(t *testing.T) {
	srv, _, cookie := setupTestServer(t)

	// Add proxy first
	p := &proxy.Proxy{
		ID:       "p-test",
		Name:     "HTTP Proxy",
		Protocol: proxy.ProtoHTTP,
		Host:     "1.1.1.1",
		Port:     8080,
	}
	_ = srv.state.SaveProxy(p)

	// Assign device 10.88.88.50 to p-test
	assignPayload := map[string]string{
		"mac":      "00:11:22:33:44:50",
		"nickname": "Test PC",
		"proxyId":  "p-test",
	}
	assignBytes, _ := json.Marshal(assignPayload)
	req := httptest.NewRequest(http.MethodPut, "/api/devices/10.88.88.50/assignment", bytes.NewReader(assignBytes))
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on assign, got: %d (%s)", w.Code, w.Body.String())
	}

	dev := srv.state.GetDevice("10.88.88.50")
	if dev == nil || dev.ProxyID != "p-test" {
		t.Fatalf("device assignment state not updated: %+v", dev)
	}

	// Unassign device
	reqUnassign := httptest.NewRequest(http.MethodDelete, "/api/devices/10.88.88.50/assignment", nil)
	reqUnassign.AddCookie(cookie)
	wUnassign := httptest.NewRecorder()
	srv.ServeHTTP(wUnassign, reqUnassign)
	if wUnassign.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on unassign, got: %d", wUnassign.Code)
	}

	devAfter := srv.state.GetDevice("10.88.88.50")
	if devAfter.ProxyID != "" {
		t.Fatalf("expected proxyId to be empty after unassign")
	}
}

func TestWebAPIAssignFailClosedRollback(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "web_failclosed_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	pass := "AdminPass123!"
	passHash, _ := auth.HashPassword(pass)

	cfg := &config.Config{
		DataDir:               tempDir,
		LanCIDR:               "10.88.88.0/24",
		ContainerGW:           "10.10.10.1",
		SingboxPath:           "sing-box",
		DashboardPasswordHash: passHash,
	}

	authMgr, err := auth.NewAuthManager(tempDir, passHash)
	if err != nil {
		t.Fatalf("failed to create AuthManager: %v", err)
	}

	st, err := state.Load(tempDir)
	if err != nil {
		t.Fatalf("failed to create State: %v", err)
	}

	sup := singbox.NewSupervisor("sing-box", tempDir)
	t.Cleanup(func() { sup.Stop() })

	removedAddressList := false
	routerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/rest/ip/dhcp-server/lease":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"address": "10.88.88.50", "mac-address": "00:11:22:33:44:50", "status": "bound", "dynamic": "true", ".id": "*1"},
			})
		case r.URL.Path == "/rest/ip/firewall/address-list" && r.Method == "PUT":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/rest/ip/firewall/address-list" && r.Method == "GET":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"list": "PROXY_DEVICES", "address": "10.88.88.50", ".id": "*AL1"},
			})
		case strings.HasPrefix(r.URL.Path, "/rest/ip/firewall/address-list/*AL1") && r.Method == "DELETE":
			removedAddressList = true
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/rest/ipv6/firewall/filter" && r.Method == "GET":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{".id": "*R1", "chain": "forward", "action": "accept", "dynamic": "false"},
			})
		case r.URL.Path == "/rest/ipv6/firewall/filter/add" && r.Method == "POST":
			// Simulate IPv6 error failure
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": 500, "message": "IPv6 firewall failure"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(func() { routerMock.Close() })

	mkClient, _ := mikrotik.NewClient(routerMock.URL, "admin", "pass", true)
	srv := NewServer(cfg, authMgr, st, sup, mkClient, nil)

	cookie, err := authMgr.Login(pass, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to generate cookie: %v", err)
	}

	p := &proxy.Proxy{
		ID:       "p-test",
		Name:     "HTTP Proxy",
		Protocol: proxy.ProtoHTTP,
		Host:     "1.1.1.1",
		Port:     8080,
	}
	_ = srv.state.SaveProxy(p)

	assignPayload := map[string]string{
		"mac":      "00:11:22:33:44:50",
		"nickname": "Test PC",
		"proxyId":  "p-test",
	}
	assignBytes, _ := json.Marshal(assignPayload)
	req := httptest.NewRequest(http.MethodPut, "/api/devices/10.88.88.50/assignment", bytes.NewReader(assignBytes))
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError on IPv6 failure, got: %d", w.Code)
	}
	if !removedAddressList {
		t.Fatalf("expected address list to be rolled back on IPv6 failure (Fail-Closed)")
	}
	// State should NOT have been updated with this assignment
	dev := srv.state.GetDevice("10.88.88.50")
	if dev != nil && dev.ProxyID != "" {
		t.Fatalf("expected state not to save assignment on failure")
	}
}
