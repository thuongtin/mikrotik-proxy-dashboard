package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/auth"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/config"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/mikrotik"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/singbox"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
)

const (
	testDeviceIP  = "10.88.88.50"
	testDeviceMAC = "00:11:22:33:44:50"
)

// fakeRouter is a stateful RouterOS REST stand-in: what the dashboard writes
// can be read back, so tests can check what is left on the router.
type fakeRouter struct {
	mu          sync.Mutex
	nextID      int
	addressList map[string]string                 // id -> address
	ipv6Rules   map[string]map[string]interface{} // id -> rule fields

	failAddressListDelete bool
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{addressList: map[string]string{}, ipv6Rules: map[string]map[string]interface{}{}}
}

func (f *fakeRouter) hasAddress(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, addr := range f.addressList {
		if addr == ip {
			return true
		}
	}
	return false
}

func (f *fakeRouter) ipv6RuleCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ipv6Rules)
}

func (f *fakeRouter) seedAssignment(ip, mac string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addressList["*seed-al"] = ip
	f.ipv6Rules["*seed-fwd"] = map[string]interface{}{"chain": "forward", "action": "reject", "src-mac-address": mac, "comment": "proxy-dash-ipv6-fwd:" + mac}
	f.ipv6Rules["*seed-in"] = map[string]interface{}{"chain": "input", "action": "reject", "src-mac-address": mac, "comment": "proxy-dash-ipv6-in:" + mac}
}

// ipv6RulesFor counts the IPv6 block rules left for mac.
func (f *fakeRouter) ipv6RulesFor(mac string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.ipv6Rules {
		if strings.EqualFold(fmt.Sprint(r["src-mac-address"]), mac) {
			n++
		}
	}
	return n
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/rest")

	switch {
	case path == "/ip/dhcp-server/lease":
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{"address": testDeviceIP, "mac-address": testDeviceMAC, "status": "bound", "dynamic": "true", ".id": "*1"},
		})

	case path == "/ip/firewall/address-list" && r.Method == http.MethodGet:
		entries := []map[string]interface{}{}
		for id, addr := range f.addressList {
			entries = append(entries, map[string]interface{}{".id": id, "list": "PROXY_DEVICES", "address": addr})
		}
		_ = json.NewEncoder(w).Encode(entries)

	case path == "/ip/firewall/address-list" && r.Method == http.MethodPut:
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.nextID++
		f.addressList[fmt.Sprintf("*al%d", f.nextID)], _ = body["address"].(string)
		_, _ = w.Write([]byte(`{}`))

	case strings.HasPrefix(path, "/ip/firewall/address-list/") && r.Method == http.MethodDelete:
		if f.failAddressListDelete {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": 500, "message": "router busy"}`))
			return
		}
		delete(f.addressList, strings.TrimPrefix(path, "/ip/firewall/address-list/"))

	case path == "/ipv6/firewall/filter" && r.Method == http.MethodGet:
		rules := []map[string]interface{}{}
		for id, rule := range f.ipv6Rules {
			out := map[string]interface{}{".id": id}
			for k, v := range rule {
				out[k] = v
			}
			rules = append(rules, out)
		}
		_ = json.NewEncoder(w).Encode(rules)

	case path == "/ipv6/firewall/filter/add" && r.Method == http.MethodPost:
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.nextID++
		delete(body, "place-before")
		f.ipv6Rules[fmt.Sprintf("*v6%d", f.nextID)] = body
		_, _ = w.Write([]byte(`{}`))

	case strings.HasPrefix(path, "/ipv6/firewall/filter/") && r.Method == http.MethodDelete:
		delete(f.ipv6Rules, strings.TrimPrefix(path, "/ipv6/firewall/filter/"))

	case path == "/ip/firewall/connection", path == "/ipv6/neighbor", path == "/ipv6/firewall/connection":
		_, _ = w.Write([]byte(`[]`))

	default:
		w.WriteHeader(http.StatusOK)
	}
}

// newHardeningServer builds a server on a fake router. sing-box is replaced by
// a stub so these tests do not depend on the binary.
func newHardeningServer(t *testing.T) (*Server, *fakeRouter, *http.Cookie) {
	t.Helper()
	dir := t.TempDir()

	pass := "AdminPass123!"
	passHash, err := auth.HashPassword(pass)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	cfg := &config.Config{
		DataDir:               dir,
		LanCIDR:               "10.88.88.0/24",
		ContainerGW:           "10.10.10.1",
		SingboxPath:           "sing-box",
		DashboardPasswordHash: passHash,
	}
	authMgr, err := auth.NewAuthManager(dir, passHash)
	if err != nil {
		t.Fatalf("auth manager: %v", err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	router := newFakeRouter()
	routerSrv := httptest.NewServer(router)
	t.Cleanup(routerSrv.Close)

	mk, err := mikrotik.NewClient(routerSrv.URL, "admin", "pass", mikrotik.Options{})
	if err != nil {
		t.Fatalf("mikrotik client: %v", err)
	}

	srv := NewServer(cfg, authMgr, st, singbox.NewSupervisor("sing-box", dir), mk, nil)
	srv.applyConfig = func([]byte) error { return nil }

	cookie, err := authMgr.Login(pass, "127.0.0.1")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return srv, router, cookie
}

func call(t *testing.T, srv *Server, cookie *http.Cookie, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case []byte:
		reader = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func decodeStepError(t *testing.T, w *httptest.ResponseRecorder) stepError {
	t.Helper()
	var se stepError
	if err := json.Unmarshal(w.Body.Bytes(), &se); err != nil {
		t.Fatalf("decode error body %q: %v", w.Body.String(), err)
	}
	return se
}

func saveProxy(t *testing.T, srv *Server, p *proxy.Proxy) {
	t.Helper()
	if err := srv.state.SaveProxy(p); err != nil {
		t.Fatalf("save proxy: %v", err)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv, _, _ := newHardeningServer(t)

	w := call(t, srv, nil, http.MethodGet, "/api/auth/me", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	}
	for name, value := range want {
		if got := w.Header().Get(name); got != value {
			t.Errorf("header %s = %q, want %q", name, got, value)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP %q is missing %q", csp, directive)
		}
	}
	// Inline scripts must stay blocked: that is what contains an XSS slip.
	if strings.Contains(strings.SplitN(csp, "style-src", 2)[0], "unsafe-inline") {
		t.Errorf("CSP allows inline scripts: %q", csp)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	srv, _, _ := newHardeningServer(t)

	body := []byte(`{"password":"` + strings.Repeat("a", maxBodyBytes+1024) + `"}`)
	w := call(t, srv, nil, http.MethodPost, "/api/auth/login", body)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestMethodChecks(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)

	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/auth/logout"},
		{http.MethodPost, "/api/auth/me"},
		{http.MethodGet, "/api/devices/" + testDeviceIP + "/nickname"},
		{http.MethodGet, "/api/devices/" + testDeviceIP + "/flush"},
		{http.MethodGet, "/api/proxies/some-id/test"},
		{http.MethodGet, "/api/system/reconcile"},
		{http.MethodPost, "/api/system/status"},
	}
	for _, tc := range cases {
		w := call(t, srv, cookie, tc.method, tc.path, nil)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: expected 405, got %d", tc.method, tc.path, w.Code)
		}
		if w.Header().Get("Allow") == "" {
			t.Errorf("%s %s: missing Allow header", tc.method, tc.path)
		}
	}

	// A GET must not end the session.
	if w := call(t, srv, cookie, http.MethodGet, "/api/devices", nil); w.Code != http.StatusOK {
		t.Fatalf("session should survive a GET to logout, got %d", w.Code)
	}
}

func TestAssignmentInputValidation(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})

	path := "/api/devices/" + testDeviceIP + "/assignment"
	cases := []struct {
		name string
		body map[string]string
	}{
		{"malformed MAC", map[string]string{"mac": "not-a-mac", "proxyId": "p1"}},
		{"MAC carrying markup", map[string]string{"mac": `00:11:22:33:44:50"><script>`, "proxyId": "p1"}},
		{"EUI-64 instead of MAC", map[string]string{"mac": "00:11:22:33:44:55:66:77", "proxyId": "p1"}},
		{"missing MAC for unknown device", map[string]string{"proxyId": "p1"}},
		{"nickname with control character", map[string]string{"mac": testDeviceMAC, "nickname": "pc\x00\x1b[31m", "proxyId": "p1"}},
		{"nickname too long", map[string]string{"mac": testDeviceMAC, "nickname": strings.Repeat("ấ", maxNameRunes+1), "proxyId": "p1"}},
		{"unknown proxy", map[string]string{"mac": testDeviceMAC, "proxyId": "missing"}},
	}
	for _, tc := range cases {
		w := call(t, srv, cookie, http.MethodPut, path, tc.body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d (%s)", tc.name, w.Code, w.Body.String())
		}
	}

	if router.hasAddress(testDeviceIP) || router.ipv6RuleCount() != 0 {
		t.Fatalf("rejected requests must not touch the router")
	}
	if dev := srv.state.GetDevice(testDeviceIP); dev != nil && dev.ProxyID != "" {
		t.Fatalf("rejected requests must not change state: %+v", dev)
	}

	// Nickname endpoint applies the same rules.
	w := call(t, srv, cookie, http.MethodPut, "/api/devices/"+testDeviceIP+"/nickname", map[string]string{"nickname": "a\nb"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("nickname with newline: expected 400, got %d", w.Code)
	}

	// A valid upper-case MAC is accepted and stored normalized.
	w = call(t, srv, cookie, http.MethodPut, path, map[string]string{"mac": "00-11-22-33-44-50", "nickname": " Máy tính ", "proxyId": "p1"})
	if w.Code != http.StatusOK {
		t.Fatalf("valid assignment: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	dev := srv.state.GetDevice(testDeviceIP)
	if dev == nil || dev.MAC != testDeviceMAC || dev.Nickname != "Máy tính" || dev.ProxyID != "p1" {
		t.Fatalf("unexpected stored device: %+v", dev)
	}
	if !router.hasAddress(testDeviceIP) || router.ipv6RuleCount() != 2 {
		t.Fatalf("router should hold the address-list entry and both IPv6 rules")
	}
}

func TestProxyIdentityIsServerSide(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)

	body := map[string]interface{}{
		"id":       `x" onmouseover="alert(1)`,
		"name":     "Injected",
		"protocol": "socks5",
		"host":     "1.2.3.4",
		"port":     1080,
		"lastTest": map[string]interface{}{"status": "ok", "exitIp": "<img src=x onerror=alert(1)>"},
	}
	w := call(t, srv, cookie, http.MethodPost, "/api/proxies", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", w.Code, w.Body.String())
	}

	proxies := srv.state.GetProxies()
	if len(proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(proxies))
	}
	got := proxies[0]
	if got.ID == "" || strings.ContainsAny(got.ID, `"<> `) {
		t.Fatalf("proxy ID was not generated by the server: %q", got.ID)
	}
	if got.LastTest != nil {
		t.Fatalf("client-supplied test result must be dropped: %+v", got.LastTest)
	}

	// Two creates with the same client ID must not overwrite each other.
	w = call(t, srv, cookie, http.MethodPost, "/api/proxies", body)
	if w.Code != http.StatusCreated || len(srv.state.GetProxies()) != 2 {
		t.Fatalf("second create should add a new proxy, got %d with %d proxies", w.Code, len(srv.state.GetProxies()))
	}

	// Names with control characters are refused.
	body["name"] = "bad\x07name"
	if w = call(t, srv, cookie, http.MethodPost, "/api/proxies", body); w.Code != http.StatusBadRequest {
		t.Fatalf("control character in name: expected 400, got %d", w.Code)
	}
}

func TestProxyCredentialsAreNotReturned(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)
	const secret = "s3cret-proxy-pass"
	const uuid = "0b0e7a5c-1111-2222-3333-444455556666"

	w := call(t, srv, cookie, http.MethodPost, "/api/proxies", map[string]interface{}{
		"name": "Auth SOCKS", "protocol": "socks5", "host": "1.2.3.4", "port": 1080,
		"username": "user", "password": secret,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d (%s)", w.Code, w.Body.String())
	}
	var created struct {
		ID          string `json:"id"`
		HasPassword bool   `json:"hasPassword"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if !created.HasPassword {
		t.Fatalf("hasPassword should be true: %s", w.Body.String())
	}

	saveProxy(t, srv, &proxy.Proxy{ID: "v1", Name: "VLESS", Protocol: proxy.ProtoVLESS, Host: "5.6.7.8", Port: 443, UUID: uuid})

	responses := map[string]*httptest.ResponseRecorder{
		"create":   w,
		"list":     call(t, srv, cookie, http.MethodGet, "/api/proxies", nil),
		"get":      call(t, srv, cookie, http.MethodGet, "/api/proxies/"+created.ID, nil),
		"get uuid": call(t, srv, cookie, http.MethodGet, "/api/proxies/v1", nil),
		"update": call(t, srv, cookie, http.MethodPut, "/api/proxies/"+created.ID, map[string]interface{}{
			"name": "Renamed", "protocol": "socks5", "host": "1.2.3.4", "port": 1080, "username": "user",
		}),
	}
	for name, resp := range responses {
		if resp.Code >= 300 {
			t.Errorf("%s: unexpected status %d (%s)", name, resp.Code, resp.Body.String())
		}
		body := resp.Body.String()
		if strings.Contains(body, secret) || strings.Contains(body, uuid) {
			t.Errorf("%s: response leaks a credential: %s", name, body)
		}
	}
	if !strings.Contains(responses["get uuid"].Body.String(), `"hasUuid":true`) {
		t.Errorf("hasUuid should be true: %s", responses["get uuid"].Body.String())
	}

	// The stored secret survives an update that does not resend it.
	stored := srv.state.GetProxy(created.ID)
	if stored.Password != secret || stored.Name != "Renamed" {
		t.Fatalf("update without password must keep it: %+v", stored)
	}
}

func TestProxyUpdateCredentialRules(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{
		ID: "p1", Name: "P1", Protocol: proxy.ProtoSocks5, Host: "1.2.3.4", Port: 1080,
		Username: "user", Password: "old-pass",
		LastTest: &proxy.TestResult{Status: "ok", ExitIP: "9.9.9.9"},
	})
	created := srv.state.GetProxy("p1").CreatedAt

	put := func(body map[string]interface{}) *httptest.ResponseRecorder {
		return call(t, srv, cookie, http.MethodPut, "/api/proxies/p1", body)
	}

	// Same endpoint, new password: password replaced, test result kept.
	if w := put(map[string]interface{}{"id": "other", "name": "P1", "protocol": "socks5", "host": "1.2.3.4", "port": 1080, "username": "user", "password": "new-pass"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	p := srv.state.GetProxy("p1")
	if p == nil || p.Password != "new-pass" || p.LastTest == nil || !p.CreatedAt.Equal(created) {
		t.Fatalf("unexpected proxy after password change: %+v", p)
	}
	if srv.state.GetProxy("other") != nil {
		t.Fatalf("the ID in the body must be ignored")
	}

	// Endpoint changed: the old test result no longer describes it.
	if w := put(map[string]interface{}{"name": "P1", "protocol": "socks5", "host": "4.3.2.1", "port": 1080, "username": "user"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	p = srv.state.GetProxy("p1")
	if p.LastTest != nil || p.Password != "new-pass" {
		t.Fatalf("host change should drop the test result and keep the password: %+v", p)
	}

	// Username removed: authentication is turned off.
	if w := put(map[string]interface{}{"name": "P1", "protocol": "socks5", "host": "4.3.2.1", "port": 1080}); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if p = srv.state.GetProxy("p1"); p.Password != "" || p.Username != "" {
		t.Fatalf("clearing the username should clear the password: %+v", p)
	}

	// Protocol changed: credentials of the old protocol are not carried over.
	if w := put(map[string]interface{}{"name": "P1", "protocol": "trojan", "host": "4.3.2.1", "port": 443}); w.Code != http.StatusBadRequest {
		t.Fatalf("trojan without a password must be rejected, got %d", w.Code)
	}

	if w := call(t, srv, cookie, http.MethodPut, "/api/proxies/missing", map[string]interface{}{"name": "x", "protocol": "http", "host": "1.1.1.1", "port": 80}); w.Code != http.StatusNotFound {
		t.Fatalf("update of unknown proxy: expected 404, got %d", w.Code)
	}
}

func TestDeleteAssignedProxyIsRefused(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})
	if err := srv.state.SetDeviceAssignment(testDeviceIP, testDeviceMAC, "Laptop", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}

	applied := 0
	srv.applyConfig = func([]byte) error { applied++; return nil }

	w := call(t, srv, cookie, http.MethodDelete, "/api/proxies/p1", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d (%s)", w.Code, w.Body.String())
	}
	var body struct {
		Error   string                `json:"error"`
		Devices []*state.DeviceConfig `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Devices) != 1 || body.Devices[0].IP != testDeviceIP || !strings.Contains(body.Error, "Laptop") {
		t.Fatalf("409 body should name the device: %s", w.Body.String())
	}
	if srv.state.GetProxy("p1") == nil || srv.state.GetDevice(testDeviceIP).ProxyID != "p1" {
		t.Fatalf("proxy and assignment must be untouched")
	}

	if err := srv.state.RemoveDeviceAssignment(testDeviceIP); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if w = call(t, srv, cookie, http.MethodDelete, "/api/proxies/p1", nil); w.Code != http.StatusOK {
		t.Fatalf("delete after unassign: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if srv.state.GetProxy("p1") != nil {
		t.Fatalf("proxy should be gone")
	}
	if applied != 0 {
		t.Fatalf("deleting an unassigned proxy must not restart sing-box, applied %d times", applied)
	}
	if w = call(t, srv, cookie, http.MethodDelete, "/api/proxies/p1", nil); w.Code != http.StatusNotFound {
		t.Fatalf("second delete: expected 404, got %d", w.Code)
	}
}

func TestUnassignReportsFailedStep(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})
	if err := srv.state.SetDeviceAssignment(testDeviceIP, testDeviceMAC, "", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	router.seedAssignment(testDeviceIP, testDeviceMAC)
	router.failAddressListDelete = true

	w := call(t, srv, cookie, http.MethodDelete, "/api/devices/"+testDeviceIP+"/assignment", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", w.Code, w.Body.String())
	}
	se := decodeStepError(t, w)
	if se.Step != stepAddressList || se.Applied || se.Error == "" {
		t.Fatalf("unexpected error body: %+v", se)
	}
	// Nothing may be half removed: the device still goes through the proxy.
	if srv.state.GetDevice(testDeviceIP).ProxyID != "p1" {
		t.Fatalf("state must keep the assignment when the router refuses")
	}
	if !router.hasAddress(testDeviceIP) || router.ipv6RuleCount() != 2 {
		t.Fatalf("router entries must be left in place")
	}
}

func TestAssignSingboxFailureRollsBackNewDevice(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})

	calls := 0
	srv.applyConfig = func([]byte) error {
		calls++
		if calls == 1 {
			return errors.New("sing-box check failed")
		}
		return nil
	}

	w := call(t, srv, cookie, http.MethodPut, "/api/devices/"+testDeviceIP+"/assignment",
		map[string]string{"mac": testDeviceMAC, "proxyId": "p1"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", w.Code, w.Body.String())
	}
	se := decodeStepError(t, w)
	if se.Step != stepSingbox || se.Applied {
		t.Fatalf("unexpected error body: %+v", se)
	}
	if dev := srv.state.GetDevice(testDeviceIP); dev != nil && dev.ProxyID != "" {
		t.Fatalf("state must not keep a failed assignment: %+v", dev)
	}
	// A device that was direct goes back to direct, with no stale IPv6 block.
	if router.hasAddress(testDeviceIP) || router.ipv6RuleCount() != 0 {
		t.Fatalf("router entries of the failed assignment must be removed")
	}
	if calls != 2 {
		t.Fatalf("expected a second apply restoring the previous config, got %d calls", calls)
	}
}

func TestReassignFailureKeepsDeviceBehindProxy(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})
	saveProxy(t, srv, &proxy.Proxy{ID: "p2", Name: "P2", Protocol: proxy.ProtoHTTP, Host: "2.2.2.2", Port: 8080})
	if err := srv.state.SetDeviceAssignment(testDeviceIP, testDeviceMAC, "Laptop", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	router.seedAssignment(testDeviceIP, testDeviceMAC)

	calls := 0
	srv.applyConfig = func([]byte) error {
		calls++
		if calls == 1 {
			return errors.New("sing-box check failed")
		}
		return nil
	}

	w := call(t, srv, cookie, http.MethodPut, "/api/devices/"+testDeviceIP+"/assignment",
		map[string]string{"mac": testDeviceMAC, "nickname": "Renamed", "proxyId": "p2"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", w.Code, w.Body.String())
	}
	if se := decodeStepError(t, w); se.Step != stepSingbox || se.Applied {
		t.Fatalf("unexpected error body: %+v", se)
	}

	dev := srv.state.GetDevice(testDeviceIP)
	if dev == nil || dev.ProxyID != "p1" || dev.Nickname != "Laptop" {
		t.Fatalf("previous assignment must be restored: %+v", dev)
	}
	// Rolling back must never drop the device out of PROXY_DEVICES: that
	// would send it straight to the internet with its real IP.
	if !router.hasAddress(testDeviceIP) || router.ipv6RuleCount() != 2 {
		t.Fatalf("an already assigned device must stay behind the proxy after a failed change")
	}
}

func TestSystemStatusAndReconcileReportErrors(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)

	w := call(t, srv, cookie, http.MethodGet, "/api/system/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status["leakGuard"] == nil || status["singbox"] == nil {
		t.Fatalf("status body should hold singbox and leakGuard: %s", w.Body.String())
	}

	srv.applyConfig = func([]byte) error { return errors.New("sing-box refused the config") }
	w = call(t, srv, cookie, http.MethodPost, "/api/system/reconcile", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("reconcile: expected 500, got %d (%s)", w.Code, w.Body.String())
	}
	if se := decodeStepError(t, w); se.Step != stepSingbox {
		t.Fatalf("reconcile should name the sing-box step: %+v", se)
	}
}
