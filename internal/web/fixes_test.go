package web

import (
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
)

const otherMAC = "00:11:22:33:44:aa"

func TestRouterRoutesReturn503WithoutClient(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)
	srv.mikrotik = nil

	routes := []struct{ method, path string }{
		{http.MethodGet, "/api/devices"},
		{http.MethodPut, "/api/devices/" + testDeviceIP + "/assignment"},
		{http.MethodGet, "/api/system/status"},
		{http.MethodPost, "/api/system/reconcile"},
		{http.MethodPost, "/api/system/flush-all"},
	}
	for _, rt := range routes {
		w := call(t, srv, cookie, rt.method, rt.path, map[string]string{"mac": testDeviceMAC, "proxyId": "p1"})
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: expected 503, got %d (%s)", rt.method, rt.path, w.Code, w.Body.String())
		}
	}

	// Auth still comes first: no session means 401, not a hint about the router.
	if w := call(t, srv, nil, http.MethodGet, "/api/devices", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: expected 401, got %d", w.Code)
	}
	// Routes that do not need the router keep working.
	if w := call(t, srv, cookie, http.MethodGet, "/api/proxies", nil); w.Code != http.StatusOK {
		t.Errorf("/api/proxies: expected 200, got %d", w.Code)
	}
}

func TestIsReservedLANAddress(t *testing.T) {
	srv, _, _ := newHardeningServer(t)
	_, lan, _ := net.ParseCIDR("10.88.88.0/24")

	cases := []struct {
		ip       string
		url      string
		reserved bool
	}{
		{"10.88.88.0", "", true},
		{"10.88.88.255", "", true},
		{"10.88.88.1", "", true},
		{"10.88.88.50", "", false},
		{"10.88.88.254", "https://10.88.88.254", true},
		{"10.88.88.254", "10.88.88.254:8443", true},
		{"10.88.88.254", "https://10.88.88.1", false},
		{"10.88.88.21", "https://router.lan", false},
	}
	for _, tc := range cases {
		srv.cfg.MikroTikURL = tc.url
		if got := srv.isReservedLANAddress(net.ParseIP(tc.ip), lan); got != tc.reserved {
			t.Errorf("ip=%s url=%q: expected reserved=%v, got %v", tc.ip, tc.url, tc.reserved, got)
		}
	}
}

func TestAssignRejectsReservedAddress(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})

	for _, ip := range []string{"10.88.88.0", "10.88.88.1", "10.88.88.255"} {
		w := call(t, srv, cookie, http.MethodPut, "/api/devices/"+ip+"/assignment",
			map[string]string{"mac": testDeviceMAC, "proxyId": "p1"})
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d (%s)", ip, w.Code, w.Body.String())
		}
		if router.hasAddress(ip) {
			t.Errorf("%s: a reserved address must never reach PROXY_DEVICES", ip)
		}
	}
}

func TestAssignRollbackLeavesNoStateForNewDevice(t *testing.T) {
	srv, _, cookie := newHardeningServer(t)
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
		map[string]string{"mac": testDeviceMAC, "nickname": "Laptop", "proxyId": "p1"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", w.Code, w.Body.String())
	}
	if dev := srv.state.GetDevice(testDeviceIP); dev != nil {
		t.Fatalf("a failed first assignment must not leave a device entry behind: %+v", dev)
	}
}

func TestAssignNewMACRemovesOldMACRules(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})
	if err := srv.state.SetDeviceAssignment(testDeviceIP, otherMAC, "Laptop", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	router.seedAssignment(testDeviceIP, otherMAC)

	w := call(t, srv, cookie, http.MethodPut, "/api/devices/"+testDeviceIP+"/assignment",
		map[string]string{"mac": testDeviceMAC, "proxyId": "p1"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if n := router.ipv6RulesFor(otherMAC); n != 0 {
		t.Fatalf("rules of the old MAC must be removed, %d left", n)
	}
	if n := router.ipv6RulesFor(testDeviceMAC); n != 2 {
		t.Fatalf("expected 2 rules for the new MAC, got %d", n)
	}
}

func TestAssignNewMACKeepsRulesSharedWithAnotherDevice(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})
	if err := srv.state.SetDeviceAssignment(testDeviceIP, otherMAC, "Laptop", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// The same MAC is also assigned on another IP, so its rules must stay.
	if err := srv.state.SetDeviceAssignment("10.88.88.60", otherMAC, "Laptop 2", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	router.seedAssignment(testDeviceIP, otherMAC)

	w := call(t, srv, cookie, http.MethodPut, "/api/devices/"+testDeviceIP+"/assignment",
		map[string]string{"mac": testDeviceMAC, "proxyId": "p1"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	if n := router.ipv6RulesFor(otherMAC); n != 2 {
		t.Fatalf("rules still used by 10.88.88.60 must stay, got %d", n)
	}
}

func TestAssignNewMACRollbackRemovesNewRules(t *testing.T) {
	srv, router, cookie := newHardeningServer(t)
	saveProxy(t, srv, &proxy.Proxy{ID: "p1", Name: "P1", Protocol: proxy.ProtoHTTP, Host: "1.1.1.1", Port: 8080})
	saveProxy(t, srv, &proxy.Proxy{ID: "p2", Name: "P2", Protocol: proxy.ProtoHTTP, Host: "2.2.2.2", Port: 8080})
	if err := srv.state.SetDeviceAssignment(testDeviceIP, otherMAC, "Laptop", "p1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	router.seedAssignment(testDeviceIP, otherMAC)

	calls := 0
	srv.applyConfig = func([]byte) error {
		calls++
		if calls == 1 {
			return errors.New("sing-box check failed")
		}
		return nil
	}
	w := call(t, srv, cookie, http.MethodPut, "/api/devices/"+testDeviceIP+"/assignment",
		map[string]string{"mac": testDeviceMAC, "proxyId": "p2"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", w.Code, w.Body.String())
	}
	if n := router.ipv6RulesFor(testDeviceMAC); n != 0 {
		t.Fatalf("rules created for the new MAC must be rolled back, %d left", n)
	}
	if n := router.ipv6RulesFor(otherMAC); n != 2 {
		t.Fatalf("rules of the restored MAC must stay, got %d", n)
	}
	if dev := srv.state.GetDevice(testDeviceIP); dev == nil || dev.MAC != otherMAC || dev.ProxyID != "p1" {
		t.Fatalf("previous assignment must be restored: %+v", dev)
	}
}
