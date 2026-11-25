package state

import (
	"errors"
	"os"
	"testing"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
)

func TestStatePersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "state_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	s, err := Load(tempDir)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	p := &proxy.Proxy{
		ID:       "proxy-1",
		Name:     "Test SOCKS5",
		Protocol: proxy.ProtoSocks5,
		Host:     "1.1.1.1",
		Port:     1080,
	}

	if err := s.SaveProxy(p); err != nil {
		t.Fatalf("failed to save proxy: %v", err)
	}

	if err := s.SetDeviceAssignment("10.88.88.50", "00:11:22:33:44:55", "Work Laptop", "proxy-1"); err != nil {
		t.Fatalf("failed to set assignment: %v", err)
	}

	// Verify assignments
	assigned := s.GetAssignedDevices()
	if len(assigned) != 1 || assigned[0].IP != "10.88.88.50" {
		t.Fatalf("expected 1 assigned device, got: %d", len(assigned))
	}

	// Reload state from disk to test persistence
	s2, err := Load(tempDir)
	if err != nil {
		t.Fatalf("failed to reload state: %v", err)
	}

	pLoaded := s2.GetProxy("proxy-1")
	if pLoaded == nil || pLoaded.Host != "1.1.1.1" {
		t.Fatalf("reloaded proxy mismatch")
	}

	devLoaded := s2.GetDevice("10.88.88.50")
	if devLoaded == nil || devLoaded.ProxyID != "proxy-1" || devLoaded.Nickname != "Work Laptop" {
		t.Fatalf("reloaded device mismatch: %+v", devLoaded)
	}

	// A proxy that still carries a device must not be deletable.
	if err := s2.DeleteProxy("proxy-1"); !errors.Is(err, ErrProxyInUse) {
		t.Fatalf("expected ErrProxyInUse, got: %v", err)
	}
	if s2.GetProxy("proxy-1") == nil {
		t.Fatalf("proxy must survive a refused deletion")
	}
	if dev := s2.GetDevice("10.88.88.50"); dev == nil || dev.ProxyID != "proxy-1" {
		t.Fatalf("assignment must survive a refused deletion: %+v", dev)
	}
	if users := s2.DevicesUsingProxy("proxy-1"); len(users) != 1 || users[0].IP != "10.88.88.50" {
		t.Fatalf("expected one device using the proxy, got: %+v", users)
	}

	// Once the device is unassigned the proxy can go.
	if err := s2.RemoveDeviceAssignment("10.88.88.50"); err != nil {
		t.Fatalf("failed to remove assignment: %v", err)
	}
	if err := s2.DeleteProxy("proxy-1"); err != nil {
		t.Fatalf("failed to delete unassigned proxy: %v", err)
	}
	if s2.GetProxy("proxy-1") != nil {
		t.Fatalf("proxy should be gone after deletion")
	}
}

func TestSetProxyTestResultNeverCreatesProxy(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	res := &proxy.TestResult{Status: "ok", ExitIP: "203.0.113.7"}
	if err := s.SetProxyTestResult("missing", res); !errors.Is(err, ErrProxyNotFound) {
		t.Fatalf("expected ErrProxyNotFound, got: %v", err)
	}
	if len(s.GetProxies()) != 0 {
		t.Fatalf("a test result must not create a proxy")
	}

	p := &proxy.Proxy{ID: "p1", Name: "P1", Protocol: "socks5", Host: "1.1.1.1", Port: 1080}
	if err := s.SaveProxy(p); err != nil {
		t.Fatalf("failed to save proxy: %v", err)
	}
	if err := s.SetProxyTestResult("p1", res); err != nil {
		t.Fatalf("failed to store test result: %v", err)
	}
	if got := s.GetProxy("p1"); got.LastTest == nil || got.LastTest.ExitIP != "203.0.113.7" {
		t.Fatalf("test result not stored: %+v", got.LastTest)
	}
}
