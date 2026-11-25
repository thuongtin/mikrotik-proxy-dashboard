package state

import (
	"os"
	"testing"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/proxy"
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

	// Deleting proxy should clear device assignment
	if err := s2.DeleteProxy("proxy-1"); err != nil {
		t.Fatalf("failed to delete proxy: %v", err)
	}
	devAfterDelete := s2.GetDevice("10.88.88.50")
	if devAfterDelete.ProxyID != "" {
		t.Fatalf("device assignment should be cleared after proxy deletion")
	}
}
