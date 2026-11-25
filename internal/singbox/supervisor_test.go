package singbox

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/config"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/state"
)

func TestSupervisorApplyAndStatus(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "supervisor_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DataDir:     tempDir,
		ContainerGW: "10.10.10.1",
		LanCIDR:     "10.88.88.0/24",
		SingboxPath: "sing-box",
	}

	st, err := state.Load(tempDir)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	cfgBytes, err := GenerateConfig(cfg, st)
	if err != nil {
		t.Fatalf("failed to generate config: %v", err)
	}

	sup := NewSupervisor("sing-box", tempDir)
	defer sup.Stop()

	// Apply invalid config -> should fail without updating
	invalidBytes := []byte(`{"invalid": "json`)
	if err := sup.ApplyConfig(invalidBytes); err == nil {
		t.Fatalf("expected error applying invalid json")
	}

	// Apply valid config
	if err := sup.ApplyConfig(cfgBytes); err != nil {
		t.Fatalf("failed to apply valid config: %v", err)
	}

	status := sup.GetStatus()
	if !strings.Contains(status.Version, "sing-box") {
		t.Fatalf("unexpected version: %s", status.Version)
	}
	if status.ConfigPath == "" {
		t.Fatalf("empty config path")
	}

	// Wait briefly and verify status or logs
	time.Sleep(200 * time.Millisecond)
	logs := sup.GetLogs()
	if len(logs) > 0 {
		// Verify no leaked secrets
		for _, l := range logs {
			if strings.Contains(l, "password=") && !strings.Contains(l, "password=***") {
				t.Fatalf("unredacted password found in log: %s", l)
			}
		}
	}
}
