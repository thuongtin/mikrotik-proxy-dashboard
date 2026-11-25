package singbox

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/config"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
)

func TestGenerateConfigAndSingboxCheck(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "singbox_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DataDir:      tempDir,
		ContainerGW:  "10.10.10.1",
		LanCIDR:      "10.88.88.0/24",
		ExcludeCIDRs: []string{"10.88.88.0/24", "10.10.10.0/24", "192.168.0.0/16"},
		SingboxPath:  "sing-box",
	}

	st, err := state.Load(tempDir)
	if err != nil {
		t.Fatalf("failed to init state: %v", err)
	}

	// Add 7 proxies across all protocols
	proxies := []*proxy.Proxy{
		{
			ID:       "p-http",
			Name:     "HTTP Proxy",
			Protocol: proxy.ProtoHTTP,
			Host:     "1.2.3.4",
			Port:     8080,
			Username: "user",
			Password: "password",
		},
		{
			ID:       "p-https",
			Name:     "HTTPS Proxy",
			Protocol: proxy.ProtoHTTPS,
			Host:     "1.2.3.4",
			Port:     8443,
			TLS:      true,
			SNI:      "example.com",
		},
		{
			ID:       "p-socks5",
			Name:     "SOCKS5 Proxy",
			Protocol: proxy.ProtoSocks5,
			Host:     "1.2.3.4",
			Port:     1080,
			UDP:      true,
		},
		{
			ID:       "p-ss",
			Name:     "Shadowsocks Proxy",
			Protocol: proxy.ProtoShadowsocks,
			Host:     "1.2.3.4",
			Port:     8388,
			Method:   "aes-256-gcm",
			Password: "secretpassword",
			UDP:      true,
		},
		{
			ID:       "p-trojan",
			Name:     "Trojan Proxy",
			Protocol: proxy.ProtoTrojan,
			Host:     "trojan.example.com",
			Port:     443,
			Password: "trojanpassword",
			TLS:      true,
			SNI:      "trojan.example.com",
			UDP:      true,
		},
		{
			ID:          "p-vless",
			Name:        "VLESS Reality",
			Protocol:    proxy.ProtoVLESS,
			Host:        "vless.example.com",
			Port:        443,
			UUID:        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			Flow:        "xtls-rprx-vision",
			Security:    "reality",
			SNI:         "vless.example.com",
			Fingerprint: "chrome",
			PublicKey:   "q6X_z88QxH98Y64aV_2G_m5l44B8H8wU1d6v9320eQo",
			ShortID:     "0123456789abcdef",
			UDP:         true,
		},
		{
			ID:        "p-vmess",
			Name:      "VMess WS",
			Protocol:  proxy.ProtoVMess,
			Host:      "vmess.example.com",
			Port:      443,
			UUID:      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			AlterID:   0,
			Security:  "auto",
			TLS:       true,
			SNI:       "vmess.example.com",
			Transport: "ws",
			WSPath:    "/ray",
			UDP:       true,
		},
	}

	for _, p := range proxies {
		if err := st.SaveProxy(p); err != nil {
			t.Fatalf("failed to save proxy: %v", err)
		}
	}

	// Assign devices:
	// Dev 1: Assigned to HTTP proxy (no UDP -> should have UDP reject rule)
	if err := st.SetDeviceAssignment("10.88.88.50", "00:11:22:33:44:55", "PC1", "p-http"); err != nil {
		t.Fatalf("failed to set assignment: %v", err)
	}
	// Dev 2: Assigned to VLESS Reality (UDP enabled -> routes UDP)
	if err := st.SetDeviceAssignment("10.88.88.51", "00:11:22:33:44:56", "PC2", "p-vless"); err != nil {
		t.Fatalf("failed to set assignment: %v", err)
	}

	// Generate sing-box config
	configBytes, err := GenerateConfig(cfg, st)
	if err != nil {
		t.Fatalf("failed to generate config: %v", err)
	}

	cfgStr := string(configBytes)

	// Assertions for Zero-Leak Fail-Closed Rules
	if !strings.Contains(cfgStr, `"dns-fakeip"`) {
		t.Fatalf("missing dns-fakeip server")
	}
	// A long FakeIP TTL breaks a device for minutes after it goes back to direct.
	if !strings.Contains(cfgStr, `"rewrite_ttl": 1`) {
		t.Fatalf("FakeIP rule must rewrite the TTL to 1 second")
	}
	if !strings.Contains(cfgStr, `"dns-doh-p-vless"`) {
		t.Fatalf("missing DoH server for assigned proxy")
	}
	if !strings.Contains(cfgStr, `"detour": "proxy-p-vless"`) {
		t.Fatalf("missing DoH detour")
	}
	if !strings.Contains(cfgStr, `"action": "hijack-dns"`) {
		t.Fatalf("missing DNS hijack rule")
	}
	if !strings.Contains(cfgStr, `"no_drop": true`) {
		t.Fatalf("missing UDP reject rule for non-UDP proxy")
	}

	// Validate using real sing-box binary
	tmpConfigFile, err := os.CreateTemp("", "singbox-full-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpConfigFile.Name())

	if _, err := tmpConfigFile.Write(configBytes); err != nil {
		t.Fatalf("failed to write config to temp file: %v", err)
	}
	_ = tmpConfigFile.Close()

	cmd := exec.Command("sing-box", "check", "-c", tmpConfigFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check failed: %v\nOutput:\n%s\nConfig:\n%s", err, string(output), cfgStr)
	}
}
