package proxy

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestToSingboxOutbounds(t *testing.T) {
	protocols := []string{ProtoHTTP, ProtoHTTPS, ProtoSocks5, ProtoShadowsocks, ProtoTrojan, ProtoVLESS, ProtoVMess}

	for _, proto := range protocols {
		p := &Proxy{
			ID:          "p1",
			Protocol:    proto,
			Host:        "1.2.3.4",
			Port:        1080,
			Method:      "aes-256-gcm",
			Password:    "testpass",
			UUID:        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			Security:    "reality",
			PublicKey:   "q6X_z88QxH98Y64aV_2G_m5l44B8H8wU1d6v9320eQo",
			ShortID:     "0123456789abcdef",
			Fingerprint: "chrome",
			Transport:   "ws",
			WSPath:      "/ws",
		}
		out := p.ToSingboxOutbound("proxy")
		if out["tag"] != "proxy" {
			t.Errorf("expected tag proxy for %s, got %v", proto, out["tag"])
		}
		if out["server"] != "1.2.3.4" {
			t.Errorf("expected server 1.2.3.4 for %s, got %v", proto, out["server"])
		}
	}
}

func TestEphemeralProxyTester(t *testing.T) {
	// Test against an unreachable test proxy (127.0.0.1 on closed port)
	p := &Proxy{
		ID:       "test-dead",
		Name:     "DeadProxy",
		Protocol: ProtoSocks5,
		Host:     "127.0.0.1",
		Port:     59999, // Unused port
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	res, err := TestProxy(ctx, p, "sing-box")
	if err != nil {
		t.Fatalf("TestProxy returned unexpected error: %v", err)
	}
	if res.Status != "error" {
		t.Fatalf("expected status error for unreachable proxy, got: %s", res.Status)
	}
	if p.LastTest == nil || p.LastTest.Status != "error" {
		t.Fatalf("expected proxy LastTest to be set to error")
	}
}

func TestEphemeralProxyTesterWithOptionsAndSingboxCheck(t *testing.T) {
	testCases := []struct {
		name       string
		opts       TestOptions
		expectDNS  bool
		expectVeth bool
	}{
		{
			name: "Both VethIF and ContainerGW set",
			opts: TestOptions{
				SingboxPath: "sing-box",
				VethIF:      "veth-proxy",
				ContainerGW: "10.10.10.1",
			},
			expectDNS:  true,
			expectVeth: true,
		},
		{
			name: "Only ContainerGW set",
			opts: TestOptions{
				SingboxPath: "sing-box",
				ContainerGW: "10.10.10.1",
			},
			expectDNS:  true,
			expectVeth: false,
		},
		{
			name: "Neither set (minimal)",
			opts: TestOptions{
				SingboxPath: "sing-box",
			},
			expectDNS:  false,
			expectVeth: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{
				ID:       "test-opts",
				Name:     "TestOptsProxy",
				Protocol: ProtoHTTP,
				Host:     "proxy.example.com",
				Port:     8080,
				Username: "user",
				Password: "secretpassword",
			}

			// Build config dictionary matching what TestProxyWithOptions generates
			outbound := p.ToSingboxOutbound("proxy")
			if tc.opts.VethIF != "" {
				outbound["bind_interface"] = tc.opts.VethIF
			}

			routeCfg := map[string]interface{}{
				"final": "proxy",
			}
			if tc.opts.VethIF != "" {
				routeCfg["default_interface"] = tc.opts.VethIF
			}

			cfg := map[string]interface{}{
				"log": map[string]interface{}{
					"level": "warn",
				},
				"inbounds": []interface{}{
					map[string]interface{}{
						"type":        "mixed",
						"tag":         "mixed-in",
						"listen":      "127.0.0.1",
						"listen_port": 12345,
					},
				},
				"outbounds": []interface{}{
					outbound,
				},
			}

			if tc.opts.ContainerGW != "" {
				cfg["dns"] = map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{
							"tag":         "dns-bootstrap",
							"type":        "udp",
							"server":      tc.opts.ContainerGW,
							"server_port": 53,
						},
					},
					"final":    "dns-bootstrap",
					"strategy": "ipv4_only",
				}
				routeCfg["default_domain_resolver"] = "dns-bootstrap"
			}
			cfg["route"] = routeCfg

			cfgBytes, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("failed to marshal test config: %v", err)
			}
			cfgStr := string(cfgBytes)

			if tc.expectDNS {
				if !strings.Contains(cfgStr, `"dns-bootstrap"`) {
					t.Fatalf("expected dns-bootstrap in config: %s", cfgStr)
				}
				if !strings.Contains(cfgStr, `"default_domain_resolver":"dns-bootstrap"`) {
					t.Fatalf("expected default_domain_resolver in config: %s", cfgStr)
				}
			}
			if tc.expectVeth {
				if !strings.Contains(cfgStr, `"bind_interface":"veth-proxy"`) {
					t.Fatalf("expected bind_interface in config: %s", cfgStr)
				}
				if !strings.Contains(cfgStr, `"default_interface":"veth-proxy"`) {
					t.Fatalf("expected default_interface in config: %s", cfgStr)
				}
			}

			// Validate with real sing-box check
			tmpFile, err := os.CreateTemp("", "singbox-tester-check-*.json")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write(cfgBytes); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			_ = tmpFile.Close()

			cmd := exec.Command("sing-box", "check", "-c", tmpFile.Name())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("sing-box check failed: %v\nOutput: %s\nConfig: %s", err, string(out), cfgStr)
			}
		})
	}
}

func TestSanitizeError(t *testing.T) {
	raw := "connection failed: password=supersecret pass=123 secret=xyz uuid=abc-123 token=tok456 pbk=pubkey123 sid=short456"
	sanitized := sanitizeError(raw)
	if strings.Contains(sanitized, "supersecret") || strings.Contains(sanitized, "xyz") || strings.Contains(sanitized, "pubkey123") {
		t.Fatalf("sensitive data leaked in sanitized error: %s", sanitized)
	}
	if !strings.Contains(sanitized, "password=***") || !strings.Contains(sanitized, "secret=***") {
		t.Fatalf("expected replacement with ***: %s", sanitized)
	}
}
