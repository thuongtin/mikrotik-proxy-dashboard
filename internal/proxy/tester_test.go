package proxy

import (
	"context"
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
