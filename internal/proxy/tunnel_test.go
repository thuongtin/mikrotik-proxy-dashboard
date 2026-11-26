package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// testTunnelProto is a tunnel protocol that exists only in these tests.
const testTunnelProto = "tunneltest"

func init() {
	RegisterTunnelProtocol(testTunnelProto, TunnelProtocol{
		Normalize: func(p *Proxy) error {
			if p.TunnelLocation == "" {
				return errors.New("location required")
			}
			*p = Proxy{ID: p.ID, Name: p.Name, Protocol: p.Protocol, TunnelLocation: p.TunnelLocation, TunnelTransport: TunnelTransportUDP, UDP: true}
			return nil
		},
		Interface: func(id string) string { return "tt" + id },
	})
}

func TestTunnelProtocolRegistry(t *testing.T) {
	p := &Proxy{ID: "abc", Name: "T", Protocol: testTunnelProto, TunnelLocation: "xyz", Host: "stale.example.com", Port: 1}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !p.IsTunnel() || p.TunnelInterface() != "ttabc" || p.Host != "" {
		t.Fatalf("tunnel profile not normalized by its protocol: %+v", p)
	}
	out := p.ToSingboxOutbound("proxy-abc")
	if out["type"] != "direct" || out["bind_interface"] != "ttabc" {
		t.Fatalf("tunnel outbound = %v", out)
	}
	if err := (&Proxy{Protocol: testTunnelProto}).Validate(); err == nil {
		t.Fatal("the protocol's own validation was skipped")
	}

	plain := &Proxy{Protocol: ProtoSocks5, Host: "1.2.3.4", Port: 1080, TunnelLocation: "xyz", TunnelTransport: "tcp"}
	if err := plain.Validate(); err != nil {
		t.Fatal(err)
	}
	if plain.IsTunnel() || plain.TunnelInterface() != "" || plain.TunnelLocation != "" || plain.TunnelTransport != "" {
		t.Fatalf("plain proxy kept tunnel fields: %+v", plain)
	}
}

// A tunnel profile's test config must pass sing-box check even before its
// interface exists; the test then fails at connect time, not at check time.
func TestTunnelProfileTestConfig(t *testing.T) {
	p := &Proxy{ID: "0123456789ab", Name: "Tunnel", Protocol: testTunnelProto, TunnelLocation: "nyc"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := TestProxyWithOptions(ctx, p, TestOptions{SingboxPath: "sing-box", VethIF: "veth-proxy", ContainerGW: "10.10.10.1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "error" {
		t.Fatalf("status = %s, want error with no tunnel interface", res.Status)
	}
	if strings.Contains(res.Error, "check failed") {
		t.Fatalf("test config rejected: %s", res.Error)
	}
}
