package proxy

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseHTTP(t *testing.T) {
	raw := "http://user:secret@proxy.example.com:8080#MyHTTP"
	p, err := ParseURI(raw, ProtoHTTP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoHTTP || p.Host != "proxy.example.com" || p.Port != 8080 || p.Username != "user" || p.Password != "secret" || p.Name != "MyHTTP" {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}
	if p.UDP {
		t.Fatalf("HTTP should not have UDP enabled")
	}
}

func TestParseHTTPS(t *testing.T) {
	raw := "https://admin:pass@ssl.example.com:8443#SecureHTTP"
	p, err := ParseURI(raw, ProtoHTTPS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoHTTPS || p.Host != "ssl.example.com" || p.Port != 8443 || !p.TLS {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}
}

func TestParseSocks5(t *testing.T) {
	raw := "socks5://socksuser:sockspass@192.168.1.50:1080?udp=1#MySocks"
	p, err := ParseURI(raw, ProtoSocks5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoSocks5 || p.Host != "192.168.1.50" || p.Port != 1080 || !p.UDP {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}
}

func TestParseRawHostPort(t *testing.T) {
	raw := "1.2.3.4:9999:myuser:mypass"
	p, err := ParseURI(raw, ProtoSocks5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoSocks5 || p.Host != "1.2.3.4" || p.Port != 9999 || p.Username != "myuser" || p.Password != "mypass" {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}
}

func TestParseShadowsocks(t *testing.T) {
	// SIP002 format
	userPassB64 := base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:mypassword"))
	raw := "ss://" + userPassB64 + "@1.2.3.4:8388?udp=1#MySS"
	p, err := ParseURI(raw, ProtoShadowsocks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoShadowsocks || p.Host != "1.2.3.4" || p.Port != 8388 || p.Method != "aes-256-gcm" || p.Password != "mypassword" || !p.UDP {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}

	// Legacy format: ss://BASE64(method:password@host:port)#name
	legacyB64 := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:legacypass@5.6.7.8:8443"))
	rawLegacy := "ss://" + legacyB64 + "#LegacySS"
	p2, err := ParseURI(rawLegacy, ProtoShadowsocks)
	if err != nil {
		t.Fatalf("unexpected legacy error: %v", err)
	}
	if p2.Host != "5.6.7.8" || p2.Port != 8443 || p2.Method != "chacha20-ietf-poly1305" || p2.Password != "legacypass" {
		t.Fatalf("parsed legacy fields mismatch: %+v", p2)
	}
}

func TestParseTrojan(t *testing.T) {
	raw := "trojan://trojanpass@trojan.example.com:443?sni=trojan.example.com&type=ws&path=/trojanws&udp=1#MyTrojan"
	p, err := ParseURI(raw, ProtoTrojan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoTrojan || p.Password != "trojanpass" || p.Transport != "ws" || p.WSPath != "/trojanws" || !p.TLS || !p.UDP {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}
}

func TestParseVLESSReality(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@vless.example.com:443?security=reality&sni=target.com&fp=chrome&pbk=q6X_z88QxH98Y64aV_2G_m5l44B8H8wU1d6v9320eQo&sid=0123456789abcdef&flow=xtls-rprx-vision&udp=1#MyVLESS"
	p, err := ParseURI(raw, ProtoVLESS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoVLESS || p.UUID != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" || p.Security != "reality" || p.SNI != "target.com" || p.PublicKey != "q6X_z88QxH98Y64aV_2G_m5l44B8H8wU1d6v9320eQo" || p.ShortID != "0123456789abcdef" || p.Flow != "xtls-rprx-vision" || !p.UDP {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}
}

func TestParseVMess(t *testing.T) {
	vj := map[string]interface{}{
		"v":    "2",
		"ps":   "MyVMess",
		"add":  "vmess.example.com",
		"port": 443,
		"id":   "b831381d-6324-4d53-ad4f-8cda48b30811",
		"aid":  0,
		"scy":  "auto",
		"net":  "ws",
		"type": "none",
		"host": "vmess.example.com",
		"path": "/ray",
		"tls":  "tls",
		"sni":  "vmess.example.com",
		"udp":  true,
	}
	bytes, _ := json.Marshal(vj)
	raw := "vmess://" + base64.StdEncoding.EncodeToString(bytes)

	p, err := ParseURI(raw, ProtoVMess)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Protocol != ProtoVMess || p.Host != "vmess.example.com" || p.Port != 443 || p.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" || !p.TLS || p.Transport != "ws" || p.WSPath != "/ray" || !p.UDP {
		t.Fatalf("parsed fields mismatch: %+v", p)
	}
}

func TestParseBatchURIs(t *testing.T) {
	input := `
# Comment line
http://user:pass@1.1.1.1:8080#P1
socks5://user:pass@2.2.2.2:1080#P2
invalid:::uri
`
	proxies, errs := ParseURIs(input, ProtoHTTP)
	if len(proxies) != 2 {
		t.Fatalf("expected 2 valid proxies, got: %d", len(proxies))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got: %d", len(errs))
	}
	if !strings.Contains(errs[0].Error(), "line 5") {
		t.Fatalf("expected error on line 5, got: %v", errs[0])
	}
}

func TestMalformedInputs(t *testing.T) {
	badInputs := []string{
		"http://host:99999",    // Port out of range
		"http://host:-1",       // Negative port
		"http://bad host:8080", // Invalid host characters
		"vless://@host:443",    // Missing UUID
		"shadowsocks://",       // Empty SS
	}

	for _, bad := range badInputs {
		_, err := ParseURI(bad, ProtoHTTP)
		if err == nil {
			t.Errorf("expected error for malformed input %q, got nil", bad)
		}
	}
}
