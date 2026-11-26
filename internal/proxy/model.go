package proxy

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Supported proxy protocols
const (
	ProtoHTTP        = "http"
	ProtoHTTPS       = "https"
	ProtoSocks5      = "socks5"
	ProtoShadowsocks = "shadowsocks"
	ProtoTrojan      = "trojan"
	ProtoVLESS       = "vless"
	ProtoVMess       = "vmess"
)

// Tunnel transports: how a tunnel reaches its server, not what the device
// may send. A TCP tunnel still carries the device's UDP traffic.
const (
	TunnelTransportUDP = "udp"
	TunnelTransportTCP = "tcp"
)

var validProtocols = map[string]bool{
	ProtoHTTP:        true,
	ProtoHTTPS:       true,
	ProtoSocks5:      true,
	ProtoShadowsocks: true,
	ProtoTrojan:      true,
	ProtoVLESS:       true,
	ProtoVMess:       true,
}

var hostRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// TestResult holds live connectivity test output.
type TestResult struct {
	Status      string    `json:"status"` // "ok", "error"
	ExitIP      string    `json:"exitIp,omitempty"`
	Country     string    `json:"country,omitempty"`
	CountryCode string    `json:"countryCode,omitempty"`
	City        string    `json:"city,omitempty"`
	ISP         string    `json:"isp,omitempty"`
	LatencyMs   int64     `json:"latencyMs"`
	Error       string    `json:"error,omitempty"`
	TestedAt    time.Time `json:"testedAt"`
}

// Proxy defines configuration for a proxy outbound.
type Proxy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // http, https, socks5, shadowsocks, trojan, vless, vmess
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	UDP      bool   `json:"udp"` // UDP relay supported (defaults to false for http/https)

	// Shadowsocks
	Method string `json:"method,omitempty"`

	// VLESS / VMess
	UUID     string `json:"uuid,omitempty"`
	AlterID  int    `json:"alterId,omitempty"`
	Security string `json:"security,omitempty"` // tls, reality, none, or vmess cipher
	Flow     string `json:"flow,omitempty"`     // xtls-rprx-vision

	// TLS / Reality / SNI
	TLS         bool   `json:"tls,omitempty"`
	SNI         string `json:"sni,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // chrome, firefox, etc.
	PublicKey   string `json:"publicKey,omitempty"`   // reality public key
	ShortID     string `json:"shortId,omitempty"`     // reality short id

	// Transport (ws, grpc, tcp)
	Transport       string `json:"transport,omitempty"` // tcp, ws, grpc
	WSPath          string `json:"wsPath,omitempty"`
	WSHost          string `json:"wsHost,omitempty"`
	GRPCServiceName string `json:"grpcServiceName,omitempty"`

	// Tunnel profiles: the location code the tunnel provider uses and the
	// transport ("udp" or "tcp"). Other protocols leave them empty.
	TunnelLocation  string `json:"vpnLocation,omitempty"`
	TunnelTransport string `json:"vpnTransport,omitempty"`

	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
	LastTest  *TestResult `json:"lastTest,omitempty"`
}

// Validate checks proxy fields for correctness and security.
func (p *Proxy) Validate() error {
	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	if !validProtocols[p.Protocol] {
		return fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}

	if tp, ok := tunnelProtocols[p.Protocol]; ok {
		return tp.Normalize(p)
	}
	// Tunnel fields only mean something for a tunnel profile.
	p.TunnelLocation = ""
	p.TunnelTransport = ""

	p.Host = strings.TrimSpace(p.Host)
	if p.Host == "" {
		return errors.New("host cannot be empty")
	}

	// Validate host (valid IP or hostname without shell injection characters)
	if net.ParseIP(p.Host) == nil && !hostRegex.MatchString(p.Host) {
		return fmt.Errorf("invalid host format: %s", p.Host)
	}

	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got: %d", p.Port)
	}

	if p.Name == "" {
		p.Name = fmt.Sprintf("%s-%s:%d", strings.ToUpper(p.Protocol), p.Host, p.Port)
	}

	switch p.Protocol {
	case ProtoHTTP, ProtoHTTPS:
		p.UDP = false // HTTP/HTTPS outbounds do not support UDP
		if p.Protocol == ProtoHTTPS {
			p.TLS = true
		}
	case ProtoShadowsocks:
		if p.Method == "" {
			p.Method = "aes-256-gcm"
		}
		if p.Password == "" {
			return errors.New("shadowsocks password cannot be empty")
		}
	case ProtoTrojan:
		if p.Password == "" {
			return errors.New("trojan password cannot be empty")
		}
		p.TLS = true
	case ProtoVLESS:
		if p.UUID == "" {
			return errors.New("vless uuid cannot be empty")
		}
		if p.Security == "" {
			p.Security = "none"
		}
	case ProtoVMess:
		if p.UUID == "" {
			return errors.New("vmess uuid cannot be empty")
		}
		if p.Security == "" {
			p.Security = "auto"
		}
	}

	return nil
}

// IsTunnel reports whether the dashboard runs a tunnel for this profile.
func (p *Proxy) IsTunnel() bool {
	_, ok := tunnelProtocols[p.Protocol]
	return ok
}

// TunnelInterface is the name of the network interface that carries this
// profile's tunnel, or "" for a profile that has no tunnel.
func (p *Proxy) TunnelInterface() string {
	tp, ok := tunnelProtocols[p.Protocol]
	if !ok {
		return ""
	}
	return tp.Interface(p.ID)
}

// Clone creates a deep copy of the proxy.
func (p *Proxy) Clone() *Proxy {
	cp := *p
	if p.LastTest != nil {
		res := *p.LastTest
		cp.LastTest = &res
	}
	return &cp
}
