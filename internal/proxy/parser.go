package proxy

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GenerateID produces a random 12-char hex string.
func GenerateID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ParseURIs parses multiple newline-separated URIs or host:port entries.
func ParseURIs(input, defaultProto string) ([]*Proxy, []error) {
	var proxies []*Proxy
	var errs []error

	scanner := bufio.NewScanner(strings.NewReader(input))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		p, err := ParseURI(line, defaultProto)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", lineNum, err))
		} else {
			proxies = append(proxies, p)
		}
	}

	return proxies, errs
}

// ParseURI parses a single proxy URI or raw host:port string.
func ParseURI(raw, defaultProto string) (*Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty URI")
	}

	if defaultProto == "" {
		defaultProto = ProtoHTTP
	}

	switch {
	case strings.HasPrefix(raw, "vmess://"):
		return parseVMess(raw)
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(raw, "ss://"):
		return parseShadowsocks(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojan(raw)
	case strings.HasPrefix(raw, "socks5://") || strings.HasPrefix(raw, "socks://"):
		return parseStandardURL(raw, ProtoSocks5)
	case strings.HasPrefix(raw, "https://"):
		return parseStandardURL(raw, ProtoHTTPS)
	case strings.HasPrefix(raw, "http://"):
		return parseStandardURL(raw, ProtoHTTP)
	default:
		// Try parsing raw host:port or host:port:user:pass
		return parseRawHostPort(raw, defaultProto)
	}
}

func parseStandardURL(raw, proto string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		if proto == ProtoHTTPS {
			port = 443
		} else if proto == ProtoHTTP {
			port = 80
		} else if proto == ProtoSocks5 {
			port = 1080
		} else {
			return nil, fmt.Errorf("missing or invalid port: %w", err)
		}
	}

	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("%s-%s:%d", strings.ToUpper(proto), u.Hostname(), port)
	}

	// SOCKS5 query param ?udp=1
	q := u.Query()
	udp := q.Get("udp") == "1" || q.Get("udp") == "true"

	p := &Proxy{
		ID:        GenerateID(),
		Name:      name,
		Protocol:  proto,
		Host:      u.Hostname(),
		Port:      port,
		Username:  username,
		Password:  password,
		UDP:       udp,
		TLS:       proto == ProtoHTTPS,
		SNI:       u.Hostname(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func parseShadowsocks(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid shadowsocks URL: %w", err)
	}

	name := u.Fragment
	var method, password, host string
	var port int

	if u.User != nil {
		// SIP002 format: ss://BASE64(method:password)@host:port
		userStr := u.User.Username()
		decodedUser, err := decodeBase64Safe(userStr)
		if err == nil && strings.Contains(decodedUser, ":") {
			parts := strings.SplitN(decodedUser, ":", 2)
			method = parts[0]
			password = parts[1]
		} else {
			method = userStr
			password, _ = u.User.Password()
		}

		host = u.Hostname()
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port in ss URL: %w", err)
		}
	} else {
		// Legacy format: ss://BASE64(method:password@host:port)
		encoded := u.Host
		decoded, err := decodeBase64Safe(encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ss URL: %w", err)
		}

		atParts := strings.Split(decoded, "@")
		if len(atParts) != 2 {
			return nil, errors.New("invalid legacy shadowsocks format")
		}

		userParts := strings.SplitN(atParts[0], ":", 2)
		if len(userParts) != 2 {
			return nil, errors.New("invalid method/password in ss URL")
		}
		method = userParts[0]
		password = userParts[1]

		hostPort := atParts[1]
		colonIdx := strings.LastIndex(hostPort, ":")
		if colonIdx == -1 {
			return nil, errors.New("missing port in ss URL")
		}
		host = hostPort[:colonIdx]
		port, err = strconv.Atoi(hostPort[colonIdx+1:])
		if err != nil {
			return nil, fmt.Errorf("invalid port in ss URL: %w", err)
		}
	}

	if name == "" {
		name = fmt.Sprintf("SS-%s:%d", host, port)
	}

	q := u.Query()
	udp := q.Get("udp") == "1" || q.Get("udp") == "true"

	p := &Proxy{
		ID:        GenerateID(),
		Name:      name,
		Protocol:  ProtoShadowsocks,
		Host:      host,
		Port:      port,
		Method:    method,
		Password:  password,
		UDP:       udp,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func parseTrojan(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid trojan URL: %w", err)
	}

	password := ""
	if u.User != nil {
		password = u.User.Username()
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		port = 443
	}

	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		sni = u.Hostname()
	}

	insecure := q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" || q.Get("allowInsecure") == "true"
	transport := q.Get("type")
	if transport == "" {
		transport = "tcp"
	}
	wsPath := q.Get("path")
	wsHost := q.Get("host")
	grpcServiceName := q.Get("serviceName")
	udp := q.Get("udp") == "1" || q.Get("udp") == "true"

	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("TROJAN-%s:%d", u.Hostname(), port)
	}

	p := &Proxy{
		ID:              GenerateID(),
		Name:            name,
		Protocol:        ProtoTrojan,
		Host:            u.Hostname(),
		Port:            port,
		Password:        password,
		TLS:             true,
		SNI:             sni,
		Insecure:        insecure,
		Transport:       transport,
		WSPath:          wsPath,
		WSHost:          wsHost,
		GRPCServiceName: grpcServiceName,
		UDP:             udp,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func parseVLESS(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid vless URL: %w", err)
	}

	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		port = 443
	}

	q := u.Query()
	security := q.Get("security")
	if security == "" {
		security = "none"
	}

	sni := q.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}

	flow := q.Get("flow")
	fingerprint := q.Get("fp")
	publicKey := q.Get("pbk")
	shortID := q.Get("sid")
	insecure := q.Get("allowInsecure") == "1" || q.Get("insecure") == "1"

	transport := q.Get("type")
	if transport == "" {
		transport = "tcp"
	}
	wsPath := q.Get("path")
	wsHost := q.Get("host")
	grpcServiceName := q.Get("serviceName")
	udp := q.Get("udp") == "1" || q.Get("udp") == "true"

	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("VLESS-%s:%d", u.Hostname(), port)
	}

	p := &Proxy{
		ID:              GenerateID(),
		Name:            name,
		Protocol:        ProtoVLESS,
		Host:            u.Hostname(),
		Port:            port,
		UUID:            uuid,
		Security:        security,
		Flow:            flow,
		TLS:             security == "tls" || security == "reality",
		SNI:             sni,
		Fingerprint:     fingerprint,
		PublicKey:       publicKey,
		ShortID:         shortID,
		Insecure:        insecure,
		Transport:       transport,
		WSPath:          wsPath,
		WSHost:          wsHost,
		GRPCServiceName: grpcServiceName,
		UDP:             udp,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

type vmessJSON struct {
	V    interface{} `json:"v"`
	Ps   string      `json:"ps"`
	Add  string      `json:"add"`
	Port interface{} `json:"port"`
	ID   string      `json:"id"`
	Aid  interface{} `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	TLS  string      `json:"tls"`
	Sni  string      `json:"sni"`
	Udp  interface{} `json:"udp"`
}

func parseVMess(raw string) (*Proxy, error) {
	b64Data := strings.TrimPrefix(raw, "vmess://")
	decoded, err := decodeBase64Safe(b64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vmess base64: %w", err)
	}

	var vj vmessJSON
	if err := json.Unmarshal([]byte(decoded), &vj); err != nil {
		return nil, fmt.Errorf("invalid vmess JSON: %w", err)
	}

	var port int
	switch v := vj.Port.(type) {
	case float64:
		port = int(v)
	case string:
		port, _ = strconv.Atoi(v)
	}

	var alterID int
	switch v := vj.Aid.(type) {
	case float64:
		alterID = int(v)
	case string:
		alterID, _ = strconv.Atoi(v)
	}

	sni := vj.Sni
	if sni == "" {
		sni = vj.Host
	}
	if sni == "" {
		sni = vj.Add
	}

	name := vj.Ps
	if name == "" {
		name = fmt.Sprintf("VMESS-%s:%d", vj.Add, port)
	}

	isTLS := strings.EqualFold(vj.TLS, "tls") || strings.EqualFold(vj.TLS, "1")
	udp := vj.Udp == true || vj.Udp == "1" || vj.Udp == "true"

	transport := vj.Net
	if transport == "" {
		transport = "tcp"
	}

	p := &Proxy{
		ID:        GenerateID(),
		Name:      name,
		Protocol:  ProtoVMess,
		Host:      vj.Add,
		Port:      port,
		UUID:      vj.ID,
		AlterID:   alterID,
		Security:  vj.Scy,
		TLS:       isTLS,
		SNI:       sni,
		Transport: transport,
		WSPath:    vj.Path,
		WSHost:    vj.Host,
		UDP:       udp,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func parseRawHostPort(raw, defaultProto string) (*Proxy, error) {
	parts := strings.Split(raw, ":")
	if len(parts) < 2 {
		return nil, errors.New("expected host:port or host:port:user:pass")
	}

	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	var user, pass string
	if len(parts) >= 4 {
		user = parts[2]
		pass = parts[3]
	}

	p := &Proxy{
		ID:        GenerateID(),
		Name:      fmt.Sprintf("%s-%s:%d", strings.ToUpper(defaultProto), host, port),
		Protocol:  defaultProto,
		Host:      host,
		Port:      port,
		Username:  user,
		Password:  pass,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeBase64Safe(s string) (string, error) {
	s = strings.TrimSpace(s)
	// Try standard encoding
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(data), nil
	}
	// Try URL safe encoding
	if data, err := base64.URLEncoding.DecodeString(s); err == nil {
		return string(data), nil
	}
	// Try unpadded standard
	if data, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(data), nil
	}
	// Try unpadded URL safe
	if data, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(data), nil
	}
	return "", errors.New("failed base64 decoding")
}
