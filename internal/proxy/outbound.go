package proxy

import "strings"

// ToSingboxOutbound converts the Proxy configuration to a sing-box outbound map.
func (p *Proxy) ToSingboxOutbound(tag string) map[string]interface{} {
	out := make(map[string]interface{})
	out["tag"] = tag

	switch p.Protocol {
	case ProtoHTTP, ProtoHTTPS:
		out["type"] = "http"
		out["server"] = p.Host
		out["server_port"] = p.Port
		if p.Username != "" {
			out["username"] = p.Username
		}
		if p.Password != "" {
			out["password"] = p.Password
		}
		if p.Protocol == ProtoHTTPS || p.TLS {
			tls := map[string]interface{}{
				"enabled": true,
			}
			if p.SNI != "" {
				tls["server_name"] = p.SNI
			} else {
				tls["server_name"] = p.Host
			}
			if p.Insecure {
				tls["insecure"] = true
			}
			out["tls"] = tls
		}

	case ProtoSocks5:
		out["type"] = "socks"
		out["server"] = p.Host
		out["server_port"] = p.Port
		if p.Username != "" {
			out["username"] = p.Username
		}
		if p.Password != "" {
			out["password"] = p.Password
		}

	case ProtoShadowsocks:
		out["type"] = "shadowsocks"
		out["server"] = p.Host
		out["server_port"] = p.Port
		out["method"] = p.Method
		out["password"] = p.Password

	case ProtoTrojan:
		out["type"] = "trojan"
		out["server"] = p.Host
		out["server_port"] = p.Port
		out["password"] = p.Password
		tls := map[string]interface{}{
			"enabled": true,
		}
		if p.SNI != "" {
			tls["server_name"] = p.SNI
		} else {
			tls["server_name"] = p.Host
		}
		if p.Insecure {
			tls["insecure"] = true
		}
		out["tls"] = tls
		applyTransport(out, p)

	case ProtoVLESS:
		out["type"] = "vless"
		out["server"] = p.Host
		out["server_port"] = p.Port
		out["uuid"] = p.UUID
		if p.Flow != "" {
			out["flow"] = p.Flow
		}

		if p.Security == "reality" {
			tls := map[string]interface{}{
				"enabled": true,
			}
			if p.SNI != "" {
				tls["server_name"] = p.SNI
			} else {
				tls["server_name"] = p.Host
			}
			if p.Insecure {
				tls["insecure"] = true
			}
			utls := map[string]interface{}{
				"enabled": true,
			}
			if p.Fingerprint != "" {
				utls["fingerprint"] = p.Fingerprint
			} else {
				utls["fingerprint"] = "chrome"
			}
			tls["utls"] = utls

			reality := map[string]interface{}{
				"enabled": true,
			}
			if p.PublicKey != "" {
				reality["public_key"] = p.PublicKey
			}
			if p.ShortID != "" {
				reality["short_id"] = p.ShortID
			}
			tls["reality"] = reality
			out["tls"] = tls
		} else if p.Security == "tls" || p.TLS {
			tls := map[string]interface{}{
				"enabled": true,
			}
			if p.SNI != "" {
				tls["server_name"] = p.SNI
			} else {
				tls["server_name"] = p.Host
			}
			if p.Insecure {
				tls["insecure"] = true
			}
			if p.Fingerprint != "" {
				tls["utls"] = map[string]interface{}{
					"enabled":     true,
					"fingerprint": p.Fingerprint,
				}
			}
			out["tls"] = tls
		}
		applyTransport(out, p)

	case ProtoVMess:
		out["type"] = "vmess"
		out["server"] = p.Host
		out["server_port"] = p.Port
		out["uuid"] = p.UUID
		out["alter_id"] = p.AlterID
		if p.Security != "" {
			out["security"] = p.Security
		} else {
			out["security"] = "auto"
		}
		if p.TLS {
			tls := map[string]interface{}{
				"enabled": true,
			}
			if p.SNI != "" {
				tls["server_name"] = p.SNI
			} else {
				tls["server_name"] = p.Host
			}
			if p.Insecure {
				tls["insecure"] = true
			}
			out["tls"] = tls
		}
		applyTransport(out, p)
	}

	return out
}

func applyTransport(out map[string]interface{}, p *Proxy) {
	trans := strings.ToLower(p.Transport)
	if trans == "ws" {
		ws := map[string]interface{}{
			"type": "ws",
		}
		if p.WSPath != "" {
			ws["path"] = p.WSPath
		}
		if p.WSHost != "" {
			ws["headers"] = map[string]string{
				"Host": p.WSHost,
			}
		}
		out["transport"] = ws
	} else if trans == "grpc" {
		grpc := map[string]interface{}{
			"type": "grpc",
		}
		if p.GRPCServiceName != "" {
			grpc["service_name"] = p.GRPCServiceName
		}
		out["transport"] = grpc
	}
}
