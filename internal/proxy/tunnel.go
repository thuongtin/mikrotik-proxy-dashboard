package proxy

// TunnelProtocol describes a protocol whose traffic does not go to a proxy
// server but leaves through a network interface that the dashboard runs
// itself, such as a VPN. sing-box binds the profile's outbound to that
// interface. The core ships none; an edition registers its own at init time.
type TunnelProtocol struct {
	// Normalize validates a profile of this protocol and clears every field
	// that belongs to other protocols, so nothing stale reaches sing-box.
	Normalize func(p *Proxy) error
	// Interface names the tunnel interface for a profile ID. The name must be
	// stable across restarts and fit the 15-byte Linux limit.
	Interface func(id string) string
}

var tunnelProtocols = map[string]TunnelProtocol{}

// RegisterTunnelProtocol adds a tunnel protocol. It must be called from an
// init function: the registry is not safe for use while the server runs.
func RegisterTunnelProtocol(name string, tp TunnelProtocol) {
	if name == "" || tp.Normalize == nil || tp.Interface == nil {
		panic("proxy: incomplete tunnel protocol " + name)
	}
	if validProtocols[name] {
		panic("proxy: protocol registered twice: " + name)
	}
	validProtocols[name] = true
	tunnelProtocols[name] = tp
}
