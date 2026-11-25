package singbox

import (
	"encoding/json"
	"path/filepath"
	"sort"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/config"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/state"
)

// GenerateConfig produces sing-box v1.12+ JSON configuration matching strict zero-leak specifications.
func GenerateConfig(cfg *config.Config, st *state.State) ([]byte, error) {
	assignedDevices := st.GetAssignedDevices()
	allProxies := st.GetProxies()

	// Map proxies by ID for easy lookup
	proxyMap := make(map[string]*proxy.Proxy)
	for _, p := range allProxies {
		proxyMap[p.ID] = p
	}

	// Find unique proxies that are actively assigned
	assignedProxyIDs := make(map[string]bool)
	for _, d := range assignedDevices {
		if proxyMap[d.ProxyID] != nil {
			assignedProxyIDs[d.ProxyID] = true
		}
	}

	// 1. Inbounds
	excludeCIDRs := cfg.ExcludeCIDRs
	if len(excludeCIDRs) == 0 {
		excludeCIDRs = []string{"10.88.88.0/24", "10.10.10.0/24", "10.77.77.0/24", "192.168.0.0/16"}
	}

	inbounds := []interface{}{
		map[string]interface{}{
			"type":                  "tun",
			"tag":                   "tun-in",
			"interface_name":        "tun0",
			"address":               []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":                   1400,
			"auto_route":            true,
			"strict_route":          false,
			"stack":                 "mixed",
			"route_exclude_address": excludeCIDRs,
		},
		map[string]interface{}{
			"type":        "direct",
			"tag":         "dns-in",
			"listen":      "0.0.0.0",
			"listen_port": 53,
		},
	}

	// 2. DNS Servers
	containerGW := cfg.ContainerGW
	if containerGW == "" {
		containerGW = "10.10.10.1"
	}

	dnsServers := []interface{}{
		map[string]interface{}{
			"tag":         "dns-bootstrap",
			"type":        "udp",
			"server":      containerGW,
			"server_port": 53,
		},
		map[string]interface{}{
			"tag":         "dns-fakeip",
			"type":        "fakeip",
			"inet4_range": "198.18.0.0/15",
		},
	}

	// For each active proxy, add DoH server
	var sortedAssignedProxyIDs []string
	for pid := range assignedProxyIDs {
		sortedAssignedProxyIDs = append(sortedAssignedProxyIDs, pid)
	}
	sort.Strings(sortedAssignedProxyIDs)

	for _, pid := range sortedAssignedProxyIDs {
		dnsServers = append(dnsServers, map[string]interface{}{
			"tag":         "dns-doh-" + pid,
			"type":        "https",
			"server":      "1.1.1.1",
			"server_port": 443,
			"path":        "/dns-query",
			"detour":      "proxy-" + pid,
		})
	}

	// 3. DNS Rules
	dnsRules := []interface{}{
		map[string]interface{}{
			"query_type": []string{"AAAA", "HTTPS", "SVCB"},
			"action":     "reject",
		},
	}

	// Sort devices by IP for deterministic output
	sort.Slice(assignedDevices, func(i, j int) bool {
		return assignedDevices[i].IP < assignedDevices[j].IP
	})

	for _, d := range assignedDevices {
		p := proxyMap[d.ProxyID]
		if p == nil {
			continue
		}
		cidr := d.IP + "/32"
		dnsRules = append(dnsRules, map[string]interface{}{
			"source_ip_cidr": []string{cidr},
			"query_type":     []string{"A"},
			"action":         "route",
			"server":         "dns-fakeip",
		})
		dnsRules = append(dnsRules, map[string]interface{}{
			"source_ip_cidr": []string{cidr},
			"action":         "route",
			"server":         "dns-doh-" + p.ID,
		})
	}

	// Catch-all DNS reject rule (prevents leak to bootstrap server)
	dnsRules = append(dnsRules, map[string]interface{}{
		"action": "reject",
	})

	dnsConfig := map[string]interface{}{
		"servers":  dnsServers,
		"rules":    dnsRules,
		"final":    "dns-bootstrap",
		"strategy": "ipv4_only",
	}

	// 4. Outbounds
	var outbounds []interface{}
	for _, p := range allProxies {
		outbounds = append(outbounds, p.ToSingboxOutbound("proxy-"+p.ID))
	}
	outbounds = append(outbounds, map[string]interface{}{
		"type": "direct",
		"tag":  "direct",
	})
	outbounds = append(outbounds, map[string]interface{}{
		"type": "block",
		"tag":  "block",
	})

	// 5. Route Rules
	routeRules := []interface{}{
		map[string]interface{}{
			"action": "sniff",
		},
		map[string]interface{}{
			"protocol": "dns",
			"action":   "hijack-dns",
		},
		map[string]interface{}{
			"port":   53,
			"action": "hijack-dns",
		},
		map[string]interface{}{
			"ip_version": 6,
			"action":     "reject",
		},
	}

	for _, d := range assignedDevices {
		p := proxyMap[d.ProxyID]
		if p == nil {
			continue
		}
		cidr := d.IP + "/32"

		// If proxy does not have UDP, reject UDP to kill WebRTC STUN leaks and force QUIC->TCP fallback
		if !p.UDP || p.Protocol == proxy.ProtoHTTP || p.Protocol == proxy.ProtoHTTPS {
			routeRules = append(routeRules, map[string]interface{}{
				"source_ip_cidr": []string{cidr},
				"network":        "udp",
				"action":         "reject",
				"method":         "default",
				"no_drop":        true,
			})
		}

		routeRules = append(routeRules, map[string]interface{}{
			"source_ip_cidr": []string{cidr},
			"action":         "route",
			"outbound":       "proxy-" + p.ID,
		})
	}

	// Block LAN & private IP access from client routing
	routeRules = append(routeRules, map[string]interface{}{
		"ip_is_private": true,
		"action":        "reject",
	})

	// Fail-closed catch-all rule (never fallback to direct!)
	routeRules = append(routeRules, map[string]interface{}{
		"action": "reject",
	})

	routeConfig := map[string]interface{}{
		"auto_detect_interface":   true,
		"default_domain_resolver": "dns-bootstrap",
		"rules":                   routeRules,
	}

	// 6. Experimental Cache File
	experimentalConfig := map[string]interface{}{
		"cache_file": map[string]interface{}{
			"enabled":      true,
			"path":         filepath.Join(cfg.DataDir, "cache.db"),
			"store_fakeip": true,
		},
	}

	// Full sing-box JSON configuration
	fullConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"dns":          dnsConfig,
		"inbounds":     inbounds,
		"outbounds":    outbounds,
		"route":        routeConfig,
		"experimental": experimentalConfig,
	}

	return json.MarshalIndent(fullConfig, "", "  ")
}
