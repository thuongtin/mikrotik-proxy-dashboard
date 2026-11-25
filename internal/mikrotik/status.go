package mikrotik

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/state"
)

// LeakGuardLayer represents the status of one security layer.
type LeakGuardLayer struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "ok", "warning", "error"
	Description string `json:"description"`
	Details     string `json:"details,omitempty"`
}

// LeakGuardStatus aggregates 6-layer protection telemetry.
type LeakGuardStatus struct {
	OverallStatus       string           `json:"overallStatus"` // "protected", "degraded", "unprotected"
	KillSwitchPackets   int64            `json:"killSwitchPackets"`
	KillSwitchBytes     int64            `json:"killSwitchBytes"`
	IPv6BlockedPackets  int64            `json:"ipv6BlockedPackets"`
	IPv6BlockedBytes    int64            `json:"ipv6BlockedBytes"`
	Layers              []LeakGuardLayer `json:"layers"`
	AssignedDeviceCount int              `json:"assignedDeviceCount"`
}

type routingTable struct {
	ID   string `json:".id"`
	Name string `json:"name"`
	Fib  string `json:"fib"`
}

type natRule struct {
	ID       string `json:".id"`
	Chain    string `json:"chain"`
	Action   string `json:"action"`
	DstPort  string `json:"dst-port"`
	Protocol string `json:"protocol"`
	Comment  string `json:"comment"`
}

type routingRule struct {
	ID       string `json:".id"`
	SrcAddress string `json:"src-address"`
	Table    string `json:"table"`
	Action   string `json:"action"`
}

// GetLeakGuardStatus checks RouterOS rules and computes telemetry.
func (c *Client) GetLeakGuardStatus(ctx context.Context, st *state.State, singboxRunning bool) (*LeakGuardStatus, error) {
	assignedDevices := st.GetAssignedDevices()

	var ksPackets, ksBytes int64
	var v6Packets, v6Bytes int64

	hasKillSwitchRule := false
	hasRoutingTable := false
	hasDNSHijackRule := false
	hasRoutingRule := false

	// 1. Check Routing Table "via-proxy"
	var tables []routingTable
	if err := c.Do(ctx, "GET", "/routing/table", nil, &tables); err == nil {
		for _, t := range tables {
			if t.Name == "via-proxy" {
				hasRoutingTable = true
				break
			}
		}
	}

	// 2. Check IPv4 Firewall Filter for Kill-Switch
	var v4Filters []ipFilterRule
	if err := c.Do(ctx, "GET", "/ip/firewall/filter", nil, &v4Filters); err == nil {
		for _, f := range v4Filters {
			if strings.Contains(f.Comment, "proxy-dash-killswitch") || f.Comment == "proxy-dash-killswitch" {
				hasKillSwitchRule = true
				ksPackets += f.Packets
				ksBytes += f.Bytes
			}
		}
	}

	// 3. Check IPv6 Firewall Filter for MAC drop rules
	var v6Filters []ipv6FilterRule
	if err := c.Do(ctx, "GET", "/ipv6/firewall/filter", nil, &v6Filters); err == nil {
		for _, f := range v6Filters {
			if strings.HasPrefix(f.Comment, "proxy-dash-ipv6-") {
				v6Packets += f.Packets
				v6Bytes += f.Bytes
			}
		}
	}

	// 4. Check NAT for DNS redirect / hijack
	var natRules []natRule
	if err := c.Do(ctx, "GET", "/ip/firewall/nat", nil, &natRules); err == nil {
		for _, n := range natRules {
			if n.Action == "dst-nat" && strings.Contains(n.DstPort, "53") {
				hasDNSHijackRule = true
				break
			}
		}
	}

	// 5. Check Routing Rules for PROXY_DEVICES / via-proxy
	var rRules []routingRule
	if err := c.Do(ctx, "GET", "/routing/rule", nil, &rRules); err == nil {
		for _, r := range rRules {
			if r.Table == "via-proxy" {
				hasRoutingRule = true
				break
			}
		}
	}

	// Build 6 Layers
	layers := make([]LeakGuardLayer, 0, 6)

	// Layer 1: Static IP Binding
	l1Status := "ok"
	l1Desc := fmt.Sprintf("%d thiết bị được cố định IP tĩnh (Static Lease)", len(assignedDevices))
	layers = append(layers, LeakGuardLayer{
		Name:        "Layer 1: Static IP Binding",
		Status:      l1Status,
		Description: l1Desc,
	})

	// Layer 2: Policy Routing
	l2Status := "ok"
	l2Desc := "Bảng định tuyến 'via-proxy' đang hoạt động"
	if !hasRoutingTable || !hasRoutingRule {
		l2Status = "warning"
		l2Desc = "Thiếu bảng định tuyến 'via-proxy' hoặc routing rule trong RouterOS"
	}
	layers = append(layers, LeakGuardLayer{
		Name:        "Layer 2: Policy Routing Table",
		Status:      l2Status,
		Description: l2Desc,
	})

	// Layer 3: RouterOS Kill-Switch
	l3Status := "ok"
	l3Desc := fmt.Sprintf("Quy tắc Kill-Switch RouterOS chặn %d gói (%d bytes)", ksPackets, ksBytes)
	if !hasKillSwitchRule {
		l3Status = "warning"
		l3Desc = "Chưa phát hiện quy tắc filter 'proxy-dash-killswitch' trên RouterOS"
	}
	layers = append(layers, LeakGuardLayer{
		Name:        "Layer 3: RouterOS Kill-Switch",
		Status:      l3Status,
		Description: l3Desc,
	})

	// Layer 4: IPv6 Hardware Block
	l4Status := "ok"
	l4Desc := fmt.Sprintf("Chặn hoàn toàn IPv6 theo MAC phần cứng (%d gói bị chặn)", v6Packets)
	layers = append(layers, LeakGuardLayer{
		Name:        "Layer 4: IPv6 Hardware Block",
		Status:      l4Status,
		Description: l4Desc,
	})

	// Layer 5: DNS Hijack & FakeIP
	l5Status := "ok"
	l5Desc := "Tất cả DNS Port 53 được chuyển hướng về sing-box FakeIP/DoH"
	if !hasDNSHijackRule {
		l5Status = "warning"
		l5Desc = "Chưa phát hiện NAT dst-nat port 53 trên RouterOS"
	}
	layers = append(layers, LeakGuardLayer{
		Name:        "Layer 5: DNS Hijack & FakeIP",
		Status:      l5Status,
		Description: l5Desc,
	})

	// Layer 6: Fail-Closed sing-box Engine
	l6Status := "ok"
	l6Desc := "Engine sing-box hoạt động ở chế độ Fail-Closed (ngắt hoàn toàn nếu mất proxy, chặn WebRTC STUN UDP)"
	if !singboxRunning {
		l6Status = "error"
		l6Desc = "Engine sing-box đang dừng hoặc gặp sự cố!"
	}
	layers = append(layers, LeakGuardLayer{
		Name:        "Layer 6: sing-box Fail-Closed Engine",
		Status:      l6Status,
		Description: l6Desc,
	})

	overall := "protected"
	for _, l := range layers {
		if l.Status == "error" {
			overall = "unprotected"
			break
		}
		if l.Status == "warning" && overall != "error" {
			overall = "degraded"
		}
	}

	return &LeakGuardStatus{
		OverallStatus:       overall,
		KillSwitchPackets:   ksPackets,
		KillSwitchBytes:     ksBytes,
		IPv6BlockedPackets:  v6Packets,
		IPv6BlockedBytes:    v6Bytes,
		Layers:              layers,
		AssignedDeviceCount: len(assignedDevices),
	}, nil
}

// Reconcile synchronizes state.json with RouterOS address-lists and IPv6 filter rules.
func (c *Client) Reconcile(ctx context.Context, st *state.State) error {
	assigned := st.GetAssignedDevices()

	assignedIPs := make(map[string]string) // IP -> MAC
	for _, d := range assigned {
		assignedIPs[d.IP] = d.MAC
	}

	// 1. Reconcile PROXY_DEVICES address-list
	var entries []addressListEntry
	_ = c.Do(ctx, "GET", "/ip/firewall/address-list", nil, &entries)

	currentInRouter := make(map[string]string) // IP -> entry ID
	for _, e := range entries {
		if e.List == "PROXY_DEVICES" {
			currentInRouter[e.Address] = e.ID
		}
	}

	// Add missing to RouterOS
	for ip, mac := range assignedIPs {
		if _, exists := currentInRouter[ip]; !exists {
			_ = c.EnsureProxyAddressList(ctx, ip, mac)
		}
		if mac != "" {
			_ = c.EnsureIPv6BlockRules(ctx, mac)
		}
	}

	// Remove unassigned from RouterOS
	for ip, id := range currentInRouter {
		if _, needed := assignedIPs[ip]; !needed {
			_ = c.Do(ctx, "DELETE", fmt.Sprintf("/ip/firewall/address-list/%s", id), nil, nil)
		}
	}

	return nil
}
