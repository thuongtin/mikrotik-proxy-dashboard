package mikrotik

import (
	"context"
	"fmt"
	"strings"
)

type addressListEntry struct {
	ID      string `json:".id"`
	List    string `json:"list"`
	Address string `json:"address"`
	Comment string `json:"comment"`
}

type ipv6FilterRule struct {
	ID            string `json:".id"`
	Chain         string `json:"chain"`
	SrcMacAddress string `json:"src-mac-address"`
	Action        string `json:"action"`
	RejectWith    string `json:"reject-with"`
	Comment       string `json:"comment"`
	Dynamic       string `json:"dynamic"`
	Packets       int64  `json:"packets,string"`
	Bytes         int64  `json:"bytes,string"`
}

type ipFilterRule struct {
	ID      string `json:".id"`
	Chain   string `json:"chain"`
	Action  string `json:"action"`
	Comment string `json:"comment"`
	Packets int64  `json:"packets,string"`
	Bytes   int64  `json:"bytes,string"`
}

type firewallConnection struct {
	ID         string `json:".id"`
	SrcAddress string `json:"src-address"`
	DstAddress string `json:"dst-address"`
	Protocol   string `json:"protocol"`
}

type ipv6Neighbor struct {
	ID         string `json:".id"`
	Address    string `json:"address"`
	MacAddress string `json:"mac-address"`
	Status     string `json:"status"`
}

// EnsureProxyAddressList adds device IP to PROXY_DEVICES address-list if missing.
func (c *Client) EnsureProxyAddressList(ctx context.Context, ip, mac string) error {
	var entries []addressListEntry
	err := c.Do(ctx, "GET", "/ip/firewall/address-list", nil, &entries)
	if err != nil {
		return fmt.Errorf("failed to query address-list: %w", err)
	}

	for _, e := range entries {
		if e.List == "PROXY_DEVICES" && e.Address == ip {
			return nil // Already present
		}
	}

	payload := map[string]interface{}{
		"list":    "PROXY_DEVICES",
		"address": ip,
		"comment": fmt.Sprintf("proxy-dash:%s", strings.ToLower(mac)),
	}

	return c.Do(ctx, "PUT", "/ip/firewall/address-list", payload, nil)
}

// RemoveProxyAddressList removes device IP from PROXY_DEVICES address-list.
func (c *Client) RemoveProxyAddressList(ctx context.Context, ip string) error {
	var entries []addressListEntry
	err := c.Do(ctx, "GET", "/ip/firewall/address-list", nil, &entries)
	if err != nil {
		return fmt.Errorf("failed to query address-list: %w", err)
	}

	for _, e := range entries {
		if e.List == "PROXY_DEVICES" && e.Address == ip {
			return c.Do(ctx, "DELETE", fmt.Sprintf("/ip/firewall/address-list/%s", e.ID), nil, nil)
		}
	}
	return nil
}

// EnsureIPv6BlockRules creates top-priority forward and input IPv6 drop rules for device MAC.
func (c *Client) EnsureIPv6BlockRules(ctx context.Context, mac string) error {
	cleanMac := strings.ToLower(mac)
	if cleanMac == "" {
		return nil
	}

	var rules []ipv6FilterRule
	if err := c.Do(ctx, "GET", "/ipv6/firewall/filter", nil, &rules); err != nil {
		return fmt.Errorf("failed to query IPv6 firewall filter rules: %w", err)
	}

	fwdComment := fmt.Sprintf("proxy-dash-ipv6-fwd:%s", cleanMac)
	inComment := fmt.Sprintf("proxy-dash-ipv6-in:%s", cleanMac)

	// Find the first regular (non-dynamic, non-proxy-dash) rule to place our drop rules before
	var firstRegularRuleID string
	for _, r := range rules {
		if r.Dynamic != "true" && !strings.HasPrefix(r.Comment, "proxy-dash-ipv6-") {
			firstRegularRuleID = r.ID
			break
		}
	}

	hasFwd := false
	hasIn := false
	for _, r := range rules {
		if r.Comment == fwdComment {
			hasFwd = true
		}
		if r.Comment == inComment {
			hasIn = true
		}
	}

	rulesAdded := false

	if !hasFwd {
		payload := map[string]interface{}{
			"chain":           "forward",
			"src-mac-address": cleanMac,
			"action":          "reject",
			"reject-with":     "icmp-admin-prohibited",
			"comment":         fwdComment,
		}
		if firstRegularRuleID != "" {
			payload["place-before"] = firstRegularRuleID
		}
		if err := c.Do(ctx, "POST", "/ipv6/firewall/filter/add", payload, nil); err != nil {
			return fmt.Errorf("failed to add IPv6 forward rule for %s: %w", cleanMac, err)
		}
		rulesAdded = true
	}

	if !hasIn {
		payload := map[string]interface{}{
			"chain":           "input",
			"src-mac-address": cleanMac,
			"action":          "reject",
			"reject-with":     "icmp-admin-prohibited",
			"comment":         inComment,
		}
		if firstRegularRuleID != "" {
			payload["place-before"] = firstRegularRuleID
		}
		if err := c.Do(ctx, "POST", "/ipv6/firewall/filter/add", payload, nil); err != nil {
			return fmt.Errorf("failed to add IPv6 input rule for %s: %w", cleanMac, err)
		}
		rulesAdded = true
	}

	// If rules were added, re-fetch rules from RouterOS to inspect actual order
	if rulesAdded {
		if err := c.Do(ctx, "GET", "/ipv6/firewall/filter", nil, &rules); err != nil {
			return fmt.Errorf("failed to refresh IPv6 firewall filter rules: %w", err)
		}
	}

	// Locate first regular rule position in the current list
	firstRegularIndex := -1
	firstRegularRuleID = ""
	for i, r := range rules {
		if r.Dynamic != "true" && !strings.HasPrefix(r.Comment, "proxy-dash-ipv6-") {
			firstRegularIndex = i
			firstRegularRuleID = r.ID
			break
		}
	}

	// If any proxy-dash-ipv6-* rule appears AFTER firstRegularRuleID, move it above firstRegularRuleID
	if firstRegularIndex != -1 && firstRegularRuleID != "" {
		for i, r := range rules {
			if strings.HasPrefix(r.Comment, "proxy-dash-ipv6-") && i > firstRegularIndex {
				movePayload := map[string]string{
					"numbers":     r.ID,
					"destination": firstRegularRuleID,
				}
				if err := c.Do(ctx, "POST", "/ipv6/firewall/filter/move", movePayload, nil); err != nil {
					return fmt.Errorf("failed to move IPv6 rule %s (%s) before %s: %w", r.ID, r.Comment, firstRegularRuleID, err)
				}
			}
		}
	}

	return nil
}

// RemoveIPv6BlockRules deletes IPv6 reject rules for device MAC.
func (c *Client) RemoveIPv6BlockRules(ctx context.Context, mac string) error {
	cleanMac := strings.ToLower(mac)
	if cleanMac == "" {
		return nil
	}

	var rules []ipv6FilterRule
	if err := c.Do(ctx, "GET", "/ipv6/firewall/filter", nil, &rules); err != nil {
		return fmt.Errorf("failed to query IPv6 firewall filter rules: %w", err)
	}

	fwdComment := fmt.Sprintf("proxy-dash-ipv6-fwd:%s", cleanMac)
	inComment := fmt.Sprintf("proxy-dash-ipv6-in:%s", cleanMac)

	for _, r := range rules {
		if r.Comment == fwdComment || r.Comment == inComment {
			if err := c.Do(ctx, "DELETE", fmt.Sprintf("/ipv6/firewall/filter/%s", r.ID), nil, nil); err != nil {
				return fmt.Errorf("failed to delete IPv6 rule %s (%s): %w", r.ID, r.Comment, err)
			}
		}
	}
	return nil
}

// FlushDeviceConnections terminates active IPv4 and IPv6 conntrack entries for an IP and MAC.
func (c *Client) FlushDeviceConnections(ctx context.Context, ip, mac string) error {
	// 1. Flush IPv4 conntrack
	var v4Conns []firewallConnection
	if err := c.Do(ctx, "GET", "/ip/firewall/connection", nil, &v4Conns); err == nil {
		prefix := ip + ":"
		for _, conn := range v4Conns {
			if conn.SrcAddress == ip || strings.HasPrefix(conn.SrcAddress, prefix) {
				_ = c.Do(ctx, "DELETE", fmt.Sprintf("/ip/firewall/connection/%s", conn.ID), nil, nil)
			}
		}
	}

	// 2. Discover IPv6 addresses from neighbor table and flush IPv6 conntrack
	cleanMac := strings.ToLower(mac)
	if cleanMac != "" {
		var neighbors []ipv6Neighbor
		_ = c.Do(ctx, "GET", "/ipv6/neighbor", nil, &neighbors)

		var v6Addrs []string
		for _, n := range neighbors {
			if strings.ToLower(n.MacAddress) == cleanMac {
				v6Addrs = append(v6Addrs, n.Address)
			}
		}

		if len(v6Addrs) > 0 {
			var v6Conns []firewallConnection
			if err := c.Do(ctx, "GET", "/ipv6/firewall/connection", nil, &v6Conns); err == nil {
				for _, conn := range v6Conns {
					for _, v6 := range v6Addrs {
						if conn.SrcAddress == v6 || strings.HasPrefix(conn.SrcAddress, "["+v6+"]") || strings.HasPrefix(conn.SrcAddress, v6+":") {
							_ = c.Do(ctx, "DELETE", fmt.Sprintf("/ipv6/firewall/connection/%s", conn.ID), nil, nil)
							break
						}
					}
				}
			}
		}
	}

	return nil
}

// FlushAllProxyConnections flushes active connections for all given IPs.
func (c *Client) FlushAllProxyConnections(ctx context.Context, ips []string) error {
	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}

	var v4Conns []firewallConnection
	if err := c.Do(ctx, "GET", "/ip/firewall/connection", nil, &v4Conns); err == nil {
		for _, conn := range v4Conns {
			host := conn.SrcAddress
			if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
				host = host[:colonIdx]
			}
			if ipSet[host] {
				_ = c.Do(ctx, "DELETE", fmt.Sprintf("/ip/firewall/connection/%s", conn.ID), nil, nil)
			}
		}
	}

	return nil
}
