package mikrotik

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type addressListEntry struct {
	ID       string `json:".id"`
	List     string `json:"list"`
	Address  string `json:"address"`
	Comment  string `json:"comment"`
	Disabled string `json:"disabled"`
}

type ipv6FilterRule struct {
	ID            string `json:".id"`
	Chain         string `json:"chain"`
	SrcMacAddress string `json:"src-mac-address"`
	Action        string `json:"action"`
	RejectWith    string `json:"reject-with"`
	Comment       string `json:"comment"`
	Dynamic       string `json:"dynamic"`
	Disabled      string `json:"disabled"`
	Invalid       string `json:"invalid"`
	// Matchers that narrow a rule to traffic a kill-switch does not care about.
	ConnectionState    string `json:"connection-state"`
	ConnectionNatState string `json:"connection-nat-state"`
	IPsecPolicy        string `json:"ipsec-policy"`
	Packets            int64  `json:"packets,string"`
	Bytes              int64  `json:"bytes,string"`
}

type ipFilterRule struct {
	ID                 string `json:".id"`
	Chain              string `json:"chain"`
	Action             string `json:"action"`
	Comment            string `json:"comment"`
	Disabled           string `json:"disabled"`
	Dynamic            string `json:"dynamic"`
	Invalid            string `json:"invalid"`
	SrcAddressList     string `json:"src-address-list"`
	OutInterface       string `json:"out-interface"`
	OutInterfaceList   string `json:"out-interface-list"`
	ConnectionState    string `json:"connection-state"`
	ConnectionNatState string `json:"connection-nat-state"`
	IPsecPolicy        string `json:"ipsec-policy"`
	Packets            int64  `json:"packets,string"`
	Bytes              int64  `json:"bytes,string"`
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

// EnsureProxyAddressList makes sure an enabled PROXY_DEVICES entry exists for
// the device IP. A disabled entry does not route the device, so it is switched
// back on instead of being taken as present.
func (c *Client) EnsureProxyAddressList(ctx context.Context, ip, mac string) error {
	var entries []addressListEntry
	err := c.Do(ctx, "GET", "/ip/firewall/address-list", nil, &entries)
	if err != nil {
		return fmt.Errorf("failed to query address-list: %w", err)
	}

	disabledID := ""
	for _, e := range entries {
		if e.List != proxyAddressList || e.Address != ip {
			continue
		}
		if !isTrue(e.Disabled) {
			return nil // Already present and active
		}
		if disabledID == "" {
			disabledID = e.ID
		}
	}

	if disabledID != "" {
		err := c.Do(ctx, "PATCH", "/ip/firewall/address-list/"+disabledID, map[string]string{"disabled": "false"}, nil)
		if err == nil {
			return nil
		}
		if !IsNotFound(err) {
			return fmt.Errorf("failed to enable address-list entry %s for %s: %w", disabledID, ip, err)
		}
		// The entry vanished in the meantime: add a fresh one below.
	}

	payload := map[string]interface{}{
		"list":    proxyAddressList,
		"address": ip,
		"comment": fmt.Sprintf("proxy-dash:%s", strings.ToLower(mac)),
	}

	return c.Do(ctx, "PUT", "/ip/firewall/address-list", payload, nil)
}

// RemoveProxyAddressList removes every PROXY_DEVICES entry of the device IP.
// A leftover duplicate would keep the device on the proxy route after it was
// set back to direct.
func (c *Client) RemoveProxyAddressList(ctx context.Context, ip string) error {
	var entries []addressListEntry
	err := c.Do(ctx, "GET", "/ip/firewall/address-list", nil, &entries)
	if err != nil {
		return fmt.Errorf("failed to query address-list: %w", err)
	}

	var errs []error
	for _, e := range entries {
		if e.List != proxyAddressList || e.Address != ip {
			continue
		}
		err := c.Do(ctx, "DELETE", fmt.Sprintf("/ip/firewall/address-list/%s", e.ID), nil, nil)
		if err != nil && !IsNotFound(err) {
			errs = append(errs, fmt.Errorf("failed to delete address-list entry %s: %w", e.ID, err))
		}
	}
	return errors.Join(errs...)
}

// ipv6RuleBlocks reports whether r is one of our IPv6 rules that actually
// blocks mac in chain. A rule that was disabled, became invalid or was edited
// into something else does not count.
func ipv6RuleBlocks(r ipv6FilterRule, chain, mac string) bool {
	return r.Chain == chain && strings.EqualFold(r.SrcMacAddress, mac) &&
		(r.Action == "drop" || r.Action == "reject") &&
		!isTrue(r.Disabled) && !isTrue(r.Invalid)
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

	// Only a rule that still blocks counts. Copies that were disabled or
	// edited are replaced, then deleted so they cannot be mistaken for ours.
	hasFwd := false
	hasIn := false
	var brokenIDs []string
	for _, r := range rules {
		switch r.Comment {
		case fwdComment:
			if ipv6RuleBlocks(r, "forward", cleanMac) {
				hasFwd = true
			} else {
				brokenIDs = append(brokenIDs, r.ID)
			}
		case inComment:
			if ipv6RuleBlocks(r, "input", cleanMac) {
				hasIn = true
			} else {
				brokenIDs = append(brokenIDs, r.ID)
			}
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

	// The working rules are in place now, so the broken copies can go.
	for _, id := range brokenIDs {
		err := c.Do(ctx, "DELETE", fmt.Sprintf("/ipv6/firewall/filter/%s", id), nil, nil)
		if err != nil && !IsNotFound(err) {
			return fmt.Errorf("failed to delete inactive IPv6 rule %s: %w", id, err)
		}
	}

	// If rules changed, re-fetch rules from RouterOS to inspect actual order
	if rulesAdded || len(brokenIDs) > 0 {
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
// Every failure is reported: a connection that survives the flush can keep
// using its old (possibly direct) path.
func (c *Client) FlushDeviceConnections(ctx context.Context, ip, mac string) error {
	var errs []error

	// 1. Flush IPv4 conntrack
	var v4Conns []firewallConnection
	if err := c.Do(ctx, "GET", "/ip/firewall/connection", nil, &v4Conns); err != nil {
		errs = append(errs, fmt.Errorf("failed to list IPv4 connections: %w", err))
	} else {
		prefix := ip + ":"
		for _, conn := range v4Conns {
			if conn.SrcAddress == ip || strings.HasPrefix(conn.SrcAddress, prefix) {
				if err := c.deleteConnection(ctx, "/ip/firewall/connection/", conn.ID); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	// 2. Discover IPv6 addresses from neighbor table and flush IPv6 conntrack
	cleanMac := strings.ToLower(mac)
	if cleanMac != "" {
		var neighbors []ipv6Neighbor
		if err := c.Do(ctx, "GET", "/ipv6/neighbor", nil, &neighbors); err != nil {
			errs = append(errs, fmt.Errorf("failed to list IPv6 neighbors: %w", err))
		}

		var v6Addrs []string
		for _, n := range neighbors {
			if strings.ToLower(n.MacAddress) == cleanMac {
				v6Addrs = append(v6Addrs, n.Address)
			}
		}

		if len(v6Addrs) > 0 {
			var v6Conns []firewallConnection
			if err := c.Do(ctx, "GET", "/ipv6/firewall/connection", nil, &v6Conns); err != nil {
				errs = append(errs, fmt.Errorf("failed to list IPv6 connections: %w", err))
			} else {
				for _, conn := range v6Conns {
					for _, v6 := range v6Addrs {
						if conn.SrcAddress == v6 || strings.HasPrefix(conn.SrcAddress, "["+v6+"]") || strings.HasPrefix(conn.SrcAddress, v6+":") {
							if err := c.deleteConnection(ctx, "/ipv6/firewall/connection/", conn.ID); err != nil {
								errs = append(errs, err)
							}
							break
						}
					}
				}
			}
		}
	}

	return errors.Join(errs...)
}

// FlushAllProxyConnections flushes active IPv4 connections for all given IPs.
func (c *Client) FlushAllProxyConnections(ctx context.Context, ips []string) error {
	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}

	var v4Conns []firewallConnection
	if err := c.Do(ctx, "GET", "/ip/firewall/connection", nil, &v4Conns); err != nil {
		return fmt.Errorf("failed to list IPv4 connections: %w", err)
	}

	var errs []error
	for _, conn := range v4Conns {
		host := conn.SrcAddress
		if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
			host = host[:colonIdx]
		}
		if ipSet[host] {
			if err := c.deleteConnection(ctx, "/ip/firewall/connection/", conn.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

// deleteConnection removes one conntrack entry. An entry that expired between
// the listing and the delete is already gone, which is the wanted outcome.
func (c *Client) deleteConnection(ctx context.Context, basePath, id string) error {
	err := c.Do(ctx, "DELETE", basePath+id, nil, nil)
	if err == nil || IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("failed to delete connection %s: %w", id, err)
}
