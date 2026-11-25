package mikrotik

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/state"
)

// Device represents a discovered or configured LAN host.
type Device struct {
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	Hostname   string `json:"hostname,omitempty"`
	Comment    string `json:"comment,omitempty"`
	DHCPStatus string `json:"dhcpStatus,omitempty"`
	Dynamic    bool   `json:"dynamic"`
	Online     bool   `json:"online"`
	Nickname   string `json:"nickname,omitempty"`
	ProxyID    string `json:"proxyId,omitempty"`
	Assigned   bool   `json:"assigned"`
}

type dhcpLease struct {
	ID        string `json:".id"`
	Address   string `json:"address"`
	MAC       string `json:"mac-address"`
	HostName  string `json:"host-name"`
	Comment   string `json:"comment"`
	Status    string `json:"status"`
	Dynamic   string `json:"dynamic"`
	Disabled  string `json:"disabled"`
}

type arpEntry struct {
	ID        string `json:".id"`
	Address   string `json:"address"`
	MAC       string `json:"mac-address"`
	Interface string `json:"interface"`
	Complete  string `json:"complete"`
	Dynamic   string `json:"dynamic"`
}

// GetDevices retrieves and merges DHCP leases and ARP entries for LAN CIDR.
func (c *Client) GetDevices(ctx context.Context, lanCIDR string, st *state.State) ([]*Device, error) {
	_, ipNet, err := net.ParseCIDR(lanCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid LAN CIDR %s: %w", lanCIDR, err)
	}

	// 1. Fetch DHCP leases
	var leases []dhcpLease
	_ = c.Do(ctx, "GET", "/ip/dhcp-server/lease", nil, &leases)

	// 2. Fetch ARP entries
	var arpEntries []arpEntry
	_ = c.Do(ctx, "GET", "/ip/arp", nil, &arpEntries)

	deviceMap := make(map[string]*Device)

	// Process DHCP leases
	for _, l := range leases {
		ip := net.ParseIP(l.Address)
		if ip == nil || !ipNet.Contains(ip) {
			continue
		}
		// Skip router gateway IP if ending in .1
		if strings.HasSuffix(l.Address, ".1") {
			continue
		}

		mac := strings.ToLower(l.MAC)
		isDynamic := l.Dynamic == "true"
		isOnline := l.Status == "bound"

		deviceMap[l.Address] = &Device{
			IP:         l.Address,
			MAC:        mac,
			Hostname:   l.HostName,
			Comment:    l.Comment,
			DHCPStatus: l.Status,
			Dynamic:    isDynamic,
			Online:     isOnline,
		}
	}

	// Merge ARP entries
	for _, a := range arpEntries {
		ip := net.ParseIP(a.Address)
		if ip == nil || !ipNet.Contains(ip) {
			continue
		}
		if strings.HasSuffix(a.Address, ".1") {
			continue
		}

		mac := strings.ToLower(a.MAC)
		isOnline := a.Complete == "true"

		if dev, exists := deviceMap[a.Address]; exists {
			if dev.MAC == "" {
				dev.MAC = mac
			}
			if isOnline {
				dev.Online = true
			}
		} else {
			deviceMap[a.Address] = &Device{
				IP:      a.Address,
				MAC:     mac,
				Dynamic: a.Dynamic == "true",
				Online:  isOnline,
			}
		}
	}

	// Merge persistent state
	persisted := st.GetAllDevices()
	for ipStr, cfg := range persisted {
		if dev, exists := deviceMap[ipStr]; exists {
			dev.Nickname = cfg.Nickname
			dev.ProxyID = cfg.ProxyID
			dev.Assigned = cfg.ProxyID != ""
			if dev.MAC == "" && cfg.MAC != "" {
				dev.MAC = strings.ToLower(cfg.MAC)
			}
		} else {
			// Device in state but not currently in DHCP/ARP table
			deviceMap[ipStr] = &Device{
				IP:       ipStr,
				MAC:      strings.ToLower(cfg.MAC),
				Nickname: cfg.Nickname,
				ProxyID:  cfg.ProxyID,
				Assigned: cfg.ProxyID != "",
				Online:   false,
			}
		}
	}

	var res []*Device
	for _, dev := range deviceMap {
		res = append(res, dev)
	}

	SortDevices(res)

	return res, nil
}

// SortDevices sorts devices deterministically:
// 1. Assigned (true before false)
// 2. Online (true before false)
// 3. Numeric IPv4 order ascending (bytes.Compare(ipA.To4(), ipB.To4()), falling back to string compare)
func SortDevices(devs []*Device) {
	sort.Slice(devs, func(i, j int) bool {
		a, b := devs[i], devs[j]

		// 1. Assigned (true before false)
		if a.Assigned != b.Assigned {
			return a.Assigned && !b.Assigned
		}

		// 2. Online (true before false)
		if a.Online != b.Online {
			return a.Online && !b.Online
		}

		// 3. Numeric IPv4 ascending
		ipA := net.ParseIP(a.IP).To4()
		ipB := net.ParseIP(b.IP).To4()
		if ipA != nil && ipB != nil {
			cmp := bytes.Compare(ipA, ipB)
			if cmp != 0 {
				return cmp < 0
			}
		} else {
			if a.IP != b.IP {
				return a.IP < b.IP
			}
		}

		return a.MAC < b.MAC
	})
}

// EnsureStaticLease converts a dynamic DHCP lease to static so device IP never shifts.
func (c *Client) EnsureStaticLease(ctx context.Context, targetIP, targetMAC string) error {
	var leases []dhcpLease
	err := c.Do(ctx, "GET", "/ip/dhcp-server/lease", nil, &leases)
	if err != nil {
		return fmt.Errorf("failed to query DHCP leases: %w", err)
	}

	for _, l := range leases {
		if l.Address == targetIP {
			if l.Dynamic == "true" {
				// Call make-static
				payload := map[string]string{
					".id": l.ID,
				}
				if err := c.Do(ctx, "POST", "/ip/dhcp-server/lease/make-static", payload, nil); err != nil {
					return fmt.Errorf("failed to make lease static for %s: %w", targetIP, err)
				}
			}
			return nil
		}
	}

	// If no lease existed at all and targetMAC is provided, create static lease
	if targetMAC != "" {
		payload := map[string]interface{}{
			"address":     targetIP,
			"mac-address": targetMAC,
			"comment":     "proxy-dash:static-reservation",
		}
		_ = c.Do(ctx, "PUT", "/ip/dhcp-server/lease", payload, nil)
	}

	return nil
}
