package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/proxy"
)

// DeviceConfig holds persistent settings for a LAN device.
type DeviceConfig struct {
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	Nickname   string    `json:"nickname,omitempty"`
	ProxyID    string    `json:"proxyId,omitempty"` // Empty string means direct (no proxy)
	AssignedAt time.Time `json:"assignedAt,omitempty"`
}

// State represents persistent data.
type State struct {
	mu       sync.RWMutex
	filePath string
	Proxies  map[string]*proxy.Proxy  `json:"proxies"`
	Devices  map[string]*DeviceConfig `json:"devices"`
}

// Load loads or creates persistent state from dataDir.
func Load(dataDir string) (*State, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	path := filepath.Join(dataDir, "state.json")
	s := &State{
		filePath: path,
		Proxies:  make(map[string]*proxy.Proxy),
		Devices:  make(map[string]*DeviceConfig),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = s.saveLocked()
			return s, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}

	if s.Proxies == nil {
		s.Proxies = make(map[string]*proxy.Proxy)
	}
	if s.Devices == nil {
		s.Devices = make(map[string]*DeviceConfig)
	}

	return s, nil
}

func (s *State) saveLocked() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write tmp state file: %w", err)
	}

	if err := os.Rename(tmpPath, s.filePath); err != nil {
		return fmt.Errorf("failed to rename state file: %w", err)
	}
	return nil
}

// GetProxies returns all configured proxies.
func (s *State) GetProxies() []*proxy.Proxy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*proxy.Proxy, 0, len(s.Proxies))
	for _, p := range s.Proxies {
		res = append(res, p.Clone())
	}
	return res
}

// GetProxy retrieves a proxy by ID.
func (s *State) GetProxy(id string) *proxy.Proxy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.Proxies[id]
	if !ok {
		return nil
	}
	return p.Clone()
}

// SaveProxy adds or updates a proxy.
func (s *State) SaveProxy(p *proxy.Proxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.ID == "" {
		p.ID = proxy.GenerateID()
	}
	p.UpdatedAt = time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = p.UpdatedAt
	}

	s.Proxies[p.ID] = p.Clone()
	return s.saveLocked()
}

// DeleteProxy removes a proxy and clears any assignments referencing it.
func (s *State) DeleteProxy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.Proxies, id)

	// Clear assignments pointing to this proxy
	for _, d := range s.Devices {
		if d.ProxyID == id {
			d.ProxyID = ""
			d.AssignedAt = time.Time{}
		}
	}

	return s.saveLocked()
}

// GetDevice returns persistent settings for a device IP.
func (s *State) GetDevice(ip string) *DeviceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	d, ok := s.Devices[ip]
	if !ok {
		return nil
	}
	cp := *d
	return &cp
}

// GetAllDevices returns all device configurations.
func (s *State) GetAllDevices() map[string]*DeviceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make(map[string]*DeviceConfig, len(s.Devices))
	for ip, d := range s.Devices {
		cp := *d
		res[ip] = &cp
	}
	return res
}

// SetDeviceAssignment updates a device's assigned proxy.
func (s *State) SetDeviceAssignment(ip, mac, nickname, proxyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.Devices[ip]
	if !ok {
		d = &DeviceConfig{
			IP: ip,
		}
		s.Devices[ip] = d
	}

	if mac != "" {
		d.MAC = mac
	}
	if nickname != "" {
		d.Nickname = nickname
	}
	d.ProxyID = proxyID
	if proxyID != "" {
		d.AssignedAt = time.Now()
	} else {
		d.AssignedAt = time.Time{}
	}

	return s.saveLocked()
}

// RemoveDeviceAssignment clears proxy assignment for an IP.
func (s *State) RemoveDeviceAssignment(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if d, ok := s.Devices[ip]; ok {
		d.ProxyID = ""
		d.AssignedAt = time.Time{}
		return s.saveLocked()
	}
	return nil
}

// SetDeviceNickname updates only the nickname.
func (s *State) SetDeviceNickname(ip, nickname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.Devices[ip]
	if !ok {
		d = &DeviceConfig{IP: ip}
		s.Devices[ip] = d
	}
	d.Nickname = nickname
	return s.saveLocked()
}

// GetAssignedDevices returns devices that currently have an active proxy assignment.
func (s *State) GetAssignedDevices() []*DeviceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var res []*DeviceConfig
	for _, d := range s.Devices {
		if d.ProxyID != "" && s.Proxies[d.ProxyID] != nil {
			cp := *d
			res = append(res, &cp)
		}
	}
	return res
}
