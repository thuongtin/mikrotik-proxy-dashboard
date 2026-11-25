package config

import (
	"os"
	"strings"
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	ListenAddr           string
	DataDir              string
	LanCIDR              string
	ContainerGW          string
	VethIF               string
	ExcludeCIDRs         []string
	SingboxPath          string
	DashboardPasswordHash string
	MikroTikURL          string
	MikroTikUser         string
	MikroTikPass         string
	MikroTikInsecureTLS  bool
}

// LoadFromEnv loads configuration from environment variables with defaults.
func LoadFromEnv() *Config {
	listenAddr := getEnv("LISTEN_ADDR", ":8080")
	dataDir := getEnv("DATA_DIR", "/data")
	lanCIDR := getEnv("LAN_CIDR", "10.88.88.0/24")
	containerGW := getEnv("CONTAINER_GW", "10.10.10.1")
	vethIF := getEnv("VETH_IF", "")
	singboxPath := getEnv("SINGBOX_PATH", "/usr/local/bin/sing-box")

	excludeCIDRsStr := getEnv("EXCLUDE_CIDRS", "10.88.88.0/24,10.10.10.0/24,10.77.77.0/24,192.168.0.0/16")
	excludeCIDRs := splitClean(excludeCIDRsStr, ",")

	mikrotikURL := getEnv("MIKROTIK_URL", "https://10.88.88.1")
	mikrotikUser := getEnv("MIKROTIK_USER", "admin")
	mikrotikPass := getEnv("MIKROTIK_PASS", "")
	insecureTLS := getEnv("MIKROTIK_INSECURE_TLS", "true") == "true"

	passwordHash := getEnv("DASHBOARD_PASSWORD_HASH", "")

	return &Config{
		ListenAddr:           listenAddr,
		DataDir:              dataDir,
		LanCIDR:              lanCIDR,
		ContainerGW:          containerGW,
		VethIF:               vethIF,
		ExcludeCIDRs:         excludeCIDRs,
		SingboxPath:          singboxPath,
		DashboardPasswordHash: passwordHash,
		MikroTikURL:          mikrotikURL,
		MikroTikUser:         mikrotikUser,
		MikroTikPass:         mikrotikPass,
		MikroTikInsecureTLS:  insecureTLS,
	}
}

func getEnv(key, defaultVal string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val
}

func splitClean(s, sep string) []string {
	parts := strings.Split(s, sep)
	var res []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}
