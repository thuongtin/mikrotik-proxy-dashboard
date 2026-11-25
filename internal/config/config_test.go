package config

import "testing"

func TestParseForwardGuardStatus(t *testing.T) {
	cases := map[string]string{
		"active":      "active",
		" Active\n":   "active",
		"unavailable": "unavailable",
		"off":         "off",
		"":            "",
		"enabled":     "",
		"activex":     "",
	}
	for raw, want := range cases {
		if got := parseForwardGuardStatus(raw); got != want {
			t.Errorf("parseForwardGuardStatus(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestLoadFromEnvSecureDefaults(t *testing.T) {
	t.Setenv("MIKROTIK_INSECURE_TLS", "")
	t.Setenv("FORWARD_GUARD_STATUS", "")
	cfg := LoadFromEnv()
	if cfg.MikroTikInsecureTLS {
		t.Fatal("certificate verification must be on by default")
	}
	if cfg.ForwardGuardStatus != "" {
		t.Fatalf("expected no forward guard status, got %q", cfg.ForwardGuardStatus)
	}
}
