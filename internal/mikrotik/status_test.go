package mikrotik

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/i18n"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
)

const (
	testIP  = "10.88.88.50"
	testMAC = "00:11:22:33:44:50"
)

// newAssignedFixture returns a mock router and state where one device is fully
// and correctly assigned, so every layer starts out "ok".
func newAssignedFixture(t *testing.T) (*mockRouterState, *Client, *state.State) {
	t.Helper()
	mock, server := setupMockRouter()
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "admin", "testpass", Options{})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	st, err := state.Load(t.TempDir())
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if err := st.SaveProxy(&proxy.Proxy{ID: "p1", Name: "Test", Protocol: "http", Host: "1.2.3.4", Port: 80}); err != nil {
		t.Fatalf("failed to save proxy: %v", err)
	}
	if err := st.SetDeviceAssignment(testIP, testMAC, "Laptop", "p1"); err != nil {
		t.Fatalf("failed to assign device: %v", err)
	}

	ctx := context.Background()
	if err := client.EnsureStaticLease(ctx, testIP, testMAC); err != nil {
		t.Fatalf("EnsureStaticLease: %v", err)
	}
	if err := client.EnsureProxyAddressList(ctx, testIP, testMAC); err != nil {
		t.Fatalf("EnsureProxyAddressList: %v", err)
	}
	if err := client.EnsureIPv6BlockRules(ctx, testMAC); err != nil {
		t.Fatalf("EnsureIPv6BlockRules: %v", err)
	}
	return mock, client, st
}

func leakGuard(t *testing.T, c *Client, st *state.State, singbox bool) *LeakGuardStatus {
	t.Helper()
	status, err := c.GetLeakGuardStatus(context.Background(), st, EngineStatus{SingboxRunning: singbox, ForwardGuard: ForwardGuardActive}, nil)
	if err != nil {
		t.Fatalf("GetLeakGuardStatus: %v", err)
	}
	if len(status.Layers) != 6 {
		t.Fatalf("expected 6 layers, got %d", len(status.Layers))
	}
	return status
}

func expectLayer(t *testing.T, status *LeakGuardStatus, layer int, want string) LeakGuardLayer {
	t.Helper()
	l := status.Layers[layer-1]
	if l.Status != want {
		t.Fatalf("layer %d: expected %q, got %q (%s | %s)", layer, want, l.Status, l.Description, l.Details)
	}
	return l
}

func TestLeakGuardAllLayersOK(t *testing.T) {
	_, client, st := newAssignedFixture(t)
	status := leakGuard(t, client, st, true)
	for i := 1; i <= 6; i++ {
		expectLayer(t, status, i, StatusOK)
	}
	if status.OverallStatus != OverallProtected {
		t.Fatalf("expected protected, got %s", status.OverallStatus)
	}
}

func TestLeakGuardKillSwitch(t *testing.T) {
	killSwitch := func(m *mockRouterState) map[string]interface{} {
		for _, r := range m.v4Filters {
			if r["comment"] == "proxy-dash-killswitch" {
				return r
			}
		}
		return nil
	}

	cases := []struct {
		name    string
		mutate  func(m *mockRouterState)
		want    string
		overall string
		detail  string
	}{
		{"disabled", func(m *mockRouterState) { killSwitch(m)["disabled"] = "true" }, StatusError, OverallUnprotected, "disabled"},
		{"invalid", func(m *mockRouterState) { killSwitch(m)["invalid"] = "true" }, StatusError, OverallUnprotected, "invalid"},
		{"wrong action", func(m *mockRouterState) { killSwitch(m)["action"] = "accept" }, StatusError, OverallUnprotected, "action"},
		{"wrong chain", func(m *mockRouterState) { killSwitch(m)["chain"] = "input" }, StatusError, OverallUnprotected, "chain"},
		{"wrong source list", func(m *mockRouterState) { killSwitch(m)["src-address-list"] = "OTHER" }, StatusError, OverallUnprotected, "src-address-list"},
		{"comment only", func(m *mockRouterState) {
			m.v4Filters = []map[string]interface{}{{"comment": "proxy-dash-killswitch", "packets": "120", "bytes": "8500"}}
		}, StatusError, OverallUnprotected, "chain"},
		{"missing", func(m *mockRouterState) { m.v4Filters = m.v4Filters[:1] }, StatusError, OverallUnprotected, ""},
		{"no out interface", func(m *mockRouterState) { delete(killSwitch(m), "out-interface-list") }, StatusWarning, OverallDegraded, "out-interface-list"},
		{"accept placed before", func(m *mockRouterState) {
			early := map[string]interface{}{".id": "*99", "chain": "forward", "action": "accept", "comment": "allow all"}
			m.v4Filters = append([]map[string]interface{}{early}, m.v4Filters...)
		}, StatusWarning, OverallDegraded, "*99"},
		{"established-only accept placed before", func(m *mockRouterState) {
			early := map[string]interface{}{".id": "*99", "chain": "forward", "action": "accept", "connection-state": "established,related"}
			m.v4Filters = append([]map[string]interface{}{early}, m.v4Filters...)
		}, StatusOK, OverallProtected, ""},
		{"disabled accept placed before", func(m *mockRouterState) {
			early := map[string]interface{}{".id": "*99", "chain": "forward", "action": "accept", "disabled": "true"}
			m.v4Filters = append([]map[string]interface{}{early}, m.v4Filters...)
		}, StatusOK, OverallProtected, ""},
		{"input chain accept placed before", func(m *mockRouterState) {
			early := map[string]interface{}{".id": "*99", "chain": "input", "action": "accept"}
			m.v4Filters = append([]map[string]interface{}{early}, m.v4Filters...)
		}, StatusOK, OverallProtected, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock, client, st := newAssignedFixture(t)
			mock.set(tc.mutate)
			status := leakGuard(t, client, st, true)
			l := expectLayer(t, status, 3, tc.want)
			if status.OverallStatus != tc.overall {
				t.Fatalf("expected overall %s, got %s", tc.overall, status.OverallStatus)
			}
			if tc.detail != "" && !strings.Contains(l.Details, tc.detail) {
				t.Fatalf("expected details to mention %q, got %q", tc.detail, l.Details)
			}
		})
	}
}

func TestLeakGuardStaticBindingAndIPv6(t *testing.T) {
	t.Run("dynamic lease", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) { m.leases[0]["dynamic"] = "true" })
		status := leakGuard(t, client, st, true)
		expectLayer(t, status, 1, StatusError)
	})
	t.Run("lease owned by another MAC", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) { m.leases[0]["mac-address"] = "AA:BB:CC:DD:EE:FF" })
		status := leakGuard(t, client, st, true)
		expectLayer(t, status, 1, StatusError)
	})
	t.Run("lease missing", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) { m.leases = m.leases[1:] })
		status := leakGuard(t, client, st, true)
		expectLayer(t, status, 1, StatusError)
	})
	t.Run("ipv6 rule disabled", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) {
			for _, r := range m.ipv6Rules {
				if r["comment"] == "proxy-dash-ipv6-fwd:"+testMAC {
					r["disabled"] = "true"
				}
			}
		})
		status := leakGuard(t, client, st, true)
		l := expectLayer(t, status, 4, StatusError)
		if !strings.Contains(l.Details, "forward") {
			t.Fatalf("expected details to name the forward chain, got %q", l.Details)
		}
	})
	t.Run("ipv6 input rule missing", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) {
			var kept []map[string]interface{}
			for _, r := range m.ipv6Rules {
				if r["comment"] != "proxy-dash-ipv6-in:"+testMAC {
					kept = append(kept, r)
				}
			}
			m.ipv6Rules = kept
		})
		status := leakGuard(t, client, st, true)
		expectLayer(t, status, 4, StatusError)
	})
	t.Run("ipv6 rule behind accept", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) {
			early := map[string]interface{}{".id": "*R0", "chain": "forward", "action": "accept", "comment": "allow v6"}
			m.ipv6Rules = append([]map[string]interface{}{early}, m.ipv6Rules...)
		})
		status := leakGuard(t, client, st, true)
		expectLayer(t, status, 4, StatusWarning)
	})
	t.Run("device without MAC", func(t *testing.T) {
		_, client, st := newAssignedFixture(t)
		if err := st.SetDeviceAssignment("10.88.88.60", "", "No MAC", "p1"); err != nil {
			t.Fatalf("failed to assign device: %v", err)
		}
		status := leakGuard(t, client, st, true)
		expectLayer(t, status, 1, StatusError)
		expectLayer(t, status, 4, StatusError)
	})
}

func TestLeakGuardPolicyRouting(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *mockRouterState)
		want   string
	}{
		{"table missing", func(m *mockRouterState) { m.tables = nil }, StatusError},
		{"rule missing", func(m *mockRouterState) { m.routeRules = nil }, StatusError},
		{"rule disabled", func(m *mockRouterState) { m.routeRules[0]["disabled"] = "true" }, StatusError},
		{"no selector", func(m *mockRouterState) { m.mangleRules = nil }, StatusError},
		{"mark rule disabled", func(m *mockRouterState) { m.mangleRules[0]["disabled"] = "true" }, StatusError},
		{"selector by routing rule", func(m *mockRouterState) {
			m.mangleRules = nil
			m.routeRules[0]["src-address"] = "10.88.88.0/24"
		}, StatusOK},
		{"non strict lookup", func(m *mockRouterState) { m.routeRules[0]["action"] = "lookup" }, StatusWarning},
		{"device missing from address-list", func(m *mockRouterState) { m.addrLists = nil }, StatusError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock, client, st := newAssignedFixture(t)
			mock.set(tc.mutate)
			expectLayer(t, leakGuard(t, client, st, true), 2, tc.want)
		})
	}
}

func TestLeakGuardDNSHijack(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *mockRouterState)
		want   string
	}{
		{"udp only", func(m *mockRouterState) { m.natRules = m.natRules[:1] }, StatusWarning},
		{"tcp only", func(m *mockRouterState) { m.natRules = m.natRules[1:] }, StatusWarning},
		{"none", func(m *mockRouterState) { m.natRules = nil }, StatusError},
		{"port 5353 is not DNS", func(m *mockRouterState) {
			for _, r := range m.natRules {
				r["dst-port"] = "5353"
			}
		}, StatusError},
		{"port list containing 53", func(m *mockRouterState) {
			for _, r := range m.natRules {
				r["dst-port"] = "53,853"
			}
		}, StatusOK},
		{"disabled", func(m *mockRouterState) {
			for _, r := range m.natRules {
				r["disabled"] = "true"
			}
		}, StatusError},
		{"redirect instead of dst-nat", func(m *mockRouterState) {
			for _, r := range m.natRules {
				r["action"] = "redirect"
				delete(r, "to-addresses")
			}
		}, StatusError},
		{"shadowed by earlier rule", func(m *mockRouterState) {
			early := map[string]interface{}{".id": "*90", "chain": "dstnat", "action": "redirect", "protocol": "udp", "dst-port": "53", "comment": "lan dns"}
			m.natRules = append([]map[string]interface{}{early}, m.natRules...)
		}, StatusWarning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock, client, st := newAssignedFixture(t)
			mock.set(tc.mutate)
			expectLayer(t, leakGuard(t, client, st, true), 5, tc.want)
		})
	}
}

func TestLeakGuardUnknownWhenRouterFails(t *testing.T) {
	t.Run("one query rejected", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) { m.failStatus["/ip/firewall/filter"] = http.StatusInternalServerError })
		status := leakGuard(t, client, st, true)
		expectLayer(t, status, 3, StatusUnknown)
		expectLayer(t, status, 5, StatusOK)
		if status.OverallStatus != OverallUnknown {
			t.Fatalf("expected overall unknown, got %s", status.OverallStatus)
		}
		if !status.RouterReachable {
			t.Fatalf("router answered other queries, expected reachable")
		}
	})

	t.Run("an error outranks unknown", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) { m.failStatus["/ip/firewall/filter"] = http.StatusInternalServerError })
		status := leakGuard(t, client, st, false)
		expectLayer(t, status, 6, StatusError)
		if status.OverallStatus != OverallUnprotected {
			t.Fatalf("expected overall unprotected, got %s", status.OverallStatus)
		}
	})

	t.Run("router down", func(t *testing.T) {
		mock, server := setupMockRouter()
		_ = mock
		client, err := NewClient(server.URL, "admin", "testpass", Options{})
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		server.Close()
		st, err := state.Load(t.TempDir())
		if err != nil {
			t.Fatalf("failed to load state: %v", err)
		}
		status := leakGuard(t, client, st, true)
		if status.RouterReachable {
			t.Fatalf("expected router to be reported unreachable")
		}
		for _, layer := range []int{2, 3, 5} {
			expectLayer(t, status, layer, StatusUnknown)
		}
		if status.OverallStatus != OverallUnknown {
			t.Fatalf("expected overall unknown, got %s", status.OverallStatus)
		}
	})
}

func TestReconcileReportsFailures(t *testing.T) {
	t.Run("address-list query fails", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) { m.failStatus["/ip/firewall/address-list"] = http.StatusInternalServerError })
		if err := client.Reconcile(context.Background(), st); err == nil {
			t.Fatalf("expected Reconcile to report the failed query")
		}
	})
	t.Run("ipv6 rule creation fails", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) {
			m.ipv6Rules = m.ipv6Rules[len(m.ipv6Rules)-1:]
			m.failStatus["/ipv6/firewall/filter/add"] = http.StatusBadRequest
		})
		err := client.Reconcile(context.Background(), st)
		if err == nil || !strings.Contains(err.Error(), "IPv6") {
			t.Fatalf("expected an IPv6 error, got %v", err)
		}
	})
	t.Run("restores missing entries and removes stale ones", func(t *testing.T) {
		mock, client, st := newAssignedFixture(t)
		mock.set(func(m *mockRouterState) {
			m.addrLists = []map[string]interface{}{{".id": "*OLD", "list": "PROXY_DEVICES", "address": "10.88.88.77"}}
			m.ipv6Rules = append(m.ipv6Rules, map[string]interface{}{".id": "*STALE", "chain": "forward", "comment": "proxy-dash-ipv6-fwd:aa:bb:cc:dd:ee:ff"})
		})
		if err := client.Reconcile(context.Background(), st); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		mock.mu.Lock()
		defer mock.mu.Unlock()
		restored := false
		for _, e := range mock.addrLists {
			if e["address"] == testIP {
				restored = true
			}
		}
		if !restored {
			t.Fatalf("expected %s to be re-added to the address-list", testIP)
		}
		joined := strings.Join(mock.deletedURLs, " ")
		if !strings.Contains(joined, "*OLD") || !strings.Contains(joined, "*STALE") {
			t.Fatalf("expected stale entries to be deleted, got %v", mock.deletedURLs)
		}
	})
}

func TestEnsureStaticLeaseRefusesWrongOwner(t *testing.T) {
	_, server := setupMockRouter()
	defer server.Close()
	client, err := NewClient(server.URL, "admin", "testpass", Options{})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	ctx := context.Background()
	if err := client.EnsureStaticLease(ctx, testIP, "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Fatalf("expected an error when the lease belongs to another MAC")
	}
	if err := client.EnsureStaticLease(ctx, testIP, ""); err == nil {
		t.Fatalf("expected an error when no MAC is given")
	}
}

func TestFlushReportsFailures(t *testing.T) {
	mock, client, _ := newAssignedFixture(t)
	mock.set(func(m *mockRouterState) { m.failStatus["/ip/firewall/connection"] = http.StatusInternalServerError })
	if err := client.FlushDeviceConnections(context.Background(), testIP, testMAC); err == nil {
		t.Fatalf("expected FlushDeviceConnections to report the failure")
	}
	if err := client.FlushAllProxyConnections(context.Background(), []string{testIP}); err == nil {
		t.Fatalf("expected FlushAllProxyConnections to report the failure")
	}
}

func TestPortListContains(t *testing.T) {
	cases := map[string]bool{
		"53":       true,
		"53,853":   true,
		"853, 53":  true,
		"50-60":    true,
		"5353":     false,
		"153":      false,
		"530":      false,
		"!53":      false,
		"":         false,
		"54-60":    false,
		"domain":   false,
		"1-52,853": false,
	}
	for list, want := range cases {
		if got := portListContains(list, 53); got != want {
			t.Errorf("portListContains(%q, 53) = %v, want %v", list, got, want)
		}
	}
}

func TestAcceptsNewConnections(t *testing.T) {
	cases := []struct {
		name                                                         string
		action, disabled, dynamic, invalid, connState, natState, ips string
		want                                                         bool
	}{
		{name: "plain accept", action: "accept", want: true},
		{name: "fasttrack without state", action: "fasttrack-connection", want: true},
		{name: "drop", action: "drop", want: false},
		{name: "established only", action: "accept", connState: "established,related,untracked", want: false},
		{name: "includes new", action: "accept", connState: "established,new", want: true},
		{name: "negated invalid", action: "accept", connState: "!invalid", want: true},
		{name: "negated new", action: "accept", connState: "!new", want: false},
		{name: "disabled", action: "accept", disabled: "true", want: false},
		{name: "dynamic", action: "accept", dynamic: "true", want: false},
		{name: "invalid", action: "accept", invalid: "true", want: false},
		{name: "dstnat only", action: "accept", natState: "dstnat", want: false},
		{name: "ipsec only", action: "accept", ips: "in,ipsec", want: false},
	}
	for _, tc := range cases {
		if got := acceptsNewConnections(tc.action, tc.disabled, tc.dynamic, tc.invalid, tc.connState, tc.natState, tc.ips); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAPIErrorAndNotFound(t *testing.T) {
	mock, client, _ := newAssignedFixture(t)
	mock.set(func(m *mockRouterState) { m.failStatus["/ip/arp"] = http.StatusNotFound })
	err := client.Do(context.Background(), "GET", "/ip/arp", nil, nil)
	if !IsNotFound(err) {
		t.Fatalf("expected a not-found API error, got %v", err)
	}
	if IsNotFound(nil) {
		t.Fatalf("nil must not be reported as not found")
	}
}

func TestLayerSingboxReflectsForwardGuard(t *testing.T) {
	cases := []struct {
		name   string
		engine EngineStatus
		want   string
	}{
		{"running with guard", EngineStatus{SingboxRunning: true, ForwardGuard: ForwardGuardActive}, StatusOK},
		{"running, guard switched off", EngineStatus{SingboxRunning: true, ForwardGuard: ForwardGuardOff}, StatusWarning},
		{"running, guard not installable", EngineStatus{SingboxRunning: true, ForwardGuard: ForwardGuardUnavailable}, StatusWarning},
		{"running, guard not reported", EngineStatus{SingboxRunning: true}, StatusWarning},
		{"stopped with guard", EngineStatus{ForwardGuard: ForwardGuardActive}, StatusError},
		{"stopped without guard", EngineStatus{}, StatusError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			layer := layerSingbox(nil, tc.engine)
			if layer.Status != tc.want {
				t.Fatalf("expected %q, got %q (%s)", tc.want, layer.Status, layer.Description)
			}
			if layer.Details == "" {
				t.Fatal("expected details describing the forward guard")
			}
		})
	}
}

func TestMissingForwardGuardDegradesOverallStatus(t *testing.T) {
	_, client, st := newAssignedFixture(t)
	status, err := client.GetLeakGuardStatus(context.Background(), st, EngineStatus{SingboxRunning: true, ForwardGuard: ForwardGuardUnavailable}, nil)
	if err != nil {
		t.Fatalf("GetLeakGuardStatus: %v", err)
	}
	if status.OverallStatus != OverallDegraded {
		t.Fatalf("expected %q, got %q", OverallDegraded, status.OverallStatus)
	}
}

func TestLeakGuardIsLocalized(t *testing.T) {
	_, client, st := newAssignedFixture(t)
	engine := EngineStatus{SingboxRunning: true, ForwardGuard: ForwardGuardActive}

	en, err := client.GetLeakGuardStatus(context.Background(), st, engine, i18n.New("en"))
	if err != nil {
		t.Fatalf("GetLeakGuardStatus en: %v", err)
	}
	vi, err := client.GetLeakGuardStatus(context.Background(), st, engine, i18n.New("vi"))
	if err != nil {
		t.Fatalf("GetLeakGuardStatus vi: %v", err)
	}
	if len(en.Layers) != len(vi.Layers) {
		t.Fatalf("layer count differs: %d vs %d", len(en.Layers), len(vi.Layers))
	}
	for i := range en.Layers {
		if en.Layers[i].Name != vi.Layers[i].Name || en.Layers[i].Status != vi.Layers[i].Status {
			t.Fatalf("layer %d: name and status must not depend on language", i)
		}
	}
	if got, want := en.Layers[0].Description, "1 device has its IP pinned (static lease)"; got != want {
		t.Fatalf("en layer 1 = %q, want %q", got, want)
	}
	if got, want := vi.Layers[0].Description, "1 thiết bị được cố định IP tĩnh (Static Lease)"; got != want {
		t.Fatalf("vi layer 1 = %q, want %q", got, want)
	}
}
