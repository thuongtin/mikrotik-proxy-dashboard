package mikrotik

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ethan/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/ethan/mikrotik-proxy-dashboard/internal/state"
)

type mockRouterState struct {
	mu          sync.Mutex
	leases      []map[string]interface{}
	arps        []map[string]interface{}
	addrLists   []map[string]interface{}
	ipv6Rules   []map[string]interface{}
	connections []map[string]interface{}
	v6Neighbors []map[string]interface{}
	madeStatic  []string
	deletedURLs []string
}

func setupMockRouter() (*mockRouterState, *httptest.Server) {
	mock := &mockRouterState{
		leases: []map[string]interface{}{
			{
				".id":         "*1",
				"address":     "10.88.88.50",
				"mac-address": "00:11:22:33:44:50",
				"host-name":   "MacBook-Pro",
				"status":      "bound",
				"dynamic":     "true",
			},
			{
				".id":         "*2",
				"address":     "10.88.88.1",
				"mac-address": "00:11:22:33:44:01",
				"host-name":   "RouterGateway",
				"status":      "bound",
				"dynamic":     "false",
			},
		},
		arps: []map[string]interface{}{
			{
				".id":         "*A1",
				"address":     "10.88.88.50",
				"mac-address": "00:11:22:33:44:50",
				"complete":    "true",
			},
			{
				".id":         "*A2",
				"address":     "10.88.88.60",
				"mac-address": "00:11:22:33:44:60",
				"complete":    "true",
				"dynamic":     "true",
			},
		},
		addrLists: []map[string]interface{}{},
		ipv6Rules: []map[string]interface{}{
			{
				".id":     "*R1",
				"chain":   "forward",
				"action":  "accept",
				"dynamic": "false",
			},
		},
		connections: []map[string]interface{}{
			{
				".id":         "*C1",
				"src-address": "10.88.88.50:49200",
				"dst-address": "1.1.1.1:443",
			},
			{
				".id":         "*C2",
				"src-address": "10.88.88.99:50000",
				"dst-address": "8.8.8.8:53",
			},
		},
		v6Neighbors: []map[string]interface{}{
			{
				".id":         "*N1",
				"address":     "2001:db8::50",
				"mac-address": "00:11:22:33:44:50",
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()

		path := r.URL.Path

		switch {
		case r.Method == "GET" && path == "/rest/ip/dhcp-server/lease":
			_ = json.NewEncoder(w).Encode(mock.leases)

		case r.Method == "POST" && path == "/rest/ip/dhcp-server/lease/make-static":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mock.madeStatic = append(mock.madeStatic, body[".id"])
			w.WriteHeader(http.StatusOK)

		case r.Method == "GET" && path == "/rest/ip/arp":
			_ = json.NewEncoder(w).Encode(mock.arps)

		case r.Method == "GET" && path == "/rest/ip/firewall/address-list":
			_ = json.NewEncoder(w).Encode(mock.addrLists)

		case r.Method == "PUT" && path == "/rest/ip/firewall/address-list":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			body[".id"] = "*AL_NEW"
			mock.addrLists = append(mock.addrLists, body)
			w.WriteHeader(http.StatusOK)

		case r.Method == "DELETE" && strings.HasPrefix(path, "/rest/ip/firewall/address-list/"):
			mock.deletedURLs = append(mock.deletedURLs, path)
			w.WriteHeader(http.StatusOK)

		case r.Method == "GET" && path == "/rest/ipv6/firewall/filter":
			_ = json.NewEncoder(w).Encode(mock.ipv6Rules)

		case r.Method == "PUT" && path == "/rest/ipv6/firewall/filter":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			body[".id"] = "*R_NEW"
			mock.ipv6Rules = append(mock.ipv6Rules, body)
			w.WriteHeader(http.StatusOK)

		case r.Method == "GET" && path == "/rest/ip/firewall/connection":
			_ = json.NewEncoder(w).Encode(mock.connections)

		case r.Method == "DELETE" && strings.HasPrefix(path, "/rest/ip/firewall/connection/"):
			mock.deletedURLs = append(mock.deletedURLs, path)
			w.WriteHeader(http.StatusOK)

		case r.Method == "GET" && path == "/rest/ipv6/neighbor":
			_ = json.NewEncoder(w).Encode(mock.v6Neighbors)

		case r.Method == "GET" && path == "/rest/routing/table":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"name": "via-proxy"}})

		case r.Method == "GET" && path == "/rest/ip/firewall/filter":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"comment": "proxy-dash-killswitch", "packets": "120", "bytes": "8500"}})

		case r.Method == "GET" && path == "/rest/ip/firewall/nat":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"action": "dst-nat", "dst-port": "53"}})

		case r.Method == "GET" && path == "/rest/routing/rule":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"table": "via-proxy"}})

		default:
			w.WriteHeader(http.StatusOK)
		}
	})

	server := httptest.NewServer(handler)
	return mock, server
}

func TestMikroTikClientOperations(t *testing.T) {
	mock, server := setupMockRouter()
	defer server.Close()

	client, err := NewClient(server.URL, "admin", "testpass", true)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "mikrotik_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	st, err := state.Load(tempDir)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	ctx := context.Background()

	// 1. Test GetDevices (merges DHCP and ARP, excludes .1)
	devices, err := client.GetDevices(ctx, "10.88.88.0/24", st)
	if err != nil {
		t.Fatalf("failed to get devices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices (excluding router gateway .1), got: %d", len(devices))
	}

	// 2. Test EnsureStaticLease
	if err := client.EnsureStaticLease(ctx, "10.88.88.50", "00:11:22:33:44:50"); err != nil {
		t.Fatalf("failed to make static lease: %v", err)
	}
	if len(mock.madeStatic) != 1 || mock.madeStatic[0] != "*1" {
		t.Fatalf("expected make-static called on *1, got: %v", mock.madeStatic)
	}

	// 3. Test EnsureProxyAddressList
	if err := client.EnsureProxyAddressList(ctx, "10.88.88.50", "00:11:22:33:44:50"); err != nil {
		t.Fatalf("failed to ensure address list: %v", err)
	}
	if len(mock.addrLists) != 1 || mock.addrLists[0]["address"] != "10.88.88.50" {
		t.Fatalf("expected address list added, got: %+v", mock.addrLists)
	}

	// 4. Test EnsureIPv6BlockRules
	if err := client.EnsureIPv6BlockRules(ctx, "00:11:22:33:44:50"); err != nil {
		t.Fatalf("failed to ensure ipv6 rules: %v", err)
	}
	// Check that 2 rules (forward and input) were added before firstNonDynamicID
	fwdFound := false
	inFound := false
	for _, r := range mock.ipv6Rules {
		if r["comment"] == "proxy-dash-ipv6-fwd:00:11:22:33:44:50" {
			fwdFound = true
			if r["place-before"] != "*R1" {
				t.Fatalf("expected place-before *R1, got: %v", r["place-before"])
			}
		}
		if r["comment"] == "proxy-dash-ipv6-in:00:11:22:33:44:50" {
			inFound = true
		}
	}
	if !fwdFound || !inFound {
		t.Fatalf("expected both IPv6 forward and input reject rules to be created")
	}

	// 5. Test FlushDeviceConnections (deletes *C1)
	if err := client.FlushDeviceConnections(ctx, "10.88.88.50", "00:11:22:33:44:50"); err != nil {
		t.Fatalf("failed to flush connections: %v", err)
	}
	c1Deleted := false
	for _, d := range mock.deletedURLs {
		if strings.Contains(d, "*C1") {
			c1Deleted = true
		}
	}
	if !c1Deleted {
		t.Fatalf("expected connection *C1 to be deleted")
	}

	// 6. Test LeakGuardStatus
	_ = st.SaveProxy(&proxy.Proxy{ID: "p1", Name: "Test", Protocol: "http", Host: "1.2.3.4", Port: 80})
	_ = st.SetDeviceAssignment("10.88.88.50", "00:11:22:33:44:50", "Laptop", "p1")
	status, err := client.GetLeakGuardStatus(ctx, st, true)
	if err != nil {
		t.Fatalf("failed to get LeakGuard status: %v", err)
	}
	if status.OverallStatus != "protected" {
		t.Fatalf("expected status protected, got: %s", status.OverallStatus)
	}
	if status.KillSwitchPackets != 120 {
		t.Fatalf("expected 120 packets, got: %d", status.KillSwitchPackets)
	}
}
