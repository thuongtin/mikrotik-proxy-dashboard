package mikrotik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/proxy"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
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
	adds        []map[string]interface{}
	patches     []string
	moves       []map[string]string
	v4Filters   []map[string]interface{}
	natRules    []map[string]interface{}
	routeRules  []map[string]interface{}
	mangleRules []map[string]interface{}
	tables      []map[string]interface{}
	// failStatus forces an HTTP error status for a REST path (without /rest).
	failStatus map[string]int
}

func (m *mockRouterState) set(fn func(m *mockRouterState)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m)
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
		v4Filters: []map[string]interface{}{
			{".id": "*28", "chain": "forward", "action": "passthrough", "dynamic": "true", "comment": "special dummy rule to show fasttrack counters"},
			{
				".id": "*2A", "chain": "forward", "action": "drop", "comment": "proxy-dash-killswitch",
				"src-address-list": "PROXY_DEVICES", "out-interface-list": "WAN",
				"disabled": "false", "dynamic": "false", "invalid": "false", "packets": "120", "bytes": "8500",
			},
			{
				".id": "*5", "chain": "forward", "action": "fasttrack-connection", "connection-state": "established,related",
				"src-address-list": "!PROXY_DEVICES", "dst-address-list": "!PROXY_DEVICES",
			},
			{".id": "*6", "chain": "forward", "action": "accept", "connection-state": "established,related,untracked"},
		},
		natRules: []map[string]interface{}{
			{
				".id": "*16", "chain": "dstnat", "action": "dst-nat", "protocol": "udp", "dst-port": "53",
				"src-address-list": "PROXY_DEVICES", "to-addresses": "10.10.10.16", "to-ports": "53", "comment": "proxy-dash:dns-hijack-udp",
			},
			{
				".id": "*17", "chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "53",
				"src-address-list": "PROXY_DEVICES", "to-addresses": "10.10.10.16", "to-ports": "53", "comment": "proxy-dash:dns-hijack-tcp",
			},
		},
		routeRules: []map[string]interface{}{
			{".id": "*1", "action": "lookup-only-in-table", "routing-mark": "via-proxy", "table": "via-proxy", "disabled": "false"},
		},
		mangleRules: []map[string]interface{}{
			{
				".id": "*11", "chain": "prerouting", "action": "mark-routing", "new-routing-mark": "via-proxy",
				"src-address-list": "PROXY_DEVICES", "in-interface": "BridgeLAN", "disabled": "false",
			},
		},
		tables:     []map[string]interface{}{{".id": "*400", "name": "via-proxy", "fib": ""}},
		failStatus: map[string]int{},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()

		path := r.URL.Path

		if code, ok := mock.failStatus[strings.TrimPrefix(path, "/rest")]; ok {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":` + fmt.Sprint(code) + `,"message":"forced failure"}`))
			return
		}

		switch {
		case r.Method == "GET" && path == "/rest/ip/dhcp-server/lease":
			_ = json.NewEncoder(w).Encode(mock.leases)

		case r.Method == "POST" && path == "/rest/ip/dhcp-server/lease/make-static":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mock.madeStatic = append(mock.madeStatic, body[".id"])
			for _, l := range mock.leases {
				if l[".id"] == body[".id"] {
					l["dynamic"] = "false"
				}
			}
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
			id := strings.TrimPrefix(path, "/rest/ip/firewall/address-list/")
			var kept []map[string]interface{}
			for _, e := range mock.addrLists {
				if e[".id"] != id {
					kept = append(kept, e)
				}
			}
			mock.addrLists = kept
			w.WriteHeader(http.StatusOK)

		case r.Method == "PATCH" && strings.HasPrefix(path, "/rest/ip/firewall/address-list/"):
			mock.patches = append(mock.patches, path)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			id := strings.TrimPrefix(path, "/rest/ip/firewall/address-list/")
			found := false
			for _, e := range mock.addrLists {
				if e[".id"] == id {
					for k, v := range body {
						e[k] = v
					}
					found = true
				}
			}
			if !found {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":404,"message":"no such item"}`))
				return
			}
			w.WriteHeader(http.StatusOK)

		case r.Method == "GET" && path == "/rest/ipv6/firewall/filter":
			_ = json.NewEncoder(w).Encode(mock.ipv6Rules)

		case r.Method == "DELETE" && strings.HasPrefix(path, "/rest/ipv6/firewall/filter/"):
			mock.deletedURLs = append(mock.deletedURLs, path)
			id := strings.TrimPrefix(path, "/rest/ipv6/firewall/filter/")
			var kept []map[string]interface{}
			for _, rule := range mock.ipv6Rules {
				if rule[".id"] != id {
					kept = append(kept, rule)
				}
			}
			mock.ipv6Rules = kept
			w.WriteHeader(http.StatusOK)

		case r.Method == "POST" && path == "/rest/ipv6/firewall/filter/add":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			body[".id"] = fmt.Sprintf("*R_%d", len(mock.ipv6Rules)+1)
			mock.adds = append(mock.adds, body)
			// Simulate RouterOS 7.25.1 where add appends at bottom even if place-before is passed
			mock.ipv6Rules = append(mock.ipv6Rules, body)
			w.WriteHeader(http.StatusOK)

		case r.Method == "POST" && path == "/rest/ipv6/firewall/filter/move":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mock.moves = append(mock.moves, body)
			num := body["numbers"]
			dest := body["destination"]
			// Find and remove rule with ID num
			numIdx := -1
			var ruleToMove map[string]interface{}
			for i, r := range mock.ipv6Rules {
				if r[".id"] == num {
					numIdx = i
					ruleToMove = r
					break
				}
			}
			if numIdx != -1 {
				mock.ipv6Rules = append(mock.ipv6Rules[:numIdx], mock.ipv6Rules[numIdx+1:]...)
				destIdx := -1
				for i, r := range mock.ipv6Rules {
					if r[".id"] == dest {
						destIdx = i
						break
					}
				}
				if destIdx != -1 {
					mock.ipv6Rules = append(mock.ipv6Rules[:destIdx], append([]map[string]interface{}{ruleToMove}, mock.ipv6Rules[destIdx:]...)...)
				} else {
					mock.ipv6Rules = append([]map[string]interface{}{ruleToMove}, mock.ipv6Rules...)
				}
			}
			w.WriteHeader(http.StatusOK)

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
			_ = json.NewEncoder(w).Encode(mock.tables)

		case r.Method == "GET" && path == "/rest/ip/firewall/filter":
			_ = json.NewEncoder(w).Encode(mock.v4Filters)

		case r.Method == "GET" && path == "/rest/ip/firewall/nat":
			_ = json.NewEncoder(w).Encode(mock.natRules)

		case r.Method == "GET" && path == "/rest/routing/rule":
			_ = json.NewEncoder(w).Encode(mock.routeRules)

		case r.Method == "GET" && path == "/rest/ip/firewall/mangle":
			_ = json.NewEncoder(w).Encode(mock.mangleRules)

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

	client, err := NewClient(server.URL, "admin", "testpass", Options{})
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

	// 4. Test EnsureIPv6BlockRules (verifies POST /add and POST /move placing rules before *R1)
	if err := client.EnsureIPv6BlockRules(ctx, "00:11:22:33:44:50"); err != nil {
		t.Fatalf("failed to ensure ipv6 rules: %v", err)
	}
	if len(mock.adds) != 2 {
		t.Fatalf("expected 2 rules added via POST /add, got: %d", len(mock.adds))
	}
	for _, add := range mock.adds {
		if add["place-before"] != "*R1" {
			t.Fatalf("expected place-before *R1 in add payload, got: %v", add["place-before"])
		}
	}
	if len(mock.moves) != 2 {
		t.Fatalf("expected 2 rules moved via POST /move, got: %d", len(mock.moves))
	}
	for _, mv := range mock.moves {
		if mv["destination"] != "*R1" {
			t.Fatalf("expected move destination *R1, got: %v", mv["destination"])
		}
	}

	// Verify that in the final mock.ipv6Rules slice, both proxy-dash rules appear BEFORE *R1
	r1Index := -1
	fwdIndex := -1
	inIndex := -1
	for idx, r := range mock.ipv6Rules {
		if r[".id"] == "*R1" {
			r1Index = idx
		}
		if r["comment"] == "proxy-dash-ipv6-fwd:00:11:22:33:44:50" {
			fwdIndex = idx
		}
		if r["comment"] == "proxy-dash-ipv6-in:00:11:22:33:44:50" {
			inIndex = idx
		}
	}
	if fwdIndex == -1 || inIndex == -1 || r1Index == -1 {
		t.Fatalf("rules not found in mock.ipv6Rules: fwd=%d, in=%d, r1=%d", fwdIndex, inIndex, r1Index)
	}
	if fwdIndex >= r1Index || inIndex >= r1Index {
		t.Fatalf("expected proxy-dash rules to be positioned before *R1, got fwdIndex=%d, inIndex=%d, r1Index=%d", fwdIndex, inIndex, r1Index)
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
	status, err := client.GetLeakGuardStatus(ctx, st, EngineStatus{SingboxRunning: true, ForwardGuard: ForwardGuardActive}, nil)
	if err != nil {
		t.Fatalf("failed to get LeakGuard status: %v", err)
	}
	if status.OverallStatus != OverallProtected {
		t.Fatalf("expected status protected, got: %s (%+v)", status.OverallStatus, status.Layers)
	}
	if !status.RouterReachable {
		t.Fatalf("expected router to be reported reachable")
	}
	if status.KillSwitchPackets != 120 {
		t.Fatalf("expected 120 packets, got: %d", status.KillSwitchPackets)
	}
}

func TestDeterministicDeviceSorting(t *testing.T) {
	devices := []*Device{
		{IP: "10.88.88.29", Assigned: false, Online: true, MAC: "00:11:22:33:44:29"},
		{IP: "10.88.88.10", Assigned: true, Online: false, MAC: "00:11:22:33:44:10"},
		{IP: "10.88.88.3", Assigned: true, Online: true, MAC: "00:11:22:33:44:03"},
		{IP: "10.88.88.2", Assigned: false, Online: false, MAC: "00:11:22:33:44:02"},
		{IP: "10.88.88.100", Assigned: true, Online: true, MAC: "00:11:22:33:44:a0"},
		{IP: "10.88.88.5", Assigned: false, Online: true, MAC: "00:11:22:33:44:05"},
	}

	// Expected order:
	// 1. Assigned (true):
	//    - Online (true): 10.88.88.3, 10.88.88.100
	//    - Online (false): 10.88.88.10
	// 2. Assigned (false):
	//    - Online (true): 10.88.88.5, 10.88.88.29
	//    - Online (false): 10.88.88.2
	expectedIPs := []string{
		"10.88.88.3",
		"10.88.88.100",
		"10.88.88.10",
		"10.88.88.5",
		"10.88.88.29",
		"10.88.88.2",
	}

	for run := 0; run < 5; run++ {
		copied := make([]*Device, len(devices))
		copy(copied, devices)

		SortDevices(copied)

		for i, dev := range copied {
			if dev.IP != expectedIPs[i] {
				t.Fatalf("run %d index %d: expected IP %s, got %s", run, i, expectedIPs[i], dev.IP)
			}
		}
	}
}
