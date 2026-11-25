package mikrotik

import (
	"context"
	"testing"
)

func entriesFor(m *mockRouterState, ip string) []map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []map[string]interface{}
	for _, e := range m.addrLists {
		if e["list"] == proxyAddressList && e["address"] == ip {
			out = append(out, e)
		}
	}
	return out
}

func TestEnsureProxyAddressListReenablesDisabledEntry(t *testing.T) {
	mock, server := setupMockRouter()
	defer server.Close()
	client, err := NewClient(server.URL, "admin", "testpass", Options{})
	if err != nil {
		t.Fatal(err)
	}
	mock.set(func(m *mockRouterState) {
		m.addrLists = []map[string]interface{}{
			{".id": "*A1", "list": proxyAddressList, "address": testIP, "disabled": "true"},
		}
	})

	if err := client.EnsureProxyAddressList(context.Background(), testIP, testMAC); err != nil {
		t.Fatalf("EnsureProxyAddressList: %v", err)
	}
	entries := entriesFor(mock, testIP)
	if len(entries) != 1 {
		t.Fatalf("expected the disabled entry to be reused, got %+v", entries)
	}
	if isTrue(entries[0]["disabled"].(string)) {
		t.Fatalf("entry is still disabled: %+v", entries[0])
	}
	if len(mock.patches) != 1 || mock.patches[0] != "/rest/ip/firewall/address-list/*A1" {
		t.Fatalf("expected one PATCH on *A1, got %v", mock.patches)
	}
}

func TestEnsureProxyAddressListAddsWhenDisabledEntryVanished(t *testing.T) {
	mock, server := setupMockRouter()
	defer server.Close()
	client, err := NewClient(server.URL, "admin", "testpass", Options{})
	if err != nil {
		t.Fatal(err)
	}
	mock.set(func(m *mockRouterState) {
		m.addrLists = []map[string]interface{}{
			{".id": "*A1", "list": proxyAddressList, "address": testIP, "disabled": "true"},
		}
		m.failStatus["/ip/firewall/address-list/*A1"] = 404
	})

	if err := client.EnsureProxyAddressList(context.Background(), testIP, testMAC); err != nil {
		t.Fatalf("EnsureProxyAddressList: %v", err)
	}
	var added bool
	for _, e := range entriesFor(mock, testIP) {
		if e[".id"] == "*AL_NEW" {
			added = true
		}
	}
	if !added {
		t.Fatalf("expected a fresh entry after the PATCH returned 404, got %+v", mock.addrLists)
	}
}

func TestEnsureProxyAddressListKeepsEnabledEntry(t *testing.T) {
	mock, server := setupMockRouter()
	defer server.Close()
	client, err := NewClient(server.URL, "admin", "testpass", Options{})
	if err != nil {
		t.Fatal(err)
	}
	mock.set(func(m *mockRouterState) {
		m.addrLists = []map[string]interface{}{
			{".id": "*A1", "list": proxyAddressList, "address": testIP, "disabled": "true"},
			{".id": "*A2", "list": proxyAddressList, "address": testIP, "disabled": "false"},
		}
	})

	if err := client.EnsureProxyAddressList(context.Background(), testIP, testMAC); err != nil {
		t.Fatalf("EnsureProxyAddressList: %v", err)
	}
	if len(mock.patches) != 0 || len(entriesFor(mock, testIP)) != 2 {
		t.Fatalf("an enabled entry exists, nothing should change: patches=%v entries=%+v", mock.patches, mock.addrLists)
	}
}

func TestRemoveProxyAddressListDeletesDuplicates(t *testing.T) {
	mock, server := setupMockRouter()
	defer server.Close()
	client, err := NewClient(server.URL, "admin", "testpass", Options{})
	if err != nil {
		t.Fatal(err)
	}
	mock.set(func(m *mockRouterState) {
		m.addrLists = []map[string]interface{}{
			{".id": "*A1", "list": proxyAddressList, "address": testIP, "disabled": "false"},
			{".id": "*A2", "list": proxyAddressList, "address": testIP, "disabled": "true"},
			{".id": "*A3", "list": proxyAddressList, "address": "10.88.88.51", "disabled": "false"},
			{".id": "*A4", "list": "OTHER", "address": testIP, "disabled": "false"},
		}
		// A copy that vanished between the GET and the DELETE is not an error.
		m.failStatus["/ip/firewall/address-list/*A2"] = 404
	})

	if err := client.RemoveProxyAddressList(context.Background(), testIP); err != nil {
		t.Fatalf("RemoveProxyAddressList: %v", err)
	}
	if left := entriesFor(mock, testIP); len(left) != 1 || left[0][".id"] != "*A2" {
		t.Fatalf("expected only the vanished *A2 left in the mock, got %+v", left)
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	for _, e := range mock.addrLists {
		if e[".id"] == "*A3" || e[".id"] == "*A4" {
			continue
		}
		if e[".id"] != "*A2" {
			t.Fatalf("unexpected entry left: %+v", e)
		}
	}
	if len(mock.addrLists) != 3 {
		t.Fatalf("entries of other IPs or lists must stay, got %+v", mock.addrLists)
	}
}

func TestEnsureIPv6BlockRulesReplacesDisabledRule(t *testing.T) {
	mock, client, _ := newAssignedFixture(t)

	var oldID string
	mock.set(func(m *mockRouterState) {
		for _, r := range m.ipv6Rules {
			if r["comment"] == "proxy-dash-ipv6-fwd:"+testMAC {
				r["disabled"] = "true"
				oldID, _ = r[".id"].(string)
			}
		}
		m.adds = nil
	})
	if oldID == "" {
		t.Fatal("fixture has no forward rule")
	}

	if err := client.EnsureIPv6BlockRules(context.Background(), testMAC); err != nil {
		t.Fatalf("EnsureIPv6BlockRules: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.adds) != 1 || mock.adds[0]["chain"] != "forward" {
		t.Fatalf("expected one new forward rule, got %+v", mock.adds)
	}
	fwd := 0
	for _, r := range mock.ipv6Rules {
		if r[".id"] == oldID {
			t.Fatalf("disabled rule %s was not deleted", oldID)
		}
		if r["comment"] == "proxy-dash-ipv6-fwd:"+testMAC {
			fwd++
		}
	}
	if fwd != 1 {
		t.Fatalf("expected exactly one forward rule, got %d", fwd)
	}
}

func TestReconcileReenablesAndDeletesDuplicates(t *testing.T) {
	mock, client, st := newAssignedFixture(t)

	mock.set(func(m *mockRouterState) {
		for _, e := range m.addrLists {
			if e["address"] == testIP {
				e["disabled"] = "true"
			}
		}
		m.addrLists = append(m.addrLists,
			map[string]interface{}{".id": "*X1", "list": proxyAddressList, "address": "10.88.88.77", "disabled": "false"},
			map[string]interface{}{".id": "*X2", "list": proxyAddressList, "address": "10.88.88.77", "disabled": "true"},
		)
		m.patches = nil
	})

	if err := client.Reconcile(context.Background(), st); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	entries := entriesFor(mock, testIP)
	if len(entries) != 1 || isTrue(entries[0]["disabled"].(string)) {
		t.Fatalf("assigned device entry should be enabled again, got %+v", entries)
	}
	if left := entriesFor(mock, "10.88.88.77"); len(left) != 0 {
		t.Fatalf("every entry of an unassigned IP must be removed, got %+v", left)
	}
}
