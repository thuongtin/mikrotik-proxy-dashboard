package mikrotik

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/i18n"
	"github.com/thuongtin/mikrotik-proxy-dashboard/internal/state"
)

// Layer status values. StatusUnknown means the router could not be asked, so
// the layer must not be shown as safe.
const (
	StatusOK      = "ok"
	StatusWarning = "warning"
	StatusError   = "error"
	StatusUnknown = "unknown"
)

// Overall status values derived from the layers.
const (
	OverallProtected   = "protected"
	OverallDegraded    = "degraded"
	OverallUnknown     = "unknown"
	OverallUnprotected = "unprotected"
)

const (
	proxyAddressList  = "PROXY_DEVICES"
	proxyRoutingTable = "via-proxy"
	killSwitchComment = "proxy-dash-killswitch"
	ipv6CommentPrefix = "proxy-dash-ipv6-"
	maxDetailLines    = 8
)

// LeakGuardLayer represents the status of one security layer.
type LeakGuardLayer struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "ok", "warning", "error", "unknown"
	Description string `json:"description"`
	Details     string `json:"details,omitempty"`
}

// LeakGuardStatus aggregates 6-layer protection telemetry.
type LeakGuardStatus struct {
	OverallStatus       string           `json:"overallStatus"` // "protected", "degraded", "unknown", "unprotected"
	RouterReachable     bool             `json:"routerReachable"`
	KillSwitchPackets   int64            `json:"killSwitchPackets"`
	KillSwitchBytes     int64            `json:"killSwitchBytes"`
	IPv6BlockedPackets  int64            `json:"ipv6BlockedPackets"`
	IPv6BlockedBytes    int64            `json:"ipv6BlockedBytes"`
	Layers              []LeakGuardLayer `json:"layers"`
	AssignedDeviceCount int              `json:"assignedDeviceCount"`
}

type routingTable struct {
	ID       string `json:".id"`
	Name     string `json:"name"`
	Fib      string `json:"fib"`
	Disabled string `json:"disabled"`
	Invalid  string `json:"invalid"`
}

type natRule struct {
	ID             string `json:".id"`
	Chain          string `json:"chain"`
	Action         string `json:"action"`
	DstPort        string `json:"dst-port"`
	Protocol       string `json:"protocol"`
	Comment        string `json:"comment"`
	Disabled       string `json:"disabled"`
	Invalid        string `json:"invalid"`
	SrcAddressList string `json:"src-address-list"`
	ToAddresses    string `json:"to-addresses"`
	ToPorts        string `json:"to-ports"`
}

type routingRule struct {
	ID          string `json:".id"`
	SrcAddress  string `json:"src-address"`
	Interface   string `json:"interface"`
	RoutingMark string `json:"routing-mark"`
	Table       string `json:"table"`
	Action      string `json:"action"`
	Disabled    string `json:"disabled"`
	Inactive    string `json:"inactive"`
}

type mangleRule struct {
	ID             string `json:".id"`
	Chain          string `json:"chain"`
	Action         string `json:"action"`
	NewRoutingMark string `json:"new-routing-mark"`
	SrcAddressList string `json:"src-address-list"`
	Disabled       string `json:"disabled"`
	Invalid        string `json:"invalid"`
}

// routerSnapshot is everything the LeakGuard checks read from RouterOS, with
// the error of each query kept so a failed read becomes "unknown", not "ok".
type routerSnapshot struct {
	tables    []routingTable
	tablesErr error
	rules     []routingRule
	rulesErr  error
	mangle    []mangleRule
	mangleErr error
	addrList  []addressListEntry
	addrErr   error
	v4Filters []ipFilterRule
	v4Err     error
	v6Filters []ipv6FilterRule
	v6Err     error
	nat       []natRule
	natErr    error
	leases    []dhcpLease
	leasesErr error
}

func isTrue(v string) bool {
	return v == "true" || v == "yes"
}

// routerAnswered reports whether err still proves the router is reachable:
// either the call worked or RouterOS itself returned an error status.
func routerAnswered(err error) bool {
	if err == nil {
		return true
	}
	var apiErr *APIError
	return errors.As(err, &apiErr)
}

func (c *Client) loadSnapshot(ctx context.Context, withDevices bool) (*routerSnapshot, bool) {
	snap := &routerSnapshot{}
	var wg sync.WaitGroup
	var errPtrs []*error

	fetch := func(path string, out interface{}, errp *error) {
		errPtrs = append(errPtrs, errp)
		wg.Add(1)
		go func() {
			defer wg.Done()
			*errp = c.Do(ctx, "GET", path, nil, out)
		}()
	}

	fetch("/routing/table", &snap.tables, &snap.tablesErr)
	fetch("/routing/rule", &snap.rules, &snap.rulesErr)
	fetch("/ip/firewall/mangle", &snap.mangle, &snap.mangleErr)
	fetch("/ip/firewall/filter", &snap.v4Filters, &snap.v4Err)
	fetch("/ipv6/firewall/filter", &snap.v6Filters, &snap.v6Err)
	fetch("/ip/firewall/nat", &snap.nat, &snap.natErr)
	if withDevices {
		fetch("/ip/firewall/address-list", &snap.addrList, &snap.addrErr)
		fetch("/ip/dhcp-server/lease", &snap.leases, &snap.leasesErr)
	}
	wg.Wait()

	reachable := false
	for _, errp := range errPtrs {
		if routerAnswered(*errp) {
			reachable = true
			break
		}
	}
	return snap, reachable
}

// GetLeakGuardStatus checks RouterOS rules and computes telemetry.
// It never reports a layer as "ok" when the data behind it could not be read.
// Descriptions and details are rendered with tr; a nil tr renders English.
// The result is built per call and never shared, so every caller gets its
// own language.
func (c *Client) GetLeakGuardStatus(ctx context.Context, st *state.State, engine EngineStatus, tr *i18n.Translator) (*LeakGuardStatus, error) {
	assigned := st.GetAssignedDevices()
	snap, reachable := c.loadSnapshot(ctx, len(assigned) > 0)

	status := &LeakGuardStatus{
		RouterReachable:     reachable,
		AssignedDeviceCount: len(assigned),
	}

	for _, f := range snap.v4Filters {
		if strings.Contains(f.Comment, killSwitchComment) {
			status.KillSwitchPackets += f.Packets
			status.KillSwitchBytes += f.Bytes
		}
	}
	for _, f := range snap.v6Filters {
		if strings.HasPrefix(f.Comment, ipv6CommentPrefix) {
			status.IPv6BlockedPackets += f.Packets
			status.IPv6BlockedBytes += f.Bytes
		}
	}

	status.Layers = []LeakGuardLayer{
		layerStaticBinding(tr, assigned, snap),
		layerPolicyRouting(tr, assigned, snap),
		layerKillSwitch(tr, snap, status.KillSwitchPackets, status.KillSwitchBytes),
		layerIPv6Block(tr, assigned, snap, status.IPv6BlockedPackets),
		layerDNSHijack(tr, snap),
		layerSingbox(tr, engine),
	}
	status.OverallStatus = overallStatus(status.Layers)

	return status, nil
}

func overallStatus(layers []LeakGuardLayer) string {
	hasUnknown, hasWarning := false, false
	for _, l := range layers {
		switch l.Status {
		case StatusOK:
		case StatusWarning:
			hasWarning = true
		case StatusUnknown:
			hasUnknown = true
		default:
			return OverallUnprotected
		}
	}
	switch {
	case hasUnknown:
		return OverallUnknown
	case hasWarning:
		return OverallDegraded
	default:
		return OverallProtected
	}
}

func joinDetails(tr *i18n.Translator, lines []string) string {
	if len(lines) > maxDetailLines {
		rest := len(lines) - maxDetailLines
		lines = append(append([]string{}, lines[:maxDetailLines]...), tr.T("leak.more_items", "count", rest))
	}
	return strings.Join(lines, "\n")
}

// unknownLayer reports a layer whose data could not be read. description is
// already translated; the raw errors are kept as details.
func unknownLayer(tr *i18n.Translator, name, description string, errs ...error) LeakGuardLayer {
	var lines []string
	for _, err := range errs {
		if err != nil {
			lines = append(lines, err.Error())
		}
	}
	return LeakGuardLayer{
		Name:        name,
		Status:      StatusUnknown,
		Description: description,
		Details:     joinDetails(tr, lines),
	}
}

// Layer 1: every assigned device must hold a static, enabled DHCP lease for
// its own MAC, otherwise the proxied IP can move to another machine.
func layerStaticBinding(tr *i18n.Translator, assigned []*state.DeviceConfig, snap *routerSnapshot) LeakGuardLayer {
	const name = "Layer 1: Static IP Binding"
	if len(assigned) == 0 {
		return LeakGuardLayer{Name: name, Status: StatusOK, Description: tr.T("leak.l1.none_assigned")}
	}
	if snap.leasesErr != nil {
		return unknownLayer(tr, name, tr.T("leak.l1.unknown"), snap.leasesErr)
	}

	var problems []string
	for _, d := range assigned {
		if p := leaseProblem(tr, d, snap.leases); p != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", d.IP, p))
		}
	}
	if len(problems) > 0 {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusError,
			Description: tr.T("leak.l1.unpinned", "count", len(problems), "total", len(assigned)),
			Details:     joinDetails(tr, problems),
		}
	}
	return LeakGuardLayer{
		Name:        name,
		Status:      StatusOK,
		Description: tr.T("leak.l1.ok", "count", len(assigned)),
	}
}

func leaseProblem(tr *i18n.Translator, d *state.DeviceConfig, leases []dhcpLease) string {
	if d.MAC == "" {
		return tr.T("leak.l1.no_mac")
	}
	problem := tr.T("leak.l1.no_lease")
	for _, l := range leases {
		if l.Address != d.IP {
			continue
		}
		switch {
		case !strings.EqualFold(l.MAC, d.MAC):
			problem = tr.T("leak.l1.lease_other_mac", "lease_mac", strings.ToLower(l.MAC), "mac", strings.ToLower(d.MAC))
		case isTrue(l.Disabled):
			problem = tr.T("leak.l1.lease_disabled")
		case isTrue(l.Dynamic):
			problem = tr.T("leak.l1.lease_dynamic")
		default:
			return ""
		}
	}
	return problem
}

// Layer 2: the routing table, a rule that looks only in it, something that
// sends proxied devices into it, and the devices being in the address-list.
func layerPolicyRouting(tr *i18n.Translator, assigned []*state.DeviceConfig, snap *routerSnapshot) LeakGuardLayer {
	const name = "Layer 2: Policy Routing Table"
	if snap.tablesErr != nil || snap.rulesErr != nil || snap.mangleErr != nil || (len(assigned) > 0 && snap.addrErr != nil) {
		return unknownLayer(tr, name, tr.T("leak.l2.unknown"), snap.tablesErr, snap.rulesErr, snap.mangleErr, snap.addrErr)
	}

	hasTable := false
	for _, t := range snap.tables {
		if t.Name == proxyRoutingTable && !isTrue(t.Disabled) && !isTrue(t.Invalid) {
			hasTable = true
			break
		}
	}
	if !hasTable {
		return LeakGuardLayer{Name: name, Status: StatusError, Description: tr.T("leak.l2.no_table")}
	}

	hasRule, strictRule, ruleSelects := false, false, false
	for _, r := range snap.rules {
		if r.Table != proxyRoutingTable || isTrue(r.Disabled) || isTrue(r.Inactive) {
			continue
		}
		hasRule = true
		if r.Action == "lookup-only-in-table" {
			strictRule = true
		}
		if r.SrcAddress != "" || r.Interface != "" {
			ruleSelects = true
		}
	}
	if !hasRule {
		return LeakGuardLayer{Name: name, Status: StatusError, Description: tr.T("leak.l2.no_rule")}
	}

	hasMark := false
	for _, m := range snap.mangle {
		if m.Action == "mark-routing" && m.NewRoutingMark == proxyRoutingTable && m.SrcAddressList == proxyAddressList && !isTrue(m.Disabled) && !isTrue(m.Invalid) {
			hasMark = true
			break
		}
	}
	if !hasMark && !ruleSelects {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusError,
			Description: tr.T("leak.l2.no_selector"),
			Details:     tr.T("leak.l2.no_selector_details"),
		}
	}

	var missing []string
	for _, d := range assigned {
		found := false
		for _, e := range snap.addrList {
			if e.List == proxyAddressList && e.Address == d.IP && !isTrue(e.Disabled) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, d.IP)
		}
	}
	if len(missing) > 0 {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusError,
			Description: tr.T("leak.l2.not_in_list", "count", len(missing)),
			Details:     joinDetails(tr, missing),
		}
	}

	if !strictRule {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusWarning,
			Description: tr.T("leak.l2.not_strict"),
			Details:     tr.T("leak.l2.not_strict_details"),
		}
	}
	return LeakGuardLayer{Name: name, Status: StatusOK, Description: tr.T("leak.l2.ok")}
}

// acceptsNewConnections reports whether a rule placed before a drop rule could
// let a brand new connection through. Rules limited to established traffic,
// NAT state or IPsec policy are ignored. This is a heuristic: it does not
// evaluate addresses or interfaces, so it can warn about a harmless rule.
func acceptsNewConnections(action, disabled, dynamic, invalid, connState, natState, ipsec string) bool {
	if isTrue(disabled) || isTrue(dynamic) || isTrue(invalid) {
		return false
	}
	if action != "accept" && action != "fasttrack-connection" {
		return false
	}
	if natState != "" || ipsec != "" {
		return false
	}
	if connState == "" {
		return true
	}
	negated := strings.HasPrefix(connState, "!")
	listsNew := false
	for _, s := range strings.Split(strings.TrimPrefix(connState, "!"), ",") {
		if strings.TrimSpace(s) == "new" {
			listsNew = true
			break
		}
	}
	return listsNew != negated
}

func ruleLabel(id, comment string) string {
	if comment != "" {
		return fmt.Sprintf("%s (%s)", id, comment)
	}
	return id
}

// Layer 3: the kill-switch is judged by what the rule does, not by its comment.
func layerKillSwitch(tr *i18n.Translator, snap *routerSnapshot, packets, bytes int64) LeakGuardLayer {
	const name = "Layer 3: RouterOS Kill-Switch"
	if snap.v4Err != nil {
		return unknownLayer(tr, name, tr.T("leak.l3.unknown"), snap.v4Err)
	}

	var firstProblems []string
	found := false
	for i, f := range snap.v4Filters {
		if !strings.Contains(f.Comment, killSwitchComment) {
			continue
		}
		var problems []string
		if isTrue(f.Disabled) {
			problems = append(problems, tr.T("leak.l3.rule_disabled"))
		}
		if isTrue(f.Invalid) {
			problems = append(problems, tr.T("leak.l3.rule_invalid"))
		}
		if f.Chain != "forward" {
			problems = append(problems, tr.T("leak.l3.wrong_chain", "chain", f.Chain))
		}
		if f.Action != "drop" && f.Action != "reject" {
			problems = append(problems, tr.T("leak.l3.wrong_action", "action", f.Action))
		}
		if f.SrcAddressList != proxyAddressList {
			problems = append(problems, tr.T("leak.l3.wrong_src_list", "list", f.SrcAddressList, "want", proxyAddressList))
		}
		if len(problems) > 0 {
			if !found {
				found = true
				firstProblems = problems
			}
			continue
		}

		// A working rule: check what could bypass or over-block it.
		var warnings []string
		if f.OutInterface == "" && f.OutInterfaceList == "" {
			warnings = append(warnings, tr.T("leak.l3.no_out_interface"))
		}
		var earlier []string
		for _, prev := range snap.v4Filters[:i] {
			if prev.Chain != "forward" || prev.SrcAddressList == "!"+proxyAddressList {
				continue
			}
			if acceptsNewConnections(prev.Action, prev.Disabled, prev.Dynamic, prev.Invalid, prev.ConnectionState, prev.ConnectionNatState, prev.IPsecPolicy) {
				earlier = append(earlier, ruleLabel(prev.ID, prev.Comment))
			}
		}
		if len(earlier) > 0 {
			warnings = append(warnings, tr.T("leak.l3.accept_before", "count", len(earlier), "rules", strings.Join(earlier, ", ")))
		}
		if len(warnings) > 0 {
			return LeakGuardLayer{
				Name:        name,
				Status:      StatusWarning,
				Description: tr.T("leak.l3.review"),
				Details:     joinDetails(tr, warnings),
			}
		}
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusOK,
			Description: tr.T("leak.l3.ok", "count", packets, "bytes", bytes),
		}
	}

	if found {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusError,
			Description: tr.T("leak.l3.ineffective"),
			Details:     joinDetails(tr, firstProblems),
		}
	}
	return LeakGuardLayer{
		Name:        name,
		Status:      StatusError,
		Description: tr.T("leak.l3.missing"),
	}
}

// Layer 4: each assigned MAC needs a working IPv6 block in forward and input.
func layerIPv6Block(tr *i18n.Translator, assigned []*state.DeviceConfig, snap *routerSnapshot, packets int64) LeakGuardLayer {
	const name = "Layer 4: IPv6 Hardware Block"
	if len(assigned) == 0 {
		return LeakGuardLayer{Name: name, Status: StatusOK, Description: tr.T("leak.l4.none_assigned")}
	}
	if snap.v6Err != nil {
		return unknownLayer(tr, name, tr.T("leak.l4.unknown"), snap.v6Err)
	}

	var problems, warnings []string
	for _, d := range assigned {
		if d.MAC == "" {
			problems = append(problems, tr.T("leak.l4.no_mac", "ip", d.IP))
			continue
		}
		mac := strings.ToLower(d.MAC)
		for _, want := range []struct{ chain, comment string }{
			{"forward", "proxy-dash-ipv6-fwd:" + mac},
			{"input", "proxy-dash-ipv6-in:" + mac},
		} {
			idx := -1
			for i, r := range snap.v6Filters {
				if r.Comment != want.comment {
					continue
				}
				if ipv6RuleBlocks(r, want.chain, mac) {
					idx = i
					break
				}
			}
			if idx == -1 {
				problems = append(problems, tr.T("leak.l4.rule_missing", "ip", d.IP, "mac", mac, "chain", want.chain))
				continue
			}
			for _, prev := range snap.v6Filters[:idx] {
				if prev.Chain != want.chain || strings.HasPrefix(prev.Comment, ipv6CommentPrefix) {
					continue
				}
				if acceptsNewConnections(prev.Action, prev.Disabled, prev.Dynamic, prev.Invalid, prev.ConnectionState, prev.ConnectionNatState, prev.IPsecPolicy) {
					warnings = append(warnings, tr.T("leak.l4.rule_shadowed", "ip", d.IP, "mac", mac, "chain", want.chain, "rule", ruleLabel(prev.ID, prev.Comment)))
					break
				}
			}
		}
	}

	if len(problems) > 0 {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusError,
			Description: tr.T("leak.l4.not_blocked"),
			Details:     joinDetails(tr, problems),
		}
	}
	if len(warnings) > 0 {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusWarning,
			Description: tr.T("leak.l4.not_first"),
			Details:     joinDetails(tr, warnings),
		}
	}
	return LeakGuardLayer{
		Name:        name,
		Status:      StatusOK,
		Description: tr.T("leak.l4.ok", "count", len(assigned), "packets", packets),
	}
}

// portListContains reports whether a RouterOS port list such as "53",
// "53,5353" or "50-60" covers port. A negated list never counts.
func portListContains(list string, port int) bool {
	if list == "" || strings.HasPrefix(list, "!") {
		return false
	}
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, isRange := strings.Cut(part, "-"); isRange {
			loN, err1 := strconv.Atoi(lo)
			hiN, err2 := strconv.Atoi(hi)
			if err1 == nil && err2 == nil && loN <= port && port <= hiN {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n == port {
			return true
		}
	}
	return false
}

// Layer 5: DNS on port 53 from proxied devices must be dst-nat'ed, for UDP
// and TCP, before any other NAT rule gets to take the same packets.
func layerDNSHijack(tr *i18n.Translator, snap *routerSnapshot) LeakGuardLayer {
	const name = "Layer 5: DNS Hijack & FakeIP"
	if snap.natErr != nil {
		return unknownLayer(tr, name, tr.T("leak.l5.unknown"), snap.natErr)
	}

	covered := map[string]bool{}
	var warnings []string
	for _, proto := range []string{"udp", "tcp"} {
		var shadowedBy string
		for _, n := range snap.nat {
			if n.Chain != "dstnat" || isTrue(n.Disabled) || isTrue(n.Invalid) || n.Protocol != proto || !portListContains(n.DstPort, 53) {
				continue
			}
			isHijack := n.Action == "dst-nat" && n.ToAddresses != "" && (n.SrcAddressList == "" || n.SrcAddressList == proxyAddressList)
			if isHijack {
				covered[proto] = true
				break
			}
			if shadowedBy == "" && n.SrcAddressList != "!"+proxyAddressList {
				shadowedBy = ruleLabel(n.ID, n.Comment)
			}
		}
		if covered[proto] && shadowedBy != "" {
			warnings = append(warnings, tr.T("leak.l5.shadowed", "rule", shadowedBy, "proto", proto))
		}
	}

	switch {
	case !covered["udp"] && !covered["tcp"]:
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusError,
			Description: tr.T("leak.l5.missing"),
		}
	case !covered["udp"]:
		warnings = append(warnings, tr.T("leak.l5.no_udp"))
	case !covered["tcp"]:
		warnings = append(warnings, tr.T("leak.l5.no_tcp"))
	}
	if len(warnings) > 0 {
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusWarning,
			Description: tr.T("leak.l5.partial"),
			Details:     joinDetails(tr, warnings),
		}
	}
	return LeakGuardLayer{
		Name:        name,
		Status:      StatusOK,
		Description: tr.T("leak.l5.ok"),
	}
}

// Forward guard states exported by entrypoint.sh as FORWARD_GUARD_STATUS.
const (
	ForwardGuardActive      = "active"
	ForwardGuardUnavailable = "unavailable"
	ForwardGuardOff         = "off"
)

// EngineStatus describes the container side of the leak protection.
type EngineStatus struct {
	SingboxRunning bool
	// ForwardGuard is one of the ForwardGuard* constants, or "" when the
	// entrypoint did not report anything.
	ForwardGuard string
}

func layerSingbox(tr *i18n.Translator, engine EngineStatus) LeakGuardLayer {
	const name = "Layer 6: sing-box Fail-Closed Engine"
	if !engine.SingboxRunning {
		layer := LeakGuardLayer{Name: name, Status: StatusError, Description: tr.T("leak.l6.stopped")}
		if engine.ForwardGuard == ForwardGuardActive {
			layer.Details = tr.T("leak.l6.stopped_guard_on")
		} else {
			layer.Details = tr.T("leak.l6.stopped_guard_off")
		}
		return layer
	}

	switch engine.ForwardGuard {
	case ForwardGuardActive:
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusOK,
			Description: tr.T("leak.l6.running"),
			Details:     tr.T("leak.l6.guard_active_details"),
		}
	case ForwardGuardOff:
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusWarning,
			Description: tr.T("leak.l6.guard_off"),
			Details:     tr.T("leak.l6.guard_off_details"),
		}
	case ForwardGuardUnavailable:
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusWarning,
			Description: tr.T("leak.l6.guard_unavailable"),
			Details:     tr.T("leak.l6.guard_unavailable_details"),
		}
	default:
		return LeakGuardLayer{
			Name:        name,
			Status:      StatusWarning,
			Description: tr.T("leak.l6.guard_unknown"),
			Details:     tr.T("leak.l6.guard_unknown_details"),
		}
	}
}

// Reconcile synchronizes state.json with the RouterOS address-list and IPv6
// filter rules. Every step that fails is reported; nothing is assumed applied.
func (c *Client) Reconcile(ctx context.Context, st *state.State) error {
	assigned := st.GetAssignedDevices()

	assignedIPs := make(map[string]string) // IP -> MAC
	assignedMACs := make(map[string]bool)
	for _, d := range assigned {
		assignedIPs[d.IP] = d.MAC
		if d.MAC != "" {
			assignedMACs[strings.ToLower(d.MAC)] = true
		}
	}

	// 1. Reconcile PROXY_DEVICES address-list
	var entries []addressListEntry
	if err := c.Do(ctx, "GET", "/ip/firewall/address-list", nil, &entries); err != nil {
		return fmt.Errorf("failed to query address-list: %w", err)
	}

	// A disabled entry does not route the device, so only enabled entries
	// count as present. Every entry, duplicates included, is a removal target.
	enabledInRouter := make(map[string]bool) // IP -> has an enabled entry
	entryIDs := make(map[string][]string)    // IP -> all entry IDs
	for _, e := range entries {
		if e.List != proxyAddressList {
			continue
		}
		entryIDs[e.Address] = append(entryIDs[e.Address], e.ID)
		if !isTrue(e.Disabled) {
			enabledInRouter[e.Address] = true
		}
	}

	var errs []error

	// Add missing to RouterOS
	for ip, mac := range assignedIPs {
		if !enabledInRouter[ip] {
			if err := c.EnsureProxyAddressList(ctx, ip, mac); err != nil {
				errs = append(errs, fmt.Errorf("address-list for %s: %w", ip, err))
			}
		}
		if mac == "" {
			errs = append(errs, fmt.Errorf("device %s has no MAC: IPv6 block cannot be enforced", ip))
			continue
		}
		if err := c.EnsureIPv6BlockRules(ctx, mac); err != nil {
			errs = append(errs, fmt.Errorf("IPv6 block for %s: %w", ip, err))
		}
	}

	// Remove unassigned from RouterOS
	for ip, ids := range entryIDs {
		if _, needed := assignedIPs[ip]; needed {
			continue
		}
		for _, id := range ids {
			err := c.Do(ctx, "DELETE", fmt.Sprintf("/ip/firewall/address-list/%s", id), nil, nil)
			if err != nil && !IsNotFound(err) {
				errs = append(errs, fmt.Errorf("failed to remove stale address-list entry %s: %w", ip, err))
			}
		}
	}

	// 2. Remove IPv6 block rules left behind for devices no longer assigned
	var v6Rules []ipv6FilterRule
	if err := c.Do(ctx, "GET", "/ipv6/firewall/filter", nil, &v6Rules); err != nil {
		errs = append(errs, fmt.Errorf("failed to query IPv6 firewall filter rules: %w", err))
	} else {
		for _, r := range v6Rules {
			if !strings.HasPrefix(r.Comment, ipv6CommentPrefix) {
				continue
			}
			_, mac, ok := strings.Cut(r.Comment, ":")
			if !ok || assignedMACs[strings.ToLower(mac)] {
				continue
			}
			err := c.Do(ctx, "DELETE", fmt.Sprintf("/ipv6/firewall/filter/%s", r.ID), nil, nil)
			if err != nil && !IsNotFound(err) {
				errs = append(errs, fmt.Errorf("failed to remove stale IPv6 rule %s: %w", r.Comment, err))
			}
		}
	}

	return errors.Join(errs...)
}
