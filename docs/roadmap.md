**English** | [Tiếng Việt](vi/roadmap.md)

# Roadmap

Roadmap proposed after the 2026-11-25 review. Phase 1 was fixed in code on 2026-11-25; phases 2 and 3 are still plans. Codes in parentheses (H1, M2...) refer to [security.md](security.md).

## Phase 1: fix weaknesses

Goal: what the dashboard reports must match reality, and the admin session must not be hijackable.

**Status: fixed in code, not yet validated on a real router.** Deploying requires rebuilding the image and loading it onto the router. The forward guard has only been tested on a Docker kernel, not on the RouterOS kernel.

| Task | Addresses | Status |
| :--- | :--- | :--- |
| Escape every dynamic value in the frontend, validate `exitIp` and `countryCode` in the backend, add a CSP | H1 | Done. The first lookup still goes over `http://ip-api.com` |
| Take the client IP from `RemoteAddr` | H2 | Done |
| Check the kill-switch by rule attributes and position | H3 | Done. The position check is a heuristic and can raise false warnings |
| In-container rule: drop forwarded packets that do not leave through `tun0` | H3 | Done in `entrypoint.sh`, the image adds `iptables-legacy`. On RouterOS it may fall back to `unavailable`, in which case layer L6 reports a warning |
| Block deleting an assigned proxy | M2 | Done. The API returns 409 with the list of devices |
| Return real errors on assign, unassign and `sing-box` reload | M7 | Done. With rollback and reporting of the failed step |
| Really check all six layers; tighten port matching in L5; add an "unknown" (could not be checked) status | M1 | Done |
| Hide proxy passwords in API responses | M6 | Done |
| Body size limit, security headers, method checks, MAC and nickname validation, server-generated proxy IDs | L1 to L4 | Done |
| Add `MIKROTIK_CA_FILE`, switch the default to certificate verification | M4 | Done. Breaking change: existing deployments must provide a CA. The default account is still `admin` |
| Pin image versions, upgrade `x/crypto`, run `govulncheck` in the build | L7 | Done. upx and running as root remain |

Remaining work before phase 1 is fully done:

- Deploy to a real router and confirm the six layers report correctly against the running configuration.
- Confirm the forward guard installs on the RouterOS kernel, or record that it cannot.
- Provide the router CA and check that the certificate SAN matches the host in `MIKROTIK_URL`.

## Phase 2: reliable operation

Goal: detect and fix drift without someone watching.

- **Watchdog:** check the six layers periodically, compare state with the router, automatically fix what the dashboard owns, record what it cannot fix. (M3)
- **Automatic baseline setup:** a "Set up router" button that creates the routing table, kill-switch and DNS NAT with a preview of the changes, instead of typing them by hand. This also resolves the routing rule issue. (M8)
- **Scheduled proxy tests:** re-measure on a schedule, keep latency history, flag dead proxies.
- **Audit log:** who logged in, what was assigned, when, success or failure.
- **Revocable sessions:** list open sessions, remote logout, change the password from the UI. (M5)
- **Edit proxies in the UI:** the API exists, only the form is missing.
- **Backup and restore:** export and import `state.json`, encrypted with a password.
- **MAC change warnings:** detect randomized MACs and MAC changes on assigned IPs. (H4)
- **Less disruptive config reloads:** adding, importing and deleting unassigned proxies no longer restarts `sing-box` (done in phase 1). Remaining: skip the reload when the generated configuration has not changed; consider splitting processes per device group.
- **HTTPS for the dashboard:** a pre-generated self-signed certificate or a user-provided certificate. (M5)

## Phase 3: feature expansion

Ordered by estimated value relative to effort.

| Feature | Description | Depends on |
| :--- | :--- | :--- |
| Proxy groups and automatic failover | Assign a device to a group; when a proxy dies, switch automatically to another proxy in the group (`sing-box` `urltest`, `selector`) | Scheduled proxy tests |
| Device groups | Assign once for a whole group (for example "Work phones") | |
| Notifications | Telegram or webhook when a proxy dies, a protection layer drifts, or an unusual login happens | Watchdog |
| Traffic statistics | Volume and connection count per device, per proxy | `sing-box` statistics API |
| Import from a subscription URL | Automatically update the proxy list from a provider | Strict input validation (see H1) |
| Domain-based routing | Some domains go through a different proxy or are blocked (rule-set) | |
| Configurable DoH | Choose the DoH server per proxy | L9 |
| Assignment schedules | Turn a device's proxy on and off by time of day | |
| Multiple accounts, two-factor authentication | View and edit permissions; TOTP | Revocable sessions |
| IPv6 through the proxy | Instead of blocking it outright, route IPv6 through proxies that support it | Requires redesigning L4 |

## Principles for new features

- On failure, cut the network; never fall back to going direct.
- Every protection layer must have a matching automated check; if it cannot be checked yet, the UI must say so.
- Data coming from proxies, the router and users is all treated as untrusted when displayed.
- Write operations on the router must be logged and must have a way to roll back.
