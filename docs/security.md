**English** | [Tiếng Việt](vi/security.md)

# Security

This document describes the threat model, the weaknesses found in the 2026-11-25 code review, and the work needed to harden the system.

**Review scope:** all Go code, the frontend, the Dockerfile, the entrypoint and the README. A running RouterOS 7.25.1 configuration was also compared read-only: filter, NAT, mangle, routing rules, routing tables, address-lists and IP services.

**Status:** phase 1 was fixed in code on 2026-11-25. Each item below is marked **Fixed**, **Partially fixed** or **Open**. Checks run: `go vet`, `go test` (7 packages), `staticcheck`, `govulncheck` (no vulnerabilities when built with Go 1.27.4, the image toolchain).

**Not yet verified on real hardware:** the fixes have not been deployed to a router yet. The in-container forward guard in particular has only been tested on a Docker kernel, not on the RouterOS kernel (see H3).

## Threat model

Assets to protect:

1. The real IP of devices with a proxy assigned (must not leak over IPv4, IPv6, DNS or WebRTC).
2. Proxy credentials (passwords, UUIDs) stored in `state.json`.
3. Control of the router: the dashboard holds a RouterOS account with write access.

Who can attack:

| Actor | Capability |
| :--- | :--- |
| Proxy provider | Sees and can modify all unencrypted traffic through their proxy, including while the dashboard tests the proxy |
| LAN devices | Can send requests to the dashboard, sniff HTTP on the same network, change their own IP or MAC |
| User of an assigned device | Wants to escape the proxy and use the network directly |
| Websites the device visits | Probe for the real IP through WebRTC, DNS, IPv6 |

Out of scope: an attacker who already controls the router, physical attacks, bugs in `sing-box` or RouterOS.

## Known weaknesses

### High

**H1. Stored XSS through proxy test results. Fixed, with a small remainder.**
Previously `app.js` inserted `exitIp`, `countryCode` and the MAC into `innerHTML` without escaping, while the first two values came from `http://ip-api.com` through the very proxy being tested. A malicious proxy could inject script into the admin session.
*Done:* the frontend builds the whole DOM with `createElement` and `textContent`, and nothing assigns `innerHTML` from API data any more (`web/dist/app.js`); the backend only accepts an `exitIp` that is a valid IP and a `countryCode` of exactly two letters, and other labels are truncated and stripped of control characters (`internal/proxy/sanitize.go`); a Content-Security-Policy that forbids inline scripts was added (`internal/web/handler.go`).
*Remaining:* the first lookup still calls `http://ip-api.com` (the free tier has no HTTPS), so a proxy provider can still fake the displayed country and ISP. Fake data can no longer run script; it is only wrong information.

**H2. Bypassing the failed-login limit with spoofed headers. Fixed.**
The client IP now comes from `RemoteAddr` (`GetClientIP` in `internal/auth/auth.go`); `X-Forwarded-For` and `X-Real-IP` are ignored. If the dashboard is later placed behind a reverse proxy, every client will share one IP, and a trusted proxy list setting will be needed.

**H3. The kill-switch was only checked by comment, and the container did not block forwarding itself. Fixed in code, not verified on RouterOS.**
*Done, dashboard side:* layer L3 finds the rule by the comment `proxy-dash-killswitch`, then checks each attribute: not disabled, not invalid, `chain=forward`, `action` is `drop` or `reject`, `src-address-list=PROXY_DEVICES`. If `out-interface` or `out-interface-list` is missing, or an accept rule before it could let new connections through, it reports a warning (`layerKillSwitch` in `internal/mikrotik/status.go`).
*Done, container side:* `entrypoint.sh` installs the forward guard: the FORWARD policy is DROP, and only packets leaving through `tun0`, entering from `tun0`, or destined for `EXCLUDE_CIDRS` are allowed. When `sing-box` stops, `tun0` disappears and every forwarded packet is dropped inside the container.
*Known limits:*
- RouterOS exposes only part of netfilter to containers, so the guard may fail to install. In that case the container keeps running (`auto` mode), the log prints a warning, layer L6 reports a warning and the overall status is `degraded`. The kill-switch on the router remains the primary blocking layer. Details and sources are in [routeros-setup.md](routeros-setup.md#7-forward-guard-in-the-container).
- The kill-switch position check is a heuristic: it ignores accept rules limited to established and related connections, and rules that exclude `PROXY_DEVICES`, but it does not evaluate addresses or interfaces. A harmless accept rule placed before it can still cause a false warning.

**H4. A device can escape the proxy by changing its IP or MAC. Open (phase 2).**
The whole mechanism relies on the source IP being in `PROXY_DEVICES` and on IPv6 rules matching the MAC. A device that sets a different static IP inside the LAN, or a phone with randomized MAC enabled, no longer matches any rule and uses the network directly.
*Planned fix:* enable `add-arp=yes` and `arp=reply-only` (see [routeros-setup.md](routeros-setup.md#6-extra-hardening-recommended)); the dashboard warns when the MAC of an assigned IP changes or is randomized (locally administered bit).

### Medium

**M1. LeakGuard status was wrong. Fixed.**
All six layers are now really checked (`internal/mikrotik/status.go`):

| Layer | Condition to pass |
| :--- | :--- |
| L1 | Every assigned device has a DHCP lease with the right IP and MAC, not disabled, not dynamic |
| L2 | The `via-proxy` table exists; an enabled routing rule points to it; a `mark-routing` mangle rule on `PROXY_DEVICES` exists, or a routing rule with a source; every assigned device is in `PROXY_DEVICES` |
| L3 | See H3 |
| L4 | Every assigned MAC has both IPv6 rules (`forward` and `input`), with the right MAC, action drop or reject, not placed after an accept rule |
| L5 | A `dst-nat` rule exists for both UDP and TCP, its `dst-port` covers port 53 exactly (port lists and ranges are understood), and no other NAT rule catches port 53 first |
| L6 | `sing-box` is running and the forward guard is `active` |

A layer that cannot be read from the router is reported as `unknown` (could not be checked) instead of passing. The overall status has four values: `protected`, `degraded`, `unknown`, `unprotected`.

**M2. Deleting a proxy cut devices off while the UI said otherwise. Fixed.**
An assigned proxy can no longer be deleted: the API returns 409 with the list of devices, and the UI asks you to unassign the devices or move them to another proxy first (`handleProxyDelete`, `DeleteProxy`).

**M3. No periodic monitoring. Open (phase 2).**
`Reconcile` now reports every error, adds missing rules, removes stale address-list entries and cleans up orphaned IPv6 rules, but it still only runs at startup and when the **Re-sync router** button is pressed. If someone edits the firewall on the router, the dashboard only finds out when someone opens the status page.
*Planned fix:* a periodic watchdog that records drift and automatically fixes what the dashboard owns.

**M4. The router connection did not verify the certificate and used the admin account. Partially fixed.**
*Done:* certificate verification is now the default. `MIKROTIK_CA_FILE` accepts the PEM file of the CA or of the self-signed certificate itself. `MIKROTIK_INSECURE_TLS=true` remains for temporary use, and logs a warning at every start.
*Breaking change:* existing deployments that set neither variable cannot reach the router after upgrading until they set `MIKROTIK_CA_FILE` or temporarily set `MIKROTIK_INSECURE_TLS=true` again. The router certificate must have a SAN that matches the host in `MIKROTIK_URL`.
*Remaining:* `MIKROTIK_USER` still defaults to `admin`; using a narrow-permission account is so far only a recommendation in [routeros-setup.md](routeros-setup.md).

**M5. The dashboard uses plain HTTP and sessions cannot be revoked. Open (phase 2).**
The password and cookie travel in cleartext on the LAN. The cookie has no `Secure` flag. A session is a self-signed token valid for 24 hours; logging out or changing the password does not invalidate tokens already issued.
*Planned fix:* TLS support; server-side session storage so sessions can be revoked; changing the password revokes every session.

**M6. The API returned proxy passwords to the browser. Fixed.**
`/api/proxies` responses no longer contain passwords or UUIDs, only `hasPassword` and `hasUuid`. When editing a proxy, leaving these two fields empty keeps the existing values. The secrets are still stored in cleartext in `state.json` and `sing-box.json` on disk.

**M7. Errors were swallowed. Fixed.**
Assign, unassign, `sing-box` reload and reconcile all return real errors. Multi-step operations return `{error, step, applied}`: `step` is the failed step, `applied` says whether the change is in effect or was rolled back. When an assignment fails partway, the steps already applied on the router are removed; if the rollback itself fails, the message says so.

**M8. The routing rule in the old guide applied to the whole LAN range. Docs fixed; automatic setup still open (phase 2).**
[routeros-setup.md](routeros-setup.md#policy-routing) was rewritten to use a `mark-routing` mangle rule only for `PROXY_DEVICES`, together with a routing rule on `routing-mark`. The dashboard still does not create these baseline rules itself.

### Low

- **L1. Fixed.** Request bodies are limited to 1 MiB; there is a CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- **L2. Fixed.** Every endpoint checks the method and returns 405 with an `Allow` header on mismatch.
- **L3. Fixed.** The MAC must be a valid 48-bit address; nicknames are length-limited and must not contain control characters. Assigning a device requires a MAC.
- **L4. Fixed.** Proxy IDs are generated by the server; client-supplied IDs are ignored.
- **L5. Open.** The gateway is identified with `strings.HasSuffix(ip, ".1")` (`handler.go`, `devices.go`) instead of comparing against the real gateway address. If the LAN gateway does not end in `.1`, a proxy can still be assigned to the gateway itself.
- **L6. Partially fixed.** RouterOS responses are now read with a size limit and errors have their own type (`APIError`). Error messages returned to the UI still contain the RouterOS error text.
- **L7. Partially fixed.** The three base images are pinned by version and digest; `golang.org/x/crypto` is at v0.59.0; `govulncheck`, `go vet` and `go test` run in the build. Remaining: the binary is still compressed with upx, and the process still runs as root (required for TUN and iptables).
- **L8. Open.** The login limiter never prunes old entries; `stopLocked` in the supervisor releases the lock midway; the proxy tester picks a free port and only then uses it (a race window); every operation loads whole tables from the router and filters them on the client side.
- **L9. Open.** DoH is fixed to `1.1.1.1` and cannot be changed.

Note on `govulncheck`: the clean result is for Go 1.27.4 in the build image. Go 1.26.4 has standard library vulnerabilities (fixed in 1.26.5 and 1.26.6), so do not ship binaries built outside Docker with that Go version.

## Deployment checklist

- [ ] Build the image with `scripts/build-arm64-tar.sh` and load it onto the router; images built before these fixes do not contain them
- [ ] Export the router certificate (or CA), place it in `/data`, set `MIKROTIK_CA_FILE`; check that the SAN matches the host in `MIKROTIK_URL`
- [ ] Once the container is running, check the log to see whether the forward guard is `active` or `unavailable`; set `FORWARD_GUARD=enforce` only after you have seen `active`
- [ ] Open the status page and fix every layer that is not passing
- [ ] Create a dedicated RouterOS account with narrow permissions, restricted to the container address
- [ ] Restrict access to port 8080 to admin machines only
- [ ] Enable `add-arp=yes` and `arp=reply-only` after listing the devices with static IPs
- [ ] Turn off randomized MAC on phones and computers with a proxy assigned
- [ ] After every assignment, run a leak test on that device
- [ ] Use a long dashboard password that is not reused anywhere else

Remaining code work: H4, M3, M5, the automatic setup part of M8, then L5, L8, L9. The phased plan is in [roadmap.md](roadmap.md).

## Reporting security issues

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md); do not open a public issue. Include the file, line, reproduction steps and impact. Do not attach `state.json`, environment variable values or router configuration exports that contain secrets.
