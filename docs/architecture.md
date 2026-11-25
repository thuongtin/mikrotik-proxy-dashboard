**English** | [Tiếng Việt](vi/architecture.md)

# Architecture

## Overview

A single Go binary (`proxy-dash`) runs in a container alongside `sing-box`:

- `proxy-dash` serves the dashboard and REST API on port 8080, stores state in `/data/state.json`, calls the RouterOS REST API to add and remove rules, generates the `sing-box` configuration, and supervises that process.
- `sing-box` receives the traffic the router steers into the container, picks an outbound based on the source IP, and answers DNS.

The only dependency outside the standard library is `golang.org/x/crypto` (used for bcrypt only). The frontend is plain HTML, CSS and JavaScript, embedded into the binary with `embed`.

## Directory layout

| Path | Role |
| :--- | :--- |
| `main.go` | Entry point: loads configuration, wires up components, handles the `--hash-password` and `--version` flags |
| `internal/config` | Reads environment variables, defaults |
| `internal/auth` | bcrypt login, HMAC-SHA256 signed session cookie, failed-login limiter (5 failures within 60 seconds locks out for 5 minutes) |
| `internal/state` | Stores proxies and device assignments in `state.json`, with atomic writes |
| `internal/proxy` | Proxy model, URI parser, conversion to `sing-box` outbounds, proxy testing |
| `internal/singbox` | Generates `sing-box.json`, supervises the process (start, stop, automatic restart 3 seconds after it dies) |
| `internal/mikrotik` | RouterOS REST client: DHCP leases, ARP, address-lists, IPv6 firewall, connection tracking, LeakGuard status |
| `internal/web` | HTTP handlers, API routing, static file serving |
| `web/dist` | Plain frontend with no build step: `index.html` (page shell and SVG sprite), `theme.js` (applies the light/dark theme before first paint), `app.js` (builds the DOM with `textContent`, never `innerHTML`), `style.css`. Runs under a CSP that blocks inline scripts and external resources |
| `entrypoint.sh` | Prepares networking inside the container (enables `ip_forward`, disables `rp_filter`, adds the route back to the LAN, installs the forward guard), then runs `proxy-dash` |
| `Dockerfile`, `scripts/build-arm64-tar.sh` | Build the `linux/arm64` image and package it as a tar file for RouterOS |

## Assigning a proxy to a device

`PUT /api/devices/{ip}/assignment` with body `{mac, nickname, proxyId}`:

1. Validate input: the IP is inside `LAN_CIDR`, the MAC is a valid 48-bit address (required), the nickname is not too long and contains no control characters, the proxy exists. On failure the API returns 400 or 404 before touching the router.
2. Convert the device's DHCP lease to static (layer L1). Step `lease`.
3. Add the IP to the `PROXY_DEVICES` address-list. From this point the router steers the device's traffic into the container, and the kill-switch and DNS hijack apply. Step `address-list`.
4. Add two IPv6 reject rules matching the MAC, in the `forward` and `input` chains, with comments `proxy-dash-ipv6-fwd:<mac>` and `proxy-dash-ipv6-in:<mac>` (layer L4). Step `ipv6`.
5. Save the assignment to `state.json`. Step `state`.
6. Regenerate `sing-box.json`, run `sing-box check`, then restart `sing-box`. Step `singbox`.
7. Remove the device's open connections from connection tracking to force them onto the new path. Step `flush`.

Write operations run sequentially, one at a time (the `opMu` lock).

**When a step fails:** the API returns HTTP 500 with body `{error, step, applied}`. `step` is the name of the failed step. `applied=false` means the change did not take effect: the steps already applied on the router are removed and the previous assignment in state is restored; if the rollback itself fails, `error` states what was left behind. `applied=true` means the assignment is in effect but the final cleanup step failed (for example, old connections could not be cut).

**Unassigning** (`DELETE`) runs in this order: remove from `PROXY_DEVICES`, remove the IPv6 rules (on failure, the address-list entry is re-added so the device is not left half-configured), delete the assignment from state, reload `sing-box`, cut connections. From the state deletion step onward, errors are reported with `applied=true`.

This is not a real transaction: if the router connection drops in the middle of a rollback, the router and state can still diverge. The **Re-sync router** button (`POST /api/system/reconcile`) brings the router back in line with state.

## Generated sing-box configuration

**Inbounds**

- `tun0`: address `172.19.0.1/30`, MTU 1400, `auto_route`, `mixed` stack, excludes the ranges in `EXCLUDE_CIDRS`.
- `dns-in`: listens on `0.0.0.0:53`, receives the DNS traffic the router redirects.

**DNS**

- `dns-bootstrap`: UDP to `CONTAINER_GW`, used only to resolve proxy server hostnames.
- `dns-fakeip`: returns fake addresses from `198.18.0.0/15`.
- `dns-doh-<id>`: DoH to `1.1.1.1`, sent through the corresponding proxy outbound.
- Rules: reject `AAAA`, `HTTPS`, `SVCB`; `A` queries from assigned devices get a FakeIP with a 1 second TTL (the sing-box default of 600 seconds left a device unable to load sites for minutes after it was switched back to direct, because its DNS cache still held unroutable FakeIP addresses); other queries go over DoH through the device's proxy; everything else is rejected.

**Route**

1. Sniff the protocol, hijack DNS.
2. Reject IPv6.
3. Per source IP: if the proxy does not support UDP, reject UDP; otherwise use outbound `proxy-<id>`.
4. Reject private destination addresses.
5. Reject everything else. There is no direct outbound for device traffic.

## API

Every endpoint under `/api`, except login, requires a session cookie.

| Method | Path | Action |
| :--- | :--- | :--- |
| POST | `/api/auth/login` | Log in, body `{password}` |
| POST | `/api/auth/logout` | Log out |
| GET | `/api/auth/me` | Check the session |
| GET | `/api/devices` | List LAN devices with their assignment status |
| PUT | `/api/devices/{ip}/assignment` | Assign a proxy, body `{mac, nickname, proxyId}` |
| DELETE | `/api/devices/{ip}/assignment` | Unassign |
| PUT | `/api/devices/{ip}/nickname` | Set the nickname, body `{nickname}` |
| POST | `/api/devices/{ip}/flush` | Cut the device's open connections |
| GET | `/api/proxies` | List proxies, without passwords or UUIDs |
| POST | `/api/proxies` | Add a proxy; the server generates the ID |
| POST | `/api/proxies/import` | Add multiple proxies from text, body `{text, defaultProto}` |
| GET, PUT, DELETE | `/api/proxies/{id}` | View, edit, delete a proxy; deleting an assigned proxy returns 409 |
| POST | `/api/proxies/{id}/test` | Test a proxy |
| GET | `/api/system/status` | Status of the six layers and `sing-box` |
| POST | `/api/system/reconcile` | Resync router rules from state and reload `sing-box` |
| POST | `/api/system/flush-all` | Cut connections for every assigned device |
| GET | `/api/system/logs` | Recent `sing-box` logs |

General conventions:

- A wrong method returns 405 with an `Allow` header. Bodies larger than 1 MiB are rejected.
- Returned proxies carry `hasPassword` and `hasUuid` instead of the real values. On `PUT`, an empty password or UUID means keep the existing value (as long as the protocol does not change).
- Deleting an assigned proxy returns 409 with `{error, devices}`.
- A failed multi-step operation returns 500 with `{error, step, applied}` as described above.
- `sing-box` only carries proxies that have devices assigned, so adding, importing or deleting an unassigned proxy does not restart `sing-box`.
- `/api/system/status` returns each layer with status `ok`, `warning`, `error` or `unknown`, and an overall status of `protected`, `degraded`, `unknown` or `unprotected`.

The UI does not yet offer proxy editing, although the API supports `PUT`.

## Data in `/data`

| File | Contents | Sensitive |
| :--- | :--- | :--- |
| `state.json` | Proxy list (including passwords, UUIDs), device assignments, latest test results | Yes |
| `session.key` | Session cookie signing key, generated on first run | Yes |
| `sing-box.json` | Generated `sing-box` configuration, contains proxy credentials | Yes |
| `cache.db` | `sing-box` FakeIP cache | No |
| `router-ca.pem` (optional) | Router CA certificate, if `MIKROTIK_CA_FILE` points here | No |

Backing up `state.json` and `session.key` is enough to rebuild. Deleting `session.key` invalidates every existing login session.

## What the dashboard owns on the router

The dashboard only creates and deletes the following items, identified by their comments:

- Entries in the `PROXY_DEVICES` address-list, comment `proxy-dash:<mac>`
- `/ipv6/firewall/filter` rules whose comment starts with `proxy-dash-ipv6-`
- The static flag on the DHCP leases of assigned devices

The routing table, routing rule, mangle rules, kill-switch and DNS NAT are created by hand by the administrator; the dashboard only reads them to report status. The **Re-sync router** button only changes the three kinds of items above: it adds missing items and removes stale address-list entries and orphaned IPv6 rules.

Inside the container, `entrypoint.sh` also owns the forward guard iptables rules (the `FORWARD` chain); they disappear when the container stops.
