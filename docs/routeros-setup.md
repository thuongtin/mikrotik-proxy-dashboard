**English** | [Tiếng Việt](vi/routeros-setup.md)

# RouterOS setup

First-time installation guide for RouterOS 7 with container support (used on an RB5009UG+S+ with RouterOS 7.25). The sample values below follow the default environment; change them to match your network.

The baseline rules in section 3 are taken from a working router configuration. Commands that have not been run on a real router are marked as such.

| Component | Sample value |
| :--- | :--- |
| LAN | `10.88.88.0/24`, gateway `10.88.88.1`, bridge `BridgeLAN` |
| Container bridge | `containers`, `10.10.10.0/24`, gateway `10.10.10.1` |
| Container | `10.10.10.16`, interface `veth-proxy` |
| Routing table | `via-proxy` |
| Address-list | `PROXY_DEVICES` |
| Data directory | `disk1/proxy-data` mounted at `/data` |

> **Before you start:** export the current configuration (`/export file=before-proxy-dash`) so you have a way back. Go step by step, and check that the LAN still works after each step.

## 1. Dedicated account for the dashboard

Do not use `admin`. Create a narrow permission group and an account that can only log in from the container address:

```routeros
/user/group add name=proxy-dash policy=read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon
/user add name=proxy-dash group=proxy-dash address=10.10.10.16/32 password="<separate-password>"
```

The policy set above is derived from reading the code (the dashboard only reads and writes through the REST API) and **has not been verified on a real router**. If the dashboard reports a permission error when assigning a device, check the RouterOS log to find the missing policy and add exactly that policy.

## 2. REST API over HTTPS

The dashboard calls `MIKROTIK_URL` (default `https://10.88.88.1`). Enable the `www-ssl` service with a certificate, and restrict which sources can reach it:

```routeros
/ip/service set www-ssl disabled=no certificate=<certificate-name> address=10.10.10.16/32,10.88.88.0/24
```

The `address` range must include the container address. The host in `MIKROTIK_URL` must be a router address reachable from the container (`10.88.88.1` or the container bridge gateway `10.10.10.1`), **and it must be in the certificate SAN**. Prefer `https://10.88.88.1`: router certificates are usually issued for the LAN address, and `10.10.10.1` is rarely in the SAN. The `10.88.88.0/24` range is in `EXCLUDE_CIDRS`, so connections to the router do not go through `tun0`, and the `proxy-dash:allow-router-api` firewall rule does not restrict the destination address.

### Certificate verification

By default the dashboard **verifies the router certificate**. With a self-signed certificate, two conditions must hold:

1. The certificate has a SAN that matches the host in `MIKROTIK_URL`. When connecting by IP, the SAN must contain `IP:<that address>`; a common name alone is not enough.
2. The dashboard has the PEM file of that certificate (or of the CA that signed it), configured through `MIKROTIK_CA_FILE`.

Create a self-signed certificate with the full SAN (skip this if the certificate in use already has the right SAN):

```routeros
/certificate add name=proxy-dash-tls common-name=10.88.88.1 subject-alt-name=IP:10.88.88.1,IP:10.10.10.1 key-usage=digital-signature,key-encipherment,tls-server days-valid=3650
/certificate sign proxy-dash-tls
/ip/service set www-ssl certificate=proxy-dash-tls
```

Export the public part of the certificate (without the private key) to a PEM file:

```routeros
/certificate export-certificate proxy-dash-tls file-name=router-ca
```

This creates `router-ca.crt` in Files. Copy that file into the container data directory as `router-ca.pem` (for example `disk1/proxy-data/router-ca.pem`), then set `MIKROTIK_CA_FILE=/data/router-ca.pem`. Do not set `export-passphrase`: with a passphrase, RouterOS also exports the private key, which must never leave the router.

If the dashboard cannot read the file, or the file contains no PEM certificate, it stops at startup and logs the reason. If the certificate has the wrong SAN, the dashboard runs but every router call fails, and the status page reports the layers as `unknown` (could not be checked).

`MIKROTIK_INSECURE_TLS=true` turns verification off entirely. Use it only temporarily while preparing the certificate; every container start logs a warning. See M4 in [security.md](security.md).

### When the account cannot export certificates

`/certificate export-certificate` requires the `sensitive` policy. An account without it gets the error `not enough permissions (9)`. In that case, take the CA from the TLS handshake, then check it against the router before trusting it:

```bash
openssl s_client -connect 10.88.88.1:443 -showcerts </dev/null 2>/dev/null > chain.txt
# The second certificate in chain.txt is the CA (subject = issuer, CA:TRUE); save it as router-ca.pem.
openssl x509 -in router-ca.pem -noout -serial -ext subjectKeyIdentifier
```

The serial and SKID must match `/certificate/print detail` on the router. Also check that the SKID really is the SHA-1 of the public key (RFC 5280, method 1), because the SKID is just a field in the certificate. Do not compare the RouterOS `fingerprint` field with `openssl x509 -fingerprint -sha256`: on RouterOS 7.25.1 the two values differ even for the same certificate. Finally, try `curl --cacert router-ca.pem https://10.88.88.1/rest/system/identity`: status 401 means TLS succeeded, curl exit code 60 means the certificate or SAN is wrong.

> This procedure was checked on RouterOS 7.25.1 with a `www-ssl` certificate signed by a local RouterOS CA; the router sends the CA in the chain. The `/certificate add` and `sign` commands above **have not been tested yet**.

## 3. Baseline rules (one-time)

### Routing table and default route via the container

```routeros
/routing/table add name=via-proxy fib
/ip/route add dst-address=0.0.0.0/0 gateway=10.10.10.16 routing-table=via-proxy
```

### Policy routing

Only traffic from devices in `PROXY_DEVICES` is sent to the `via-proxy` table. Device selection is done by mangle, because RouterOS `/routing/rule` cannot filter by address-list.

First, an address-list that groups the internal ranges devices still need to reach directly (printers, NAS, the dashboard itself):

```routeros
/ip/firewall/address-list add list=LAN address=10.88.88.0/24
/ip/firewall/address-list add list=LAN address=10.10.10.0/24
```

Four mangle rules, **in exactly this order**:

```routeros
/ip/firewall/mangle add chain=prerouting action=accept in-interface=BridgeLAN dst-address-list=LAN comment="proxy-dash:bypass-lan"
/ip/firewall/mangle add chain=prerouting action=accept protocol=udp dst-port=53 in-interface=BridgeLAN src-address-list=PROXY_DEVICES comment="proxy-dash:bypass-dns-udp"
/ip/firewall/mangle add chain=prerouting action=accept protocol=tcp dst-port=53 in-interface=BridgeLAN src-address-list=PROXY_DEVICES comment="proxy-dash:bypass-dns-tcp"
/ip/firewall/mangle add chain=prerouting action=mark-routing new-routing-mark=via-proxy passthrough=no src-address-list=PROXY_DEVICES in-interface=BridgeLAN dst-address-type=!local comment="proxy-dash:mark-routing"
```

- Rule 1 lets internal traffic flow as usual.
- Rules 2 and 3 keep DNS packets unmarked; the DNS hijack rules below redirect them to `sing-box`.
- Rule 4 marks everything else from assigned devices.

A routing rule forces marked packets to be looked up only in the `via-proxy` table:

```routeros
/routing/rule add action=lookup-only-in-table routing-mark=via-proxy table=via-proxy comment="proxy-dash:strict-table"
```

`lookup-only-in-table` is the key point: if the `via-proxy` table has no usable route (the route is disabled, deleted, or the container interface is gone), the packet is dropped instead of falling back to the `main` table. With `action=lookup`, packets fall back to `main` and go straight out the WAN; the dashboard reports a warning on layer L2 in that case.

Unassigned devices match none of the rules above and use the network as before.

### Kill-switch

```routeros
/ip/firewall/filter add chain=forward action=drop src-address-list=PROXY_DEVICES out-interface-list=WAN comment="proxy-dash-killswitch" place-before=1
```

Requirements:

- The `WAN` interface list must contain **every** path to the Internet (PPPoE, backup WAN, LTE). A missing path is an unprotected path.
- The rule must come before the established/related `accept` and fasttrack rules in the `forward` chain. Check with `/ip/firewall/filter print`.
- Keep the `proxy-dash-killswitch` comment unchanged. The dashboard finds the rule by this comment, then checks that the rule is enabled, in the `forward` chain, with action `drop` or `reject`, and `src-address-list=PROXY_DEVICES`. If the outgoing interface is missing, or an accept rule before it also accepts new connections, layer L3 reports a warning. The position check is a heuristic: a narrowly scoped accept rule (by port, by destination) can still trigger a false warning.
- If you use fasttrack, exclude `PROXY_DEVICES` from the fasttrack rule so packets from assigned devices always go through the firewall.

This is the most important layer: every time `sing-box` restarts, the kill-switch is what reliably stops packets from going straight out the WAN. The forward guard in the container ([section 7](#7-forward-guard-in-the-container)) is a second layer, but not every router can install it.

### DNS hijack

```routeros
/ip/firewall/nat add chain=dstnat action=dst-nat to-addresses=10.10.10.16 to-ports=53 protocol=udp src-address-list=PROXY_DEVICES dst-port=53 comment="proxy-dash:dns-hijack-udp"
/ip/firewall/nat add chain=dstnat action=dst-nat to-addresses=10.10.10.16 to-ports=53 protocol=tcp src-address-list=PROXY_DEVICES dst-port=53 comment="proxy-dash:dns-hijack-tcp"
```

## 4. Container

```routeros
/interface/veth add name=veth-proxy address=10.10.10.16/24 gateway=10.10.10.1
/interface/bridge/port add bridge=containers interface=veth-proxy

/container/envs add name=proxy_envs key=DASHBOARD_PASSWORD_HASH value="<bcrypt-hash>"
/container/envs add name=proxy_envs key=MIKROTIK_URL value="https://10.88.88.1"
/container/envs add name=proxy_envs key=MIKROTIK_USER value="proxy-dash"
/container/envs add name=proxy_envs key=MIKROTIK_PASS value="<separate-password>"
/container/envs add name=proxy_envs key=MIKROTIK_CA_FILE value="/data/router-ca.pem"
/container/envs add name=proxy_envs key=FORWARD_GUARD value="auto"

/container/mounts add name=proxy_data src=disk1/proxy-data dst=/data
/container/add file=disk1/proxy-gw-arm64.tar interface=veth-proxy envlist=proxy_envs mounts=proxy_data root-dir=disk1/proxy-gw start-on-boot=yes logging=yes
```

**Escape every `$` in the password hash.** A bcrypt hash looks like `$2a$10$` followed by 53 more characters. In the RouterOS terminal and in scripts, `$` inside a string starts a variable name: an unescaped hash is stored as an empty or truncated value, and no password will ever match. Write each `$` as `\$`:

```routeros
/container/envs add name=proxy_envs key=DASHBOARD_PASSWORD_HASH value="\$2a\$10\$<rest-of-the-hash>"
```

To escape a hash in one step, put it between the single quotes:

```bash
printf '%s\n' '<bcrypt-hash>' | sed 's/\$/\\$/g'
```

This applies only to the terminal and scripts. In Winbox or WebFig, paste the hash as it is, without backslashes. If you cannot sign in with the right password, run `/container/envs print where key=DASHBOARD_PASSWORD_HASH`: the value must start with `$2a$` and be 60 characters long.

Upload `dist/proxy-gw-arm64.tar` to `disk1/` and copy `router-ca.pem` into `disk1/proxy-data/` before running the last command. The full list of environment variables is in the [README](../README.md#configuration).

A note on secrets: values in `/container/envs` live in the router configuration and appear in `/export show-sensitive`. Do not paste these values into chats, tickets or committed files.

### Stopping the container

On `/container/stop`, RouterOS first reads `SigCgt` in `/proc/1/status` of the container. If PID 1 has no handler for SIGTERM, RouterOS logs `signal 15 (Terminated) not caught, kill immediately` and sends SIGKILL at once, without waiting for `stop-time`. That is why `entrypoint.sh` stays PID 1 with a shell `trap` and forwards the signal to proxy-dash: do not put `tini` or `dumb-init` in front of it, because they collect signals with `sigtimedwait`, which RouterOS counts as "not caught". `scripts/build-arm64-tar.sh` checks the SigCgt bit and a real `docker stop` before it accepts an image.

A clean stop logs `Shutting down gracefully...`, `proxy-dash exited cleanly` and `exited with status 0`. If the stop is cut short, raise the grace period:

```routeros
/container/set [find name=proxy-gw] stop-time=20s
```

Background: [tikoci/app-t3code#25](https://github.com/tikoci/app-t3code/issues/25).

## 5. Restrict who can open the dashboard

The dashboard serves plain HTTP on port 8080. Allow only admin machines to reach it:

```routeros
/ip/firewall/address-list add list=PROXY_ADMINS address=<admin-machine-ip>
/ip/firewall/filter add chain=forward action=drop dst-address=10.10.10.16 protocol=tcp dst-port=8080 src-address-list=!PROXY_ADMINS comment="proxy-dash:admin-only"
```

Place this rule before the established/related accept rule. Do not create a dst-nat from the WAN to port 8080.

## 6. Extra hardening (recommended)

A device that sets a different static IP on its own, or changes its MAC address, leaves `PROXY_DEVICES` and uses the network directly. To prevent this:

```routeros
/ip/dhcp-server set [find interface=BridgeLAN] add-arp=yes
/interface/bridge set BridgeLAN arp=reply-only
```

After these two commands, only devices that got their IP over DHCP can talk to the router. **Every device with a manually configured static IP (printers, cameras, NAS) loses connectivity** until you add a static ARP entry or move it to DHCP. List those devices before enabling this.

## 7. Forward guard in the container

At startup, `entrypoint.sh` installs a set of iptables rules inside the container itself: the `FORWARD` chain policy is DROP, and only packets entering or leaving through `tun0`, plus packets to the ranges in `EXCLUDE_CIDRS`, are allowed. As a result, while `sing-box` is stopped or restarting, the container does not forward device packets straight to the uplink.

The `FORWARD_GUARD` variable controls the behavior:

| Value | Behavior |
| :--- | :--- |
| `auto` (default) | Install the rules. If installation fails, log a warning and keep running |
| `enforce` | Install the rules. If installation fails, the container does not start |
| `off` | Do not touch iptables |

**Known RouterOS limitation.** The RouterOS kernel exposes only part of netfilter to containers. Users on the MikroTik forum have reported `iptables` not working inside containers, and MikroTik support has answered that iptables is not available to third-party code. The forward guard has been tested on Docker (a regular Linux kernel) and **has not been tested on RouterOS**. Therefore:

1. Always start with `FORWARD_GUARD=auto`.
2. Check the container log (`/log print where topics~"container"`). Look for one of these two lines:
   - `Forward guard active (...)`: installed successfully.
   - `WARNING: forward guard could NOT be installed`: the kernel refused.
3. On the dashboard, layer L6 passes when the guard is installed; it reports a warning when the guard could not be installed or is turned off.
4. Switch to `FORWARD_GUARD=enforce` only after you have seen the `active` line. Setting `enforce` on a router that does not support it keeps the container from starting.

A guard that cannot be installed does not mean you are exposed: the kill-switch from section 3 still blocks on the router side. It means you have one blocking layer instead of two, which makes running the full "Failure tests" checklist below even more important.

References (looked up in November 2026):

- [Tailscale container: iptables not working](https://forum.mikrotik.com/t/tailscale-container-iptables-not-working/172271)
- [RouterOS 7.24: privileged containers](https://forum.mikrotik.com/t/routeros-7-24-privileged-containers/272219)
- [Lack of TPROXY module in RouterOS kernel and Docker containers](https://forum.mikrotik.com/t/lack-of-tproxy-module-in-routeros-kernel-and-docker-containers/164452)
- [Feature request: nftables netdev ingress hook in containers](https://forum.mikrotik.com/t/feature-request-enable-nftables-netdev-family-ingress-hook-in-containers/272351)

## Post-install checks

On the router:

- [ ] `/routing/table print` shows `via-proxy`
- [ ] `/ip/route print where routing-table=via-proxy` shows the default route, active
- [ ] `/ip/firewall/mangle print where comment~"proxy-dash:"` shows all four rules, in the right order, with the `mark-routing` rule last
- [ ] `/routing/rule print where table=via-proxy` shows the `lookup-only-in-table` rule, not disabled
- [ ] `/ip/firewall/filter print where comment~"killswitch"` shows the rule, not disabled, before fasttrack
- [ ] `/ip/firewall/nat print where comment~"dns-hijack"` shows both the UDP and TCP rules
- [ ] `/container print` shows status `running`
- [ ] The container log has no TLS errors when calling the router, and has a forward guard line (`active` or a warning)

On the dashboard:

- [ ] The status page shows no layer in error or `unknown` (could not be checked)
- [ ] Layer L6 passes, or reports a warning whose reason is that the forward guard could not be installed

On a device with a proxy assigned:

- [ ] The IP shown at `ipleak.net` is the proxy exit IP
- [ ] `browserleaks.com/dns` shows no ISP DNS servers
- [ ] `browserleaks.com/webrtc` does not show the real WAN IP
- [ ] `test-ipv6.com` reports no IPv6

Failure tests:

- [ ] Stop the container (`/container stop`): the assigned device **loses connectivity** and does not fall back to going direct
- [ ] Start the container again: the device gets connectivity back through the proxy
- [ ] A device without a proxy keeps normal connectivity throughout

## Uninstall

First unassign every device in the dashboard, then:

```routeros
/container stop [find interface=veth-proxy]
/container remove [find interface=veth-proxy]
/ip/firewall/nat remove [find comment~"proxy-dash:dns-hijack"]
/ip/firewall/filter remove [find comment="proxy-dash-killswitch"]
/ip/firewall/filter remove [find comment="proxy-dash:admin-only"]
/ipv6/firewall/filter remove [find comment~"proxy-dash-ipv6-"]
/ip/firewall/address-list remove [find list=PROXY_DEVICES]
/ip/firewall/mangle remove [find comment~"proxy-dash:"]
/routing/rule remove [find comment="proxy-dash:strict-table"]
/ip/route remove [find routing-table=via-proxy]
/routing/table remove [find name=via-proxy]
/user remove proxy-dash
/user/group remove proxy-dash
```

DHCP leases that were converted to static stay as they are; change them back by hand if needed. The `LAN` address-list and the certificate are also kept, since other rules may be using them.
