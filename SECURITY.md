# Security Policy

MikroTik Proxy Dashboard changes firewall, routing and DHCP configuration on a
real router and decides whether a device's traffic can leave the network
without a proxy. Bugs here can expose a user's real IP address, so security
reports are taken seriously.

## Supported versions

Only the latest release and the `main` branch receive security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through GitHub:
**Security** tab of the repository, then **Report a vulnerability**
(GitHub private vulnerability reporting).

Include, if you can:

- What an attacker can do and from where (LAN device, dashboard user, upstream proxy, Internet).
- RouterOS version, router model, and the dashboard version or commit.
- Steps to reproduce, and whether it leaks the real IP, DNS queries or IPv6 traffic.
- Logs with secrets removed (passwords, proxy credentials, `session.key`, password hashes).

You can expect a first answer within 7 days. Once a fix is ready, the report is
credited in the release notes unless you prefer to stay anonymous.

## Scope

In scope:

- Any way for a device assigned to a proxy to reach the Internet directly
  (real IP, DNS, IPv6, WebRTC/UDP leaks) while every leak guard layer reports OK.
- Authentication bypass, session forgery, CSRF or XSS in the dashboard.
- Disclosure of proxy credentials or router credentials through the API, logs or UI.
- Changes on the router that go beyond the rules and leases the dashboard is documented to manage.

Out of scope:

- Attacks that require administrator access to the router or the container.
- The dashboard being reachable over plain HTTP from the LAN: this is a documented
  limitation, see [docs/security.md](docs/security.md).
- Apps that use their own DoH, VPN or hardcoded resolvers (documented limitation of layer L5).

The threat model and known weaknesses are described in [docs/security.md](docs/security.md).
