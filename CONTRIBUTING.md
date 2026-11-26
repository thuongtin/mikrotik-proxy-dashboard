# Contributing

Thanks for taking the time to help. This project manages firewall and routing
rules on real routers, so changes are reviewed with safety first: a feature
that can leak a device's real IP will not be merged, however useful it is.

## Before you start

- For a bug, open an issue with your RouterOS version, router model, what you
  expected and what happened. Remove passwords, proxy links and hashes from logs.
- For a security problem, do **not** open an issue: follow [SECURITY.md](SECURITY.md).
- For a larger feature, open an issue first so the design can be agreed on.
  [docs/roadmap.md](docs/roadmap.md) lists what is already planned.

## Development setup

Requirements: Go (see `go.mod`), a `sing-box` binary in `PATH` for the tests,
Node.js for the frontend checks, and Docker with `buildx` to build the ARM64 image.

```bash
go vet ./...
```

```bash
go test ./...
```

```bash
node scripts/check-i18n.mjs
```

```bash
./scripts/build-arm64-tar.sh
```

The build script runs vet, tests and `govulncheck` inside the pinned toolchain
before it builds `dist/proxy-gw-arm64.tar`.

Code layout and the API are described in [docs/architecture.md](docs/architecture.md).

### Docker labs on macOS: never reuse your real LAN subnet

When you build a Docker lab that imitates the router (for example a fake LAN
network for end-to-end tests of device routing), give it a subnet that does not
overlap the LAN your Mac is on. Docker Desktop and OrbStack on macOS create their
networks through Apple's vmnet, which adds each subnet to the pf table
`network_isolation_table_v4` in the anchor
`com.apple.internet-sharing/network_isolation`. That anchor holds a rule
`block drop quick inet from <table> to <table>`, so once your real LAN subnet is
in the table, every IP packet between the Mac and the LAN is dropped: the router
stops answering ping, SSH and HTTP, while internet access and ARP still work.
Removing the Docker network does not always remove the entry.

Check the table:

```bash
sudo pfctl -a com.apple.internet-sharing/network_isolation -t network_isolation_table_v4 -T show
```

Remove a stale entry (replace the CIDR with yours):

```bash
sudo pfctl -a com.apple.internet-sharing/network_isolation -t network_isolation_table_v4 -T delete 192.168.88.0/24
```

Only delete entries that no running Docker network still uses.

## Pull requests

- Keep each pull request focused on one change.
- Add or update tests for backend changes. Leak guard logic
  (`internal/mikrotik/status.go`) and rule management must stay fail-closed:
  when something cannot be verified, report it as unknown or error, never OK.
- Run `gofmt`, `go vet ./...` and `go test ./...` before pushing.
- Code, identifiers, comments and log messages are written in English.
- Do not use the em dash character in code, docs or translations.

## Translations

The dashboard and API messages are available in English (default), Vietnamese,
Simplified Chinese, Russian and Korean. Every language has two flat JSON files:

| File | Contains |
| :--- | :--- |
| `web/dist/locales/<code>.json` | Dashboard UI text |
| `internal/i18n/locales/<code>.json` | Messages returned by the API (errors, leak guard results) |

`en.json` is the source of truth. To fix a translation, edit the matching key
in the other language file. Rules:

- Keep every `{placeholder}` exactly as it is in English.
- Plural forms use the suffixes `_one`, `_few`, `_many`, `_other`
  (CLDR categories). Provide the forms your language needs; `_other` is required.
- Do not translate product and protocol names: Proxy Gateway, RouterOS,
  sing-box, VLESS, VMess, Trojan, Shadowsocks, SOCKS5, IPv6, DNS, FakeIP, DoH.
- A missing key falls back to English, so a partial translation is still useful.

To add a new language, add both JSON files, register the code in
`web/dist/i18n.js` and `internal/i18n`, add the option to the language menu,
and run `node scripts/check-i18n.mjs` and `go test ./internal/i18n/`.

README translations live next to `README.md` (`README.<code>.md`). Keep the
language links at the top of every README in sync.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
