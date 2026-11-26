#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
# DIST_DIR and IMAGE_TAG can be overridden to build a trial image without
# replacing the released one.
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
OUTPUT_TAR="$DIST_DIR/proxy-gw-arm64.tar"
IMAGE_TAG="${IMAGE_TAG:-proxy-gw:arm64}"

# EDITION picks a build flavour. "public" (the default) builds this repository
# as published. Any other value loads scripts/editions/<EDITION>.env, which can
# set GO_BUILD_TAGS (Go build tags), EXTRA_APK_PACKAGES (runtime Alpine
# packages) and EDITION_CHECK_CMD (a command the image must run successfully).
EDITION="${EDITION:-public}"
GO_BUILD_TAGS=""
EXTRA_APK_PACKAGES=""
EDITION_CHECK_CMD=""
if [ "$EDITION" != "public" ]; then
    EDITION_FILE="$SCRIPT_DIR/editions/$EDITION.env"
    if [ ! -f "$EDITION_FILE" ]; then
        echo "[build] ERROR: unknown edition '$EDITION' ($EDITION_FILE not found)" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    . "$EDITION_FILE"
fi
EDITION_ARGS=(
    --build-arg "GO_BUILD_TAGS=$GO_BUILD_TAGS"
    --build-arg "EXTRA_APK_PACKAGES=$EXTRA_APK_PACKAGES"
)

echo "=== Building mikrotik-proxy-dashboard ARM64 Container (edition: $EDITION) ==="

# 1. Ensure OrbStack daemon is running
if command -v orb >/dev/null 2>&1; then
    echo "[build] Checking OrbStack status..."
    orb start 2>/dev/null || true
fi

# 2. Static checks, tests and vulnerability scan. They run in the Dockerfile's
#    "check" stage, so they use the same pinned Go toolchain and sing-box binary
#    as the release build. SKIP_CHECKS=1 skips this step; SKIP_VULNCHECK=1 skips
#    only govulncheck (it needs network access to vuln.go.dev).
if [ "${SKIP_CHECKS:-0}" = "1" ]; then
    echo "[check] WARNING: SKIP_CHECKS=1, building without vet, tests and govulncheck" >&2
else
    echo "[check] Running go vet, go test and govulncheck (Dockerfile stage: check)..."
    # --no-cache-filter: a cached result must never stand in for a fresh scan.
    docker build \
        --platform linux/arm64 \
        --target check \
        --no-cache-filter check \
        --build-arg "SKIP_VULNCHECK=${SKIP_VULNCHECK:-0}" \
        "${EDITION_ARGS[@]}" \
        --progress plain \
        "$ROOT_DIR"
fi

# 3. Prepare output directory
mkdir -p "$DIST_DIR"
rm -f "$OUTPUT_TAR"

# 4. Build linux/arm64 Docker image
echo "[build] Building Docker image for linux/arm64..."
docker build \
    --platform linux/arm64 \
    "${EDITION_ARGS[@]}" \
    -t "$IMAGE_TAG" \
    "$ROOT_DIR"

# 5. Export container image to .tar archive
echo "[build] Saving image to $OUTPUT_TAR..."
docker save "$IMAGE_TAG" -o "$OUTPUT_TAR"

# 6. Measure and display exact size
FILE_SIZE_BYTES=$(stat -f "%z" "$OUTPUT_TAR" 2>/dev/null || stat -c "%s" "$OUTPUT_TAR" 2>/dev/null)
FILE_SIZE_MIB=$(awk "BEGIN {printf \"%.2f\", $FILE_SIZE_BYTES / 1048576}")

echo "=========================================================="
echo "SUCCESS: Built $OUTPUT_TAR"
echo "Image Tag: $IMAGE_TAG"
echo "File Size: ${FILE_SIZE_MIB} MiB (${FILE_SIZE_BYTES} bytes)"
echo "=========================================================="

# 7. Verification test inside built container
echo "[verify] Testing sing-box version in container..."
docker run --rm --platform linux/arm64 "$IMAGE_TAG" sing-box version

echo "[verify] Testing forward guard rules (needs NET_ADMIN, as on the router)..."
GUARD_RULES=$(docker run --rm --platform linux/arm64 --cap-add NET_ADMIN -e FORWARD_GUARD=enforce "$IMAGE_TAG" iptables -S FORWARD)
echo "$GUARD_RULES"
echo "$GUARD_RULES" | grep -q -- "^-P FORWARD DROP" || { echo "[verify] ERROR: FORWARD policy is not DROP" >&2; exit 1; }
echo "$GUARD_RULES" | grep -q -- "-o tun0 -j ACCEPT" || { echo "[verify] ERROR: tun0 accept rule missing" >&2; exit 1; }

echo "[verify] Testing proxy-dash version in container..."
docker run --rm --platform linux/arm64 "$IMAGE_TAG" proxy-dash --version

if [ -n "$EDITION_CHECK_CMD" ]; then
    echo "[verify] Testing edition '$EDITION': $EDITION_CHECK_CMD"
    # shellcheck disable=SC2086
    docker run --rm --platform linux/arm64 "$IMAGE_TAG" $EDITION_CHECK_CMD
fi

echo "[verify] Testing proxy-dash --hash-password..."
HASH_OUTPUT=$(echo "AdminTest123" | docker run --rm -i --platform linux/arm64 "$IMAGE_TAG" proxy-dash --hash-password)
echo "Generated hash test: $HASH_OUTPUT"
[ -n "$HASH_OUTPUT" ] || { echo "[verify] ERROR: --hash-password printed nothing (stdin not passed through?)" >&2; exit 1; }

# RouterOS sends the stop signal only when PID 1 has a handler for SIGTERM
# (bit 15 of SigCgt, mask 0x4000); otherwise it logs "signal 15 (Terminated)
# not caught, kill immediately" and sends SIGKILL without waiting for stop-time.
echo "[verify] Testing that PID 1 catches SIGTERM..."
# The entrypoint logs to stdout too, so keep only the last line and make sure
# it is a hex mask before doing arithmetic on it.
SIGCGT=$(docker run --rm --platform linux/arm64 "$IMAGE_TAG" sh -c 'awk "/^SigCgt:/ {print \$2}" /proc/1/status' 2>/dev/null | tail -n 1)
echo "PID 1 SigCgt: $SIGCGT"
if ! printf '%s' "$SIGCGT" | grep -Eq '^[0-9a-fA-F]{1,16}$'; then
    echo "[verify] ERROR: could not read SigCgt of PID 1 (got '$SIGCGT')" >&2
    exit 1
fi
if [ $(( 0x$SIGCGT & 0x4000 )) -eq 0 ]; then
    echo "[verify] ERROR: PID 1 does not catch SIGTERM; RouterOS would SIGKILL the container on stop" >&2
    exit 1
fi

echo "[verify] Testing graceful stop (docker stop must deliver SIGTERM to the command)..."
STOP_CID=$(docker run -d --platform linux/arm64 "$IMAGE_TAG" \
    sh -c 'trap "echo child got SIGTERM; exit 0" TERM; while :; do sleep 0.2; done')
sleep 2
docker stop -t 10 "$STOP_CID" >/dev/null
STOP_CODE=$(docker inspect -f '{{.State.ExitCode}}' "$STOP_CID")
STOP_LOG=$(docker logs "$STOP_CID" 2>&1)
docker rm "$STOP_CID" >/dev/null
if [ "$STOP_CODE" != "0" ] || ! echo "$STOP_LOG" | grep -q "child got SIGTERM"; then
    echo "$STOP_LOG" >&2
    echo "[verify] ERROR: graceful stop failed (exit code $STOP_CODE)" >&2
    exit 1
fi
echo "Graceful stop verified (exit code 0)"

echo "[verify] Testing that PID 1 reaps orphaned processes..."
ZOMBIES=$(docker run --rm --platform linux/arm64 "$IMAGE_TAG" \
    sh -c '(sleep 0.3 &); sleep 2; grep -l "^State:[[:space:]]*Z" /proc/[0-9]*/status 2>/dev/null | wc -l')
ZOMBIES=$(echo "$ZOMBIES" | tail -n 1 | tr -d '[:space:]')
if [ "$ZOMBIES" != "0" ]; then
    echo "[verify] ERROR: $ZOMBIES zombie process(es) left behind; PID 1 is not reaping orphans" >&2
    exit 1
fi
echo "No zombies left"

echo "[verify] Testing sample sing-box.json config with sing-box check in container..."
SAMPLE_CFG='{
  "log": { "level": "warn" },
  "dns": {
    "servers": [
      { "tag": "dns-bootstrap", "type": "udp", "server": "10.10.10.1", "server_port": 53 },
      { "tag": "dns-fakeip", "type": "fakeip", "inet4_range": "198.18.0.0/15" },
      { "tag": "dns-doh-p1", "type": "https", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "proxy-p-vless" }
    ],
    "rules": [
      { "query_type": ["AAAA", "HTTPS", "SVCB"], "action": "reject" },
      { "source_ip_cidr": ["10.88.88.50/32"], "query_type": ["A"], "action": "route", "server": "dns-fakeip" },
      { "source_ip_cidr": ["10.88.88.50/32"], "action": "route", "server": "dns-doh-p1" },
      { "action": "reject" }
    ],
    "final": "dns-bootstrap",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "mtu": 1400,
      "auto_route": true,
      "strict_route": false,
      "stack": "mixed",
      "route_exclude_address": ["10.88.88.0/24", "10.10.10.0/24", "192.168.0.0/16"]
    },
    { "type": "direct", "tag": "dns-in", "listen": "0.0.0.0", "listen_port": 53 }
  ],
  "outbounds": [
    { "type": "http", "tag": "proxy-p-http", "server": "1.2.3.4", "server_port": 8080 },
    { "type": "socks", "tag": "proxy-p-socks", "server": "1.2.3.4", "server_port": 1080 },
    { "type": "shadowsocks", "tag": "proxy-p-ss", "server": "1.2.3.4", "server_port": 8388, "method": "aes-256-gcm", "password": "pass" },
    { "type": "trojan", "tag": "proxy-p-trojan", "server": "trojan.com", "server_port": 443, "password": "pass", "tls": {"enabled": true, "server_name": "trojan.com"} },
    {
      "type": "vless",
      "tag": "proxy-p-vless",
      "server": "vless.com",
      "server_port": 443,
      "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "tls": {
        "enabled": true,
        "server_name": "vless.com",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": "q6X_z88QxH98Y64aV_2G_m5l44B8H8wU1d6v9320eQo", "short_id": "0123456789abcdef"}
      }
    },
    {
      "type": "vmess",
      "tag": "proxy-p-vmess",
      "server": "vmess.com",
      "server_port": 443,
      "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "alter_id": 0,
      "security": "auto",
      "tls": {"enabled": true, "server_name": "vmess.com"}
    },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-bootstrap",
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "port": 53, "action": "hijack-dns" },
      { "ip_version": 6, "action": "reject" },
      { "source_ip_cidr": ["10.88.88.50/32"], "network": "udp", "action": "reject", "method": "default", "no_drop": true },
      { "source_ip_cidr": ["10.88.88.50/32"], "action": "route", "outbound": "proxy-p-vless" },
      { "ip_is_private": true, "action": "reject" },
      { "action": "reject" }
    ]
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "/data/cache.db",
      "store_fakeip": true
    }
  }
}'

echo "$SAMPLE_CFG" | docker run --rm -i --platform linux/arm64 "$IMAGE_TAG" sh -c '
cat > /tmp/check.json
sing-box check -c /tmp/check.json
rm -f /tmp/check.json
'
echo "sing-box check exit code 0 verified inside container!"

echo "[verify] All verification checks completed successfully!"
