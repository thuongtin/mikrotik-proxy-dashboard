#!/bin/sh
set -e

# Detect container uplink interface (RouterOS 7.20.7+ names it after the veth interface, e.g. veth-proxy)
if [ -z "$VETH_IF" ]; then
    VETH_IF=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1)
    if [ -z "$VETH_IF" ]; then
        VETH_IF="eth0"
    fi
fi

# Detect gateway
if [ -z "$CONTAINER_GW" ]; then
    CONTAINER_GW=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -n 1)
    if [ -z "$CONTAINER_GW" ]; then
        CONTAINER_GW="10.10.10.1"
    fi
fi

# Target LAN CIDR
LAN_CIDR="${LAN_CIDR:-10.88.88.0/24}"

echo "[entrypoint] Uplink interface: $VETH_IF, Gateway: $CONTAINER_GW, LAN CIDR: $LAN_CIDR"

# Enable IPv4 forwarding for transparent routing
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# Add explicit route for LAN return traffic to preserve true device source IP without NAT
if [ -n "$LAN_CIDR" ] && [ -n "$CONTAINER_GW" ] && [ -n "$VETH_IF" ]; then
    echo "[entrypoint] Ensuring direct route for $LAN_CIDR via $CONTAINER_GW dev $VETH_IF"
    ip route replace "$LAN_CIDR" via "$CONTAINER_GW" dev "$VETH_IF" 2>/dev/null || \
    ip route add "$LAN_CIDR" via "$CONTAINER_GW" dev "$VETH_IF" 2>/dev/null || true
fi

# Ensure persistent data directory exists
DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

# If a custom binary or command is passed as first argument, execute it
if [ "$#" -gt 0 ]; then
    if [ "$1" = "sing-box" ]; then
        shift
        exec /usr/local/bin/sing-box "$@"
    elif [ "$1" = "proxy-dash" ]; then
        shift
        exec /usr/local/bin/proxy-dash "$@"
    elif command -v "$1" >/dev/null 2>&1; then
        exec "$@"
    fi
fi

# Execute application
exec /usr/local/bin/proxy-dash "$@"
