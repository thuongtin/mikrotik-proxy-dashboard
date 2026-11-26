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

# proxy-dash reads both: features that open their own sockets bind them to
# VETH_IF so they skip tun0, and resolve names through CONTAINER_GW.
export VETH_IF CONTAINER_GW

# Target LAN CIDR
LAN_CIDR="${LAN_CIDR:-10.88.88.0/24}"

echo "[entrypoint] Uplink interface: $VETH_IF, Gateway: $CONTAINER_GW, LAN CIDR: $LAN_CIDR"

# Enable IPv4 forwarding for transparent routing
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# Disable strict reverse-path filtering so forwarded LAN packets entering tun0 are never dropped
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
if [ -n "$VETH_IF" ]; then
    sysctl -w "net.ipv4.conf.${VETH_IF}.rp_filter=0" 2>/dev/null || true
fi

# Add explicit route for LAN return traffic to preserve true device source IP without NAT
if [ -n "$LAN_CIDR" ] && [ -n "$CONTAINER_GW" ] && [ -n "$VETH_IF" ]; then
    echo "[entrypoint] Ensuring direct route for $LAN_CIDR via $CONTAINER_GW dev $VETH_IF"
    ip route replace "$LAN_CIDR" via "$CONTAINER_GW" dev "$VETH_IF" 2>/dev/null || \
    ip route add "$LAN_CIDR" via "$CONTAINER_GW" dev "$VETH_IF" 2>/dev/null || true
fi

# --- Forward guard (LeakGuard layer 6) ---------------------------------------
# A packet from a proxied device may only leave this container through tun0,
# which is sing-box. Without this guard, a stopped or crashed sing-box takes its
# routes with it and the kernel forwards the packet straight back to the router:
# a direct path to the internet whenever the RouterOS kill-switch is missing.
#
#   FORWARD_GUARD=auto     install the rules; warn and keep going if the kernel refuses
#   FORWARD_GUARD=enforce  install the rules; refuse to start if that fails
#   FORWARD_GUARD=off      leave iptables alone
#
# RouterOS only exposes part of netfilter to containers and does not document
# which part, so the result is checked and handed to the dashboard, which shows
# it on layer 6 instead of assuming the guard is there.
FORWARD_GUARD="${FORWARD_GUARD:-auto}"
TUN_IF="tun0"
EXCLUDE_CIDRS="${EXCLUDE_CIDRS:-10.88.88.0/24,10.10.10.0/24,10.77.77.0/24,192.168.0.0/16}"
export EXCLUDE_CIDRS

# install_forward_guard <iptables binary> <4|6>
install_forward_guard() {
    ipt="$1"
    family="$2"
    command -v "$ipt" >/dev/null 2>&1 || return 1

    # Policy first: if anything below fails, nothing is forwarded.
    "$ipt" -w 5 -P FORWARD DROP 2>/dev/null || return 1
    "$ipt" -w 5 -F FORWARD 2>/dev/null || return 1
    "$ipt" -w 5 -A FORWARD -o "$TUN_IF" -j ACCEPT 2>/dev/null || return 1
    "$ipt" -w 5 -A FORWARD -i "$TUN_IF" -j ACCEPT 2>/dev/null || return 1

    # Destinations in EXCLUDE_CIDRS never enter tun0 (sing-box route_exclude_address).
    # They are local networks the operator chose to reach directly.
    for cidr in $(echo "$EXCLUDE_CIDRS" | tr ',' ' '); do
        case "$cidr" in
            *:*) [ "$family" = "6" ] || continue ;;
            *)   [ "$family" = "4" ] || continue ;;
        esac
        if ! "$ipt" -w 5 -A FORWARD -d "$cidr" -j ACCEPT 2>/dev/null; then
            echo "[entrypoint] WARNING: forward guard skipped invalid EXCLUDE_CIDRS entry: $cidr" >&2
        fi
    done

    # Trust what the kernel reports, not the exit codes above.
    rules=$("$ipt" -w 5 -S FORWARD 2>/dev/null) || return 1
    echo "$rules" | grep -q -- "^-P FORWARD DROP" || return 1
    echo "$rules" | grep -q -- "-o $TUN_IF -j ACCEPT" || return 1
    echo "$rules" | grep -q -- "-i $TUN_IF -j ACCEPT" || return 1
    return 0
}

# remove_forward_guard <iptables binary>: back to the kernel default.
remove_forward_guard() {
    command -v "$1" >/dev/null 2>&1 || return 0
    "$1" -w 5 -F FORWARD 2>/dev/null || true
    "$1" -w 5 -P FORWARD ACCEPT 2>/dev/null || true
}

FORWARD_GUARD_STATUS="off"
case "$FORWARD_GUARD" in
    off)
        echo "[entrypoint] WARNING: FORWARD_GUARD=off, forwarded packets are not restricted to $TUN_IF" >&2
        ;;
    auto|enforce)
        FORWARD_GUARD_STATUS="unavailable"
        # Alpine's iptables is the nftables backend; older kernels only have the legacy one.
        for ipt in iptables iptables-legacy; do
            if install_forward_guard "$ipt" 4; then
                FORWARD_GUARD_STATUS="active"
                echo "[entrypoint] Forward guard active ($ipt): forwarding allowed only through $TUN_IF" >&2
                break
            fi
            remove_forward_guard "$ipt"
        done

        if [ "$FORWARD_GUARD_STATUS" = "active" ]; then
            # IPv6 is rejected by sing-box and blocked on the router; this is one more lock.
            # Best effort: the container may have no IPv6 netfilter at all.
            for ipt in ip6tables ip6tables-legacy; do
                if install_forward_guard "$ipt" 6; then
                    break
                fi
                remove_forward_guard "$ipt"
            done
        elif [ "$FORWARD_GUARD" = "enforce" ]; then
            echo "[entrypoint] FATAL: FORWARD_GUARD=enforce but the iptables FORWARD rules could not be installed" >&2
            exit 1
        else
            echo "[entrypoint] WARNING: forward guard could NOT be installed (iptables unavailable in this kernel or missing NET_ADMIN)." >&2
            echo "[entrypoint] WARNING: leak protection relies on the RouterOS kill-switch only. Set FORWARD_GUARD=enforce to refuse to start instead." >&2
        fi
        ;;
    *)
        echo "[entrypoint] FATAL: unknown FORWARD_GUARD value '$FORWARD_GUARD' (use auto, enforce or off)" >&2
        exit 1
        ;;
esac
export FORWARD_GUARD_STATUS

# Ensure persistent data directory exists
DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

# Pick the command: a known binary or any command passed as the first
# argument, otherwise proxy-dash with the arguments as its flags.
if [ "$1" = "sing-box" ]; then
    shift
    set -- /usr/local/bin/sing-box "$@"
elif [ "$1" = "proxy-dash" ]; then
    shift
    set -- /usr/local/bin/proxy-dash "$@"
elif [ "$#" -gt 0 ] && command -v "$1" >/dev/null 2>&1; then
    :
else
    set -- /usr/local/bin/proxy-dash "$@"
fi

# --- PID 1 -----------------------------------------------------------------
# This shell stays PID 1 instead of exec'ing the command, for two reasons:
#
# 1. RouterOS only sends the stop signal when PID 1 has a handler for it: it
#    reads SigCgt in /proc/1/status and, when the bit is clear, logs
#    "signal 15 (Terminated) not caught, kill immediately" and sends SIGKILL,
#    skipping stop-time. tini blocks signals and collects them with
#    sigtimedwait, so it counts as "not caught"; a shell trap is a real handler.
# 2. Processes orphaned inside the container (helpers the dashboard starts, ip) are
#    re-parented to PID 1. ash reaps every child while it waits, so they do
#    not pile up as zombies.
#
# Every stop-like signal is forwarded to the command as SIGTERM: proxy-dash
# handles SIGTERM, and a background job of a non-interactive shell starts with
# SIGINT and SIGQUIT ignored. Only the command itself is signalled: proxy-dash
# stops its own children, and a group-wide signal would race that shutdown.
set +e
child=""
stop_requested=""

forward_stop() {
    stop_requested=1
    if [ -n "$child" ]; then
        kill -TERM "$child" 2>/dev/null
    fi
}
trap forward_stop TERM INT HUP QUIT

# A background job of a non-interactive shell gets /dev/null as stdin; hand it
# the real one through fd 3 so `proxy-dash --hash-password` can read a pipe.
exec 3<&0
"$@" 0<&3 3<&- &
child=$!
exec 3<&-
# A signal that arrived before the command started is delivered now.
if [ -n "$stop_requested" ]; then
    kill -TERM "$child" 2>/dev/null
fi

# wait returns early (status > 128) whenever a trapped signal arrives, so keep
# waiting until the command has really exited.
while :; do
    wait "$child"
    status=$?
    kill -0 "$child" 2>/dev/null || break
done
exit "$status"
