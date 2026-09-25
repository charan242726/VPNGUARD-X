#!/bin/sh
set -eu

role="${VGX_ROLE:-utility}"

if [ "$role" = "gateway" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || true
    charon_bin="$(command -v charon 2>/dev/null || true)"
    if [ -z "$charon_bin" ]; then
        for candidate in /usr/libexec/ipsec/charon /usr/lib/ipsec/charon; do
            if [ -x "$candidate" ]; then charon_bin="$candidate"; break; fi
        done
    fi
    if [ -z "$charon_bin" ]; then
        echo "charon binary not found" >&2
        exit 1
    fi
    "$charon_bin" &
    attempts=0
    while [ ! -S /var/run/charon.vici ] && [ ! -S /run/charon.vici ]; do
        attempts=$((attempts + 1))
        if [ "$attempts" -gt 100 ]; then echo "VICI socket did not appear" >&2; exit 1; fi
        sleep 0.1
    done
elif [ "$role" = "nat_router" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
    transit_iface="$(ip -o -4 addr show | awk '$4 ~ /^10\.80\.0\.1\// {print $2; exit}')"
    if [ -z "$transit_iface" ]; then echo "NAT transit interface not found" >&2; exit 1; fi
    iptables -t nat -A POSTROUTING -s 10.81.0.0/24 -o "$transit_iface" -j MASQUERADE
    iptables -A FORWARD -s 10.81.0.0/24 -j ACCEPT
    iptables -A FORWARD -d 10.81.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
elif [ "$role" = "left_client" ]; then
    ip route replace 10.22.0.0/24 via 10.11.0.1
    ip -6 route replace fd00:22::/64 via fd00:11::1 || true
elif [ "$role" = "right_server" ]; then
    ip route replace 10.11.0.0/24 via 10.22.0.1
    ip -6 route replace fd00:11::/64 via fd00:22::1 || true
fi

exec "$@"
