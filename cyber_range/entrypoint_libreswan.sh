#!/bin/sh
set -eu

role="${VGX_ROLE:-utility}"

if [ "$role" = "libreswan_gateway" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || true
    if [ ! -f /var/lib/ipsec/nss/cert9.db ]; then
        ipsec initnss >/scenario/libreswan-initnss.log 2>&1
    fi
    ipsec start >/scenario/libreswan-start.log 2>&1
    attempts=0
    until ipsec status >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "$attempts" -gt 100 ]; then
            echo "Libreswan pluto did not become ready" >&2
            exit 1
        fi
        sleep 0.1
    done
elif [ "$role" = "right_server" ]; then
    ip route replace 10.11.0.0/24 via 10.22.0.1
fi

exec "$@"
