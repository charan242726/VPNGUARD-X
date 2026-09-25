#!/usr/bin/env python3
"""Seeded application-shape generator for the isolated range only."""

from __future__ import annotations

import argparse
import ipaddress
import random
import socket
import subprocess
import time


ALLOWED_TARGETS = {
    ipaddress.ip_address("10.22.0.20"),
    ipaddress.ip_address("fd00:22::20"),
    ipaddress.ip_address("10.80.0.20"),
    ipaddress.ip_address("fd00:80::20"),
}


def _tcp(target: str, port: int, chunks: list[bytes], pauses: list[float] | None = None) -> None:
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect((target, port))
        for index, chunk in enumerate(chunks):
            connection.sendall(chunk)
            connection.recv(128)
            if pauses and index < len(pauses):
                time.sleep(pauses[index])


def _udp(target: str, port: int, sizes: list[int], pauses: list[float], rng: random.Random) -> None:
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        for size, pause in zip(sizes, pauses, strict=True):
            connection.sendto(rng.randbytes(size), (target, port))
            time.sleep(pause)


PROFILE_TO_LABEL = {
    "https_seeded": "WEB",
    "udp_video_seeded": "VIDEO",
    "udp_voip_seeded": "VOIP",
    "tcp_bulk_seeded": "BULK_FILE",
    "interactive_seeded": "INTERACTIVE_MESSAGING",
    "messaging_like_seeded": "INTERACTIVE_MESSAGING",
    "email_smtp_imap_seeded": "EMAIL",
    "icmp_seeded": "ICMP_CONTROL",
    "dns_burst_seeded": "UNKNOWN",
    "iot_telemetry_seeded": "UNKNOWN",
    "mixed_unknown_seeded": "UNKNOWN",
}


def generate(label: str, target: str, seed: int, *, profile: str | None = None) -> None:
    address = ipaddress.ip_address(target)
    if address not in ALLOWED_TARGETS:
        raise ValueError("traffic target must be the fixed isolated cyber-range server")
    selected_profile = profile or next(
        (name for name, expected_label in PROFILE_TO_LABEL.items() if expected_label == label),
        None,
    )
    if selected_profile not in PROFILE_TO_LABEL:
        raise ValueError(f"unsupported application profile: {selected_profile}")
    if PROFILE_TO_LABEL[selected_profile] != label:
        raise ValueError(f"profile {selected_profile} is not registered for label {label}")
    rng = random.Random(seed)
    if selected_profile == "https_seeded":
        requests = [f"GET /item/{rng.randrange(1000)} HTTP/1.1\r\nHost: range\r\n\r\n".encode() for _ in range(24)]
        _tcp(target, 8080, requests, [rng.uniform(0.03, 0.15) for _ in requests])
    elif selected_profile == "udp_video_seeded":
        sizes = [rng.randint(900, 1350) for _ in range(450)]
        _udp(target, 9000, sizes, [0.008] * len(sizes), rng)
    elif selected_profile == "udp_voip_seeded":
        sizes = [rng.randint(120, 240) for _ in range(300)]
        _udp(target, 9001, sizes, [0.02] * len(sizes), rng)
    elif selected_profile == "tcp_bulk_seeded":
        chunks = [rng.randbytes(16384) for _ in range(128)]
        _tcp(target, 9002, chunks)
    elif selected_profile == "interactive_seeded":
        chunks = [rng.randbytes(rng.randint(20, 220)) for _ in range(80)]
        _tcp(target, 9003, chunks, [rng.uniform(0.02, 0.3) for _ in chunks])
    elif selected_profile == "messaging_like_seeded":
        # Controlled shape proxy only: this is not WhatsApp traffic or a WhatsApp label.
        chunks = [rng.randbytes(rng.randint(24, 340)) for _ in range(96)]
        pauses = [rng.choice([rng.uniform(0.01, 0.12), rng.uniform(0.35, 1.1)]) for _ in chunks]
        _tcp(target, 9003, chunks, pauses)
    elif selected_profile == "email_smtp_imap_seeded":
        # Synthetic SMTP/IMAP-like lab exchange. No real mail addresses or content are used.
        smtp = [b"EHLO range.invalid\r\n", b"MAIL FROM:<sender@range.invalid>\r\n", b"RCPT TO:<receiver@range.invalid>\r\n", b"DATA\r\n"]
        smtp.extend([rng.randbytes(rng.randint(180, 900)) for _ in range(14)])
        smtp.append(b"\r\n.\r\nQUIT\r\n")
        _tcp(target, 9025, smtp, [rng.uniform(0.02, 0.14) for _ in smtp])
        imap = [b"a1 LOGIN demo demo\r\n", b"a2 SELECT INBOX\r\n", b"a3 FETCH 1:* (ENVELOPE)\r\n", b"a4 LOGOUT\r\n"]
        _tcp(target, 9143, imap, [rng.uniform(0.03, 0.18) for _ in imap])
    elif selected_profile == "icmp_seeded":
        command = ["ping", "-6" if ":" in target else "-4", "-c", "30", "-i", "0.05", target]
        subprocess.run(command, check=True, timeout=10)
    elif selected_profile == "dns_burst_seeded":
        sizes: list[int] = []
        pauses: list[float] = []
        for _ in range(18):
            burst = rng.randint(2, 7)
            sizes.extend(rng.randint(48, 180) for _ in range(burst))
            pauses.extend([rng.uniform(0.002, 0.015)] * burst)
            pauses[-1] = rng.uniform(0.15, 0.6)
        _udp(target, 9053, sizes, pauses, rng)
    elif selected_profile == "iot_telemetry_seeded":
        sizes = [rng.randint(36, 110) for _ in range(75)]
        _udp(target, 9053, sizes, [rng.uniform(0.08, 0.45) for _ in sizes], rng)
    elif selected_profile == "mixed_unknown_seeded":
        first_sizes = [rng.choice([64, 96, 512, 1024]) for _ in range(60)]
        _udp(target, 9053, first_sizes, [rng.uniform(0.004, 0.08) for _ in first_sizes], rng)
        chunks = [rng.randbytes(rng.randint(300, 4000)) for _ in range(12)]
        _tcp(target, 9003, chunks, [rng.uniform(0.01, 0.12) for _ in chunks])
    else:
        raise AssertionError("registered profile has no generator")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--class", dest="label", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--profile", choices=sorted(PROFILE_TO_LABEL))
    args = parser.parse_args()
    generate(args.label, args.target, args.seed, profile=args.profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
