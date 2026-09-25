#!/usr/bin/env python3
"""Small TCP/UDP sinks for deterministic cyber-range traffic."""

from __future__ import annotations

import socket
import threading


def tcp_server(port: int) -> None:
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("::", port))
    server.listen(16)
    while True:
        connection, _ = server.accept()
        threading.Thread(target=handle_tcp, args=(connection, port), daemon=True).start()


def handle_tcp(connection: socket.socket, port: int) -> None:
    with connection:
        while True:
            data = connection.recv(65536)
            if not data:
                return
            if port == 8080:
                body = b"vpnguard-x-range"
                reply = b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: keep-alive\r\n\r\n" + body
            else:
                reply = b"OK"
            connection.sendall(reply)


def udp_server(port: int) -> None:
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("::", port))
    while True:
        server.recvfrom(65535)


for selected_port in (8080, 9002, 9003, 9025, 9143):
    threading.Thread(target=tcp_server, args=(selected_port,), daemon=True).start()
for selected_port in (9000, 9001, 9053):
    threading.Thread(target=udp_server, args=(selected_port,), daemon=True).start()

threading.Event().wait()
