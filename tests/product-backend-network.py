#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Exercise #101's real nftables/socket boundary in a disposable user namespace.

This proves the kernel UID rule and loopback socket behavior, not a host-native
SELinux HAProxy/product qualification. It never modifies host firewall rules.
"""

import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from product_backend_contract import BACKENDS, host_policy


def connect_as(uid: int, host: str, port: int, expected: bool) -> None:
    child = os.fork()
    if child == 0:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        try:
            with socket.create_connection((host, port), timeout=1) as connection:
                connection.sendall(b"GET /health/live HTTP/1.0\r\n\r\n")
                success = connection.recv(1024).startswith(b"HTTP/1.0 200")
        except OSError:
            success = False
        os._exit(0 if success == expected else 1)
    _, status = os.waitpid(child, 0)
    if os.waitstatus_to_exitcode(status) != 0:
        raise RuntimeError("socket/UID boundary did not match expected access")


def namespace_test() -> None:
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "link", "add", "external", "type", "dummy"], check=True)
    subprocess.run(["ip", "addr", "add", "192.0.2.1/24", "dev", "external"], check=True)
    subprocess.run(["ip", "link", "set", "external", "up"], check=True)
    rules = host_policy(991)["product-backends.nft"]
    subprocess.run(["nft", "--check", "-f", "-"], input=rules, text=True, check=True)
    subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True)

    for backend in BACKENDS.values():
        # Recreate the listener twice at exactly the same configured endpoint.
        for _ in range(2):
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", backend.host_port))
                listener.listen()
                server = os.fork()
                if server == 0:
                    while True:
                        connection, _ = listener.accept()
                        with connection:
                            connection.recv(1024)
                            connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                try:
                    connect_as(991, "127.0.0.1", backend.host_port, True)
                    connect_as(992, "127.0.0.1", backend.host_port, False)
                    connect_as(991, "192.0.2.1", backend.host_port, False)
                    connect_as(991, "::1", backend.host_port, False)
                finally:
                    os.kill(server, signal.SIGTERM)
                    os.waitpid(server, 0)
    print("PASS: exact IPv4 loopback sockets, UID admission/denial, external/IPv6 denial, recreation")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside-namespace", action="store_true")
    args = parser.parse_args()
    if args.inside_namespace:
        namespace_test()
    else:
        subprocess.run(
            ["unshare", "--user", "--map-auto", "--map-root-user", "--net",
             sys.executable, str(Path(__file__).resolve()), "--inside-namespace"],
            check=True,
        )


if __name__ == "__main__":
    main()
