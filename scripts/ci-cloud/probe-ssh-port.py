#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Return one closed TCP reachability observation for a public SSH endpoint."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import socket
import sys


PROBE_TIMEOUT_SECONDS = 5.0
OBSERVATIONS = frozenset(
    ("reachable", "connection_refused", "connection_timeout", "other")
)


def classify_connect_result(result: int | None) -> str:
    if result == 0:
        return "reachable"
    if result == errno.ECONNREFUSED:
        return "connection_refused"
    if result in (
        errno.EAGAIN,
        errno.EINPROGRESS,
        errno.ETIMEDOUT,
        errno.EWOULDBLOCK,
    ):
        return "connection_timeout"
    return "other"


def probe(address: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(PROBE_TIMEOUT_SECONDS)
            return classify_connect_result(connection.connect_ex((address, 22)))
    except TimeoutError:
        return "connection_timeout"
    except OSError as error:
        return classify_connect_result(error.errno)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    arguments = parser.parse_args()
    try:
        address = ipaddress.ip_address(arguments.address)
    except ValueError:
        print("ERROR: SSH probe address is invalid.", file=sys.stderr)
        return 1
    if address.version != 4 or not address.is_global:
        print("ERROR: SSH probe address is not a public IPv4 address.", file=sys.stderr)
        return 1
    observation = probe(str(address))
    if observation not in OBSERVATIONS:
        print("ERROR: SSH probe returned an invalid observation.", file=sys.stderr)
        return 1
    print(observation)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
