#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Emit one identity-bound client PID before the real user daemon reload."""

from __future__ import annotations

import fcntl
import os
import pwd
import select
import stat
import sys


RUNTIME_ACCOUNT = "secpal-runtime"
REAL_SYSTEMCTL = "/usr/bin/systemctl"
ACK = b"SECPAL_RELOAD_CLIENT_ADMITTED_V1\n"
ACK_TIMEOUT_MILLISECONDS = 2_000


def admitted_fifo(descriptor: int, access_modes: frozenset[int]) -> None:
    metadata = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    if (
        not stat.S_ISFIFO(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or flags & os.O_ACCMODE not in access_modes
    ):
        raise OSError("reload observation channel is outside the closed contract")


def exact_runtime_identity() -> bool:
    runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
    return (
        os.getresuid() == (runtime.pw_uid,) * 3
        and os.getresgid() == (runtime.pw_gid,) * 3
    )


def read_acknowledgement() -> bytes:
    poller = select.poll()
    poller.register(0, select.POLLIN)
    if not poller.poll(ACK_TIMEOUT_MILLISECONDS):
        return b""
    with os.fdopen(0, "rb", buffering=0, closefd=False) as channel:
        return channel.readline(65)


def main() -> int:
    try:
        if (
            sys.argv[1:] != ["--user", "daemon-reload"]
            or not exact_runtime_identity()
        ):
            return 126
        admitted_fifo(0, frozenset({os.O_RDONLY, os.O_RDWR}))
        admitted_fifo(1, frozenset({os.O_WRONLY, os.O_RDWR}))
        record = f"SECPAL_QUADLET_RELOAD_CLIENT_V1:{os.getpid()}\n".encode("ascii")
        if os.write(1, record) != len(record) or read_acknowledgement() != ACK:
            return 126
        os.close(0)
        os.close(1)
        os.execv(REAL_SYSTEMCTL, [REAL_SYSTEMCTL, "--user", "daemon-reload"])
    except (KeyError, OSError, ValueError):
        return 126
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
