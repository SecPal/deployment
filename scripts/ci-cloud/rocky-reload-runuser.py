#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Carry one trusted daemon-reload client record across runuser explicitly."""

from __future__ import annotations

import fcntl
import os
import pwd
import stat
import sys


RUNTIME_ACCOUNT = "secpal-runtime"
REAL_RUNUSER = "/usr/sbin/runuser"
TRUSTED_SYSTEMCTL = (
    "/usr/local/libexec/secpal-control/rocky-reload-systemctl"
)
RECORD_FD = 4
ACK_FD = 5


def admitted_fifo(descriptor: int, access_mode: int) -> None:
    metadata = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    if (
        not stat.S_ISFIFO(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or flags & os.O_ACCMODE != access_mode
    ):
        raise OSError("reload observation channel is outside the closed contract")


def exact_arguments() -> list[str]:
    runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
    runtime_directory = f"/run/user/{runtime.pw_uid}"
    return [
        "--user",
        RUNTIME_ACCOUNT,
        "--",
        "env",
        "-u",
        "CONTAINER_HOST",
        "-u",
        "CONTAINER_CONNECTION",
        f"HOME={runtime.pw_dir}",
        f"XDG_RUNTIME_DIR={runtime_directory}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_directory}/bus",
        "systemctl",
        "--user",
        "daemon-reload",
    ]


def main() -> int:
    try:
        arguments = sys.argv[1:]
        if os.geteuid() != 0 or os.environ.get("SECPAL_RELOAD_EXACT_CALL") != "1":
            return 126
        expected = exact_arguments()
        if arguments != expected:
            return 126
        admitted_fifo(RECORD_FD, os.O_RDWR)
        admitted_fifo(ACK_FD, os.O_RDWR)
        arguments = [*arguments]
        arguments[-3] = TRUSTED_SYSTEMCTL
        os.dup2(ACK_FD, 0, inheritable=True)
        os.dup2(RECORD_FD, 1, inheritable=True)
        os.closerange(3, int(os.sysconf("SC_OPEN_MAX")))
        os.environ.pop("BASH_ENV", None)
        os.execv(REAL_RUNUSER, [REAL_RUNUSER, *arguments])
    except (KeyError, OSError, ValueError):
        return 126
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
