#!/usr/bin/python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Observe the exact env execution before one runtime-user systemctl start."""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO


RUNTIME_ACCOUNT = "secpal-runtime"
REAL_ENV = Path("/usr/bin/env")
TRUSTED_SYSTEMCTL = Path(
    "/usr/local/libexec/secpal-control/rocky-start-systemctl"
)
MAX_PROTOCOL_BYTES = 2_048


def exact_arguments(runtime: Any, arguments: list[str]) -> tuple[list[str], str]:
    prefix = [
        "-u",
        "CONTAINER_HOST",
        "-u",
        "CONTAINER_CONNECTION",
        f"HOME={runtime.pw_dir}",
        f"XDG_RUNTIME_DIR=/run/user/{runtime.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime.pw_uid}/bus",
        "systemctl",
        "--user",
        "start",
    ]
    if len(arguments) != len(prefix) + 1 or arguments[:-1] != prefix:
        raise ValueError("env arguments are outside the exact start contract")
    return arguments, arguments[-1]


def emit(output: BinaryIO | None, stage: str) -> None:
    if output is None:
        return
    record = json.dumps(
        {"schema_version": 1, "kind": "env", "stage": stage},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    output.write(record)
    output.flush()


def execute_env(
    arguments: list[str],
    *,
    runtime: Any,
    env_path: Path = REAL_ENV,
    systemctl_helper_path: Path = TRUSTED_SYSTEMCTL,
    output: BinaryIO | None = None,
) -> tuple[int, tuple[str, ...]]:
    exact, unit = exact_arguments(runtime, arguments)
    records = ["env-entered"]
    emit(output, records[-1])
    command = [
        os.fspath(env_path),
        *exact[:-4],
        os.fspath(systemctl_helper_path),
        "--user",
        "start",
        unit,
    ]
    try:
        with tempfile.TemporaryFile() as protocol:
            result = subprocess.run(
                command,
                check=False,
                stdout=protocol,
                stderr=sys.stderr,
                env=dict(os.environ),
            )
            protocol.seek(0)
            payload = protocol.read(MAX_PROTOCOL_BYTES + 1)
    except OSError:
        records.append("env-exec-failed")
        emit(output, records[-1])
        return 126, tuple(records)
    if output is not None and len(payload) <= MAX_PROTOCOL_BYTES:
        output.write(payload)
        output.flush()
    return min(result.returncode if result.returncode >= 0 else 128 + abs(result.returncode), 255), tuple(records)


def main() -> int:
    try:
        runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
        if (
            os.getresuid() != (runtime.pw_uid,) * 3
            or os.getresgid() != (runtime.pw_gid,) * 3
        ):
            return 126
        status, _records = execute_env(
            sys.argv[1:], runtime=runtime, output=sys.stdout.buffer
        )
        return status
    except (KeyError, OSError, ValueError):
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
