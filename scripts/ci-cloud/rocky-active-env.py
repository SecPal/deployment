#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Observe the env execution for one exact runtime-user active-state request."""

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
TRUSTED_SYSTEMCTL = Path("/usr/local/libexec/secpal-control/rocky-active-systemctl")
MAX_PROTOCOL_BYTES = 2_048


class DiagnosticUnavailable(Exception):
    """The observer failed before it could attribute the target operation."""


def exact_arguments(runtime: Any, arguments: list[str]) -> list[str]:
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
        "is-active",
        "--quiet",
    ]
    if len(arguments) != len(prefix) + 1 or arguments[:-1] != prefix:
        raise ValueError("env arguments are outside the exact active-state contract")
    return arguments


def emit(output: BinaryIO, stage: str) -> None:
    record = {"schema_version": 1, "kind": "env", "stage": stage}
    output.write(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )
    )
    output.flush()


def execute_env(
    arguments: list[str],
    *,
    runtime: Any,
    env_path: Path = REAL_ENV,
    systemctl_helper_path: Path = TRUSTED_SYSTEMCTL,
    output: BinaryIO,
) -> int:
    exact = exact_arguments(runtime, arguments)
    command = [
        os.fspath(env_path),
        *exact[:-5],
        os.fspath(systemctl_helper_path),
        *exact[-4:],
    ]
    try:
        protocol_context = tempfile.TemporaryFile()
    except OSError as error:
        raise DiagnosticUnavailable from error
    emit(output, "env-entered")
    status: int | None = None
    try:
        with protocol_context as protocol:
            try:
                result = subprocess.run(
                    command,
                    check=False,
                    stdout=protocol,
                    stderr=sys.stderr,
                    env=dict(os.environ),
                )
            except OSError as error:
                if error.filename == os.fspath(env_path):
                    emit(output, "env-exec-failed")
                    return 127 if error.errno == 2 else 126
                raise DiagnosticUnavailable from error
            status = min(
                result.returncode
                if result.returncode >= 0
                else 128 + abs(result.returncode),
                255,
            )
            try:
                protocol.seek(0)
                payload = protocol.read(MAX_PROTOCOL_BYTES + 1)
            except OSError:
                emit(output, "diagnostic-unavailable")
                return status
    except OSError as error:
        if status is not None:
            emit(output, "diagnostic-unavailable")
            return status
        raise DiagnosticUnavailable from error
    assert status is not None
    if len(payload) > MAX_PROTOCOL_BYTES:
        emit(output, "diagnostic-unavailable")
    else:
        output.write(payload)
        output.flush()
    return status


def fallback(arguments: list[str], output: BinaryIO) -> int:
    emit(output, "diagnostic-unavailable")
    try:
        os.execv(os.fspath(REAL_ENV), [os.fspath(REAL_ENV), *arguments])
    except OSError as error:
        return 127 if error.errno == 2 else 126


def main() -> int:
    try:
        runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
        if (
            os.getresuid() != (runtime.pw_uid,) * 3
            or os.getresgid() != (runtime.pw_gid,) * 3
        ):
            return fallback(sys.argv[1:], sys.stdout.buffer)
        return execute_env(sys.argv[1:], runtime=runtime, output=sys.stdout.buffer)
    except DiagnosticUnavailable:
        return fallback(sys.argv[1:], sys.stdout.buffer)
    except (KeyError, OSError, ValueError):
        return fallback(sys.argv[1:], sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
