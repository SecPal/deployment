#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Observe one exact runtime-user systemctl is-active request."""

from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


RUNTIME_ACCOUNT = "secpal-runtime"
REAL_SYSTEMCTL = Path("/usr/bin/systemctl")
UNIT = re.compile(r"^secpal-host-qualification-[A-Za-z0-9]{6}\.service$")


class DiagnosticUnavailable(Exception):
    """The observer failed before it could attribute the target operation."""


def process_status(returncode: int) -> int:
    return min(returncode if returncode >= 0 else 128 + abs(returncode), 255)


def exact_runtime_identity(runtime: Any) -> bool:
    return (
        os.getresuid() == (runtime.pw_uid,) * 3
        and os.getresgid() == (runtime.pw_gid,) * 3
        and os.environ.get("HOME") == runtime.pw_dir
        and os.environ.get("XDG_RUNTIME_DIR") == f"/run/user/{runtime.pw_uid}"
        and os.environ.get("DBUS_SESSION_BUS_ADDRESS")
        == f"unix:path=/run/user/{runtime.pw_uid}/bus"
        and "CONTAINER_HOST" not in os.environ
        and "CONTAINER_CONNECTION" not in os.environ
    )


def execute_systemctl(
    arguments: list[str], *, runtime: Any, systemctl_path: Path = REAL_SYSTEMCTL
) -> tuple[int, str]:
    if (
        len(arguments) != 4
        or arguments[:3] != ["--user", "is-active", "--quiet"]
        or UNIT.fullmatch(arguments[3]) is None
    ):
        raise ValueError("systemctl arguments are outside the exact active-state contract")
    try:
        result = subprocess.run(
            [os.fspath(systemctl_path), *arguments],
            check=False,
            stdout=sys.stderr,
            stderr=sys.stderr,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                "LC_ALL": "C",
                "HOME": runtime.pw_dir,
                "XDG_RUNTIME_DIR": f"/run/user/{runtime.pw_uid}",
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{runtime.pw_uid}/bus",
            },
        )
    except OSError as error:
        if error.filename == os.fspath(systemctl_path):
            return (127 if error.errno == 2 else 126), "systemctl-exec-failed"
        raise DiagnosticUnavailable from error
    status = process_status(result.returncode)
    return status, "success" if status == 0 else "systemctl-request-failed"


def write_record(stage: str, status: int | None) -> None:
    record = {
        "schema_version": 1,
        "kind": "systemctl",
        "stage": stage,
        "systemctl_client_status": status,
    }
    os.write(
        1,
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        ),
    )


def fallback(arguments: list[str]) -> int:
    try:
        write_record("diagnostic-unavailable", None)
    except OSError:
        pass
    try:
        os.execv(os.fspath(REAL_SYSTEMCTL), [os.fspath(REAL_SYSTEMCTL), *arguments])
    except OSError as error:
        return 127 if error.errno == 2 else 126


def main() -> int:
    arguments = sys.argv[1:]
    try:
        runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
        if not exact_runtime_identity(runtime):
            return fallback(arguments)
        status, stage = execute_systemctl(arguments, runtime=runtime)
        write_record(stage, None if stage == "systemctl-exec-failed" else status)
        return status
    except DiagnosticUnavailable:
        return fallback(arguments)
    except (KeyError, OSError, ValueError):
        return fallback(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
