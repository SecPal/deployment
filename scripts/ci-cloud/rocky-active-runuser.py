#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Preserve and observe one exact runuser active-state boundary."""

from __future__ import annotations

import fcntl
import json
import os
import pwd
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


RUNTIME_ACCOUNT = "secpal-runtime"
REAL_RUNUSER = Path("/usr/sbin/runuser")
TRUSTED_ENV = Path("/usr/local/libexec/secpal-control/rocky-active-env")
OBSERVATION_FD = 7
MAX_PROTOCOL_BYTES = 2_048


class DiagnosticUnavailable(Exception):
    """The observer failed before it could attribute the target operation."""


def target_arguments(runtime: Any, unit: str) -> list[str]:
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
        f"XDG_RUNTIME_DIR=/run/user/{runtime.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime.pw_uid}/bus",
        "systemctl",
        "--user",
        "is-active",
        "--quiet",
        unit,
    ]


def blank(stage: str, status: int | None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "stage": stage,
        "runuser_status": status,
        "systemctl_client_status": None,
    }


def parse_protocol(payload: bytes, status: int) -> dict[str, object]:
    if len(payload) > MAX_PROTOCOL_BYTES:
        return blank("diagnostic-unavailable", status)
    try:
        records = [json.loads(line) for line in payload.decode("ascii").splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return blank("diagnostic-unavailable", status)
    if not records:
        return blank("runuser-invocation-failed", status)
    if records[0] != {"kind": "env", "schema_version": 1, "stage": "env-entered"}:
        return blank("diagnostic-unavailable", status)
    if len(records) == 1:
        return blank("env-command-exec-failed", status)
    if records[1] == {"kind": "env", "schema_version": 1, "stage": "env-exec-failed"}:
        return blank("env-exec-failed", status) if len(records) == 2 else blank(
            "diagnostic-unavailable", status
        )
    if len(records) != 2 or not isinstance(records[1], dict):
        return blank("diagnostic-unavailable", status)
    systemctl = records[1]
    if set(systemctl) != {
        "schema_version",
        "kind",
        "stage",
        "systemctl_client_status",
    } or systemctl.get("schema_version") != 1 or systemctl.get("kind") != "systemctl":
        return blank("diagnostic-unavailable", status)
    stage = systemctl.get("stage")
    client_status = systemctl.get("systemctl_client_status")
    if stage not in {"success", "systemctl-exec-failed", "systemctl-request-failed"}:
        return blank("diagnostic-unavailable", status)
    facts = blank(str(stage), status)
    facts["systemctl_client_status"] = client_status
    return facts


def execute_active(
    arguments: list[str], *, runtime: Any, runuser_path: Path = REAL_RUNUSER
) -> tuple[int, dict[str, object]]:
    expected = target_arguments(runtime, arguments[-1] if arguments else "")
    if arguments != expected:
        raise ValueError("runuser arguments are outside the exact active-state contract")
    command = [
        os.fspath(runuser_path),
        *arguments[:3],
        os.fspath(TRUSTED_ENV),
        *arguments[4:],
    ]
    try:
        protocol_context = tempfile.TemporaryFile()
    except OSError as error:
        raise DiagnosticUnavailable from error
    status: int | None = None
    try:
        with protocol_context as protocol:
            try:
                result = subprocess.run(
                    command,
                    check=False,
                    stdout=protocol,
                    stderr=sys.stderr,
                    env={
                        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                        "LC_ALL": "C",
                    },
                )
            except OSError as error:
                if error.filename == os.fspath(runuser_path):
                    status = 127 if error.errno == 2 else 126
                    return status, blank("runuser-exec-failed", None)
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
                return status, blank("diagnostic-unavailable", status)
    except OSError as error:
        if status is not None:
            return status, blank("diagnostic-unavailable", status)
        raise DiagnosticUnavailable from error
    assert status is not None
    return status, parse_protocol(payload, status)


def admitted_observation_descriptor() -> None:
    metadata = os.fstat(OBSERVATION_FD)
    flags = fcntl.fcntl(OBSERVATION_FD, fcntl.F_GETFL)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or flags & os.O_ACCMODE != os.O_WRONLY
    ):
        raise OSError("active-state observation descriptor is outside the closed contract")


def write_observation(facts: dict[str, object]) -> None:
    try:
        os.write(
            OBSERVATION_FD,
            (json.dumps(facts, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "ascii"
            ),
        )
    except OSError:
        pass


def fallback(arguments: list[str]) -> int:
    os.environ.pop("BASH_ENV", None)
    os.environ.pop("SECPAL_ACTIVE_EXACT_CALL", None)
    os.environ.pop("SECPAL_ACTIVE_OBSERVATION_PATH", None)
    try:
        os.close(OBSERVATION_FD)
    except OSError:
        pass
    try:
        os.execv(os.fspath(REAL_RUNUSER), [os.fspath(REAL_RUNUSER), *arguments])
    except OSError as error:
        return 127 if error.errno == 2 else 126


def main() -> int:
    arguments = sys.argv[1:]
    try:
        runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
        if os.geteuid() != 0 or os.environ.get("SECPAL_ACTIVE_EXACT_CALL") != "1":
            return fallback(arguments)
        admitted_observation_descriptor()
        if arguments != target_arguments(runtime, arguments[-1] if arguments else ""):
            return fallback(arguments)
        status, facts = execute_active(arguments, runtime=runtime)
        write_observation(facts)
        return status
    except DiagnosticUnavailable:
        write_observation(blank("diagnostic-unavailable", None))
        return fallback(arguments)
    except (KeyError, OSError, ValueError):
        return fallback(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
