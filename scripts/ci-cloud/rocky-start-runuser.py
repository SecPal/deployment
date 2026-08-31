#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Preserve and observe one exact runuser to systemctl start boundary."""

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
TRUSTED_ENV = Path("/usr/local/libexec/secpal-control/rocky-start-env")
OBSERVATION_FD = 6
MAX_PROTOCOL_BYTES = 2_048
STAGES = frozenset(
    {
        "diagnostic-unavailable",
        "env-exec-failed",
        "systemctl-exec-failed",
        "systemctl-request-failed",
        "service-job-failed",
        "success",
    }
)


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
        "start",
        unit,
    ]


def blank(stage: str, status: int | None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "stage": stage,
        "runuser_status": status,
        "systemctl_client_status": None,
        "service_result": None,
        "exec_main_code": None,
        "exec_main_status": None,
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
    if records[0] == {
        "kind": "env",
        "schema_version": 1,
        "stage": "diagnostic-unavailable",
    }:
        if len(records) != 1:
            return blank("diagnostic-unavailable", status)
        return blank("diagnostic-unavailable", status)
    if records[0] != {"kind": "env", "schema_version": 1, "stage": "env-entered"}:
        return blank("diagnostic-unavailable", status)
    if len(records) == 1:
        return blank("env-command-exec-failed", status)
    if records[1] == {"kind": "env", "schema_version": 1, "stage": "env-exec-failed"}:
        if len(records) != 2:
            return blank("diagnostic-unavailable", status)
        return blank("env-exec-failed", status)
    if records[1] == {
        "kind": "env",
        "schema_version": 1,
        "stage": "diagnostic-unavailable",
    }:
        if len(records) != 2:
            return blank("diagnostic-unavailable", status)
        return blank("diagnostic-unavailable", status)
    if len(records) != 2 or not isinstance(records[1], dict):
        return blank("diagnostic-unavailable", status)
    systemctl = records[1]
    if set(systemctl) != {
        "schema_version",
        "kind",
        "stage",
        "systemctl_client_status",
        "service_result",
        "exec_main_code",
        "exec_main_status",
    } or systemctl.get("schema_version") != 1 or systemctl.get("kind") != "systemctl":
        return blank("diagnostic-unavailable", status)
    stage = systemctl.get("stage")
    if stage not in STAGES:
        return blank("diagnostic-unavailable", status)
    facts = blank(str(stage), status)
    for name in (
        "systemctl_client_status",
        "service_result",
        "exec_main_code",
        "exec_main_status",
    ):
        facts[name] = systemctl.get(name)
    return facts


def execute_start(
    arguments: list[str],
    *,
    runtime: Any,
    runuser_path: Path = REAL_RUNUSER,
    env_helper_path: Path = TRUSTED_ENV,
) -> tuple[int, dict[str, object]]:
    if len(arguments) < 1:
        raise ValueError("start arguments are empty")
    expected = target_arguments(runtime, arguments[-1])
    if arguments != expected:
        raise ValueError("runuser arguments are outside the exact start contract")
    command = [
        os.fspath(runuser_path),
        *arguments[:3],
        os.fspath(env_helper_path),
        *arguments[4:],
    ]
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
        "LC_ALL": "C",
    }
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
                    env=environment,
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
        raise OSError("start observation descriptor is outside the closed contract")


def write_observation(facts: dict[str, object]) -> None:
    encoded = (json.dumps(facts, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    try:
        os.write(OBSERVATION_FD, encoded)
    except OSError:
        pass


def fallback(arguments: list[str]) -> int:
    os.environ.pop("BASH_ENV", None)
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
        if os.geteuid() != 0:
            return fallback(arguments)
        admitted_observation_descriptor()
        expected = target_arguments(runtime, arguments[-1] if arguments else "")
        if arguments != expected:
            return fallback(arguments)
        status, facts = execute_start(arguments, runtime=runtime)
        write_observation(facts)
        return status
    except DiagnosticUnavailable:
        write_observation(blank("diagnostic-unavailable", None))
        return fallback(arguments)
    except (KeyError, OSError, ValueError):
        return fallback(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
