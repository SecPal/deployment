#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Observe one exact runtime-user systemctl start without copying its output."""

from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


RUNTIME_ACCOUNT = "secpal-runtime"
REAL_SYSTEMCTL = Path("/usr/bin/systemctl")
UNIT = re.compile(r"^secpal-host-qualification-[A-Za-z0-9]{6}\.service$")
MAX_PROPERTY_BYTES = 1_024
SERVICE_RESULTS = frozenset(
    {
        "success",
        "resources",
        "protocol",
        "timeout",
        "exit-code",
        "signal",
        "core-dump",
        "watchdog",
        "start-limit-hit",
        "oom-kill",
        "exec-condition",
    }
)


class DiagnosticUnavailable(Exception):
    """The observer failed before it could attribute the target operation."""


def process_status(returncode: int) -> int:
    if returncode >= 0:
        return min(returncode, 255)
    return min(128 + abs(returncode), 255)


def empty_facts(stage: str) -> dict[str, object]:
    return {
        "stage": stage,
        "systemctl_client_status": None,
        "service_result": None,
        "exec_main_code": None,
        "exec_main_status": None,
    }


def parse_service_properties(payload: bytes) -> dict[str, object] | None:
    if len(payload) > MAX_PROPERTY_BYTES:
        return None
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        return None
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            return None
        name, value = line.split("=", 1)
        if name in values or name not in {"Result", "ExecMainCode", "ExecMainStatus"}:
            return None
        values[name] = value
    if set(values) != {"Result", "ExecMainCode", "ExecMainStatus"}:
        return None
    if values["Result"] not in SERVICE_RESULTS:
        return None
    if re.fullmatch(r"[0-6]", values["ExecMainCode"]) is None:
        return None
    if re.fullmatch(r"[0-9]{1,3}", values["ExecMainStatus"]) is None:
        return None
    status = int(values["ExecMainStatus"])
    if status > 255:
        return None
    return {
        "service_result": values["Result"],
        "exec_main_code": int(values["ExecMainCode"]),
        "exec_main_status": status,
    }


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
    arguments: list[str],
    *,
    runtime: Any,
    systemctl_path: Path = REAL_SYSTEMCTL,
) -> tuple[int, dict[str, object]]:
    if (
        len(arguments) != 3
        or arguments[:2] != ["--user", "start"]
        or UNIT.fullmatch(arguments[2]) is None
    ):
        raise ValueError("systemctl start arguments are outside the exact contract")
    command = [os.fspath(systemctl_path), *arguments]
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=sys.stderr,
            stderr=sys.stderr,
            env=dict(os.environ),
        )
    except OSError as error:
        if error.filename == os.fspath(systemctl_path):
            return (127 if error.errno == 2 else 126), empty_facts(
                "systemctl-exec-failed"
            )
        raise DiagnosticUnavailable from error
    client_status = process_status(result.returncode)
    if client_status == 0:
        facts = empty_facts("success")
        facts["systemctl_client_status"] = 0
        return 0, facts

    properties: dict[str, object] | None = None
    observation_complete = False
    try:
        with tempfile.TemporaryFile() as output:
            observation = subprocess.run(
                [
                    os.fspath(systemctl_path),
                    "--user",
                    "show",
                    "--no-pager",
                    "--property=Result",
                    "--property=ExecMainCode",
                    "--property=ExecMainStatus",
                    arguments[2],
                ],
                check=False,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env=dict(os.environ),
            )
            output.seek(0)
            payload = output.read(MAX_PROPERTY_BYTES + 1)
        if observation.returncode == 0:
            properties = parse_service_properties(payload)
            observation_complete = properties is not None
    except OSError:
        properties = None

    if properties is not None and properties["service_result"] != "success":
        return client_status, {
            "stage": "service-job-failed",
            "systemctl_client_status": client_status,
            **properties,
        }
    if not observation_complete:
        facts = empty_facts("diagnostic-unavailable")
        facts["systemctl_client_status"] = client_status
        return client_status, facts
    facts = empty_facts("systemctl-request-failed")
    facts["systemctl_client_status"] = client_status
    return client_status, facts


def write_record(facts: dict[str, object]) -> None:
    record = {
        "schema_version": 1,
        "kind": "systemctl",
        **facts,
    }
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    os.write(1, encoded)


def fallback(arguments: list[str]) -> int:
    try:
        write_record(empty_facts("diagnostic-unavailable"))
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
        status, facts = execute_systemctl(arguments, runtime=runtime)
        write_record(facts)
        return status
    except DiagnosticUnavailable:
        return fallback(arguments)
    except (KeyError, OSError, ValueError):
        return fallback(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
