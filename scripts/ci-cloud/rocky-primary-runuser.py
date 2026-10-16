#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Route one exact primary workload through a closed runtime observer."""

from __future__ import annotations

import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


RUNTIME_ACCOUNT = "secpal-runtime"
REAL_RUNUSER = Path("/usr/sbin/runuser")
RUNTIME_HELPER = Path("/usr/local/libexec/secpal-control/rocky-primary-runtime")
FIXTURE = "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
CONTAINER = re.compile(r"^secpal-host-qualification-([A-Za-z0-9]{6})-a$")
MAX_PROTOCOL_BYTES = 512
OBSERVATION_PATH = Path(
    "/var/lib/secpal-rocky/evidence/primary-workload-observation.json"
)


def process_status(returncode: int) -> int:
    return min(returncode if returncode >= 0 else 128 + abs(returncode), 255)


def diagnostic(
    stage: str, runuser_status: int | None, podman_status: int | None = None
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "stage": stage,
        "runuser_status": runuser_status,
        "podman_status": podman_status,
    }


def exact_primary(arguments: list[str], runtime: Any) -> list[str] | None:
    if len(arguments) != 29:
        return None
    prefix = [
        "--user", RUNTIME_ACCOUNT, "--", "env",
        "-u", "CONTAINER_HOST", "-u", "CONTAINER_CONNECTION",
        f"HOME={runtime.pw_dir}",
        f"XDG_RUNTIME_DIR=/run/user/{runtime.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime.pw_uid}/bus",
        "podman",
    ]
    if arguments[:12] != prefix:
        return None
    podman = arguments[12:]
    if podman[:3] != ["run", "--detach", "--name"]:
        return None
    match = CONTAINER.fullmatch(podman[3])
    if match is None:
        return None
    expected = [
        "run", "--detach", "--name", podman[3],
        "--security-opt", "no-new-privileges", "--cap-drop", "all",
        "--user", "65532:65532", "--network", "pasta", "-v",
        f"/var/tmp/secpal-host-qualification-{match.group(1)}/state-a:/state:Z",
        FIXTURE, "sleep", "infinity",
    ]
    return podman if podman == expected else None


def parse_protocol(payload: bytes, status: int) -> dict[str, object]:
    if len(payload) > MAX_PROTOCOL_BYTES:
        return diagnostic("diagnostic-unavailable", status)
    try:
        records = [json.loads(line) for line in payload.decode("ascii").splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError):
        return diagnostic("diagnostic-unavailable", status)
    entered = {"kind": "runtime", "schema_version": 1, "stage": "runtime-entered"}
    if not records:
        return diagnostic("runuser-invocation-failed", status)
    if records[0] != entered or len(records) != 2 or not isinstance(records[1], dict):
        return diagnostic("diagnostic-unavailable", status)
    result = records[1]
    if set(result) != {"kind", "podman_status", "schema_version", "stage"}:
        return diagnostic("diagnostic-unavailable", status)
    if result.get("kind") != "runtime" or result.get("schema_version") != 1:
        return diagnostic("diagnostic-unavailable", status)
    stage = result.get("stage")
    podman_status = result.get("podman_status")
    if stage == "env-preparation-failed" and podman_status is None:
        return diagnostic(stage, status)
    if stage == "podman-exec-failed" and podman_status is None:
        return diagnostic(stage, status)
    if (
        stage not in {
            "success", "podman-internal-failed", "podman-oci-status-126",
            "podman-oci-status-127", "podman-request-failed",
        }
        or type(podman_status) is not int
        or not 0 <= podman_status <= 255
        or podman_status != status
    ):
        return diagnostic("diagnostic-unavailable", status)
    return diagnostic(str(stage), status, podman_status)


def execute_primary(
    podman_arguments: list[str], *, runuser_path: Path = REAL_RUNUSER,
    runtime_helper_path: Path = RUNTIME_HELPER,
) -> tuple[int, dict[str, object]]:
    command = [
        os.fspath(runuser_path), "--user", RUNTIME_ACCOUNT, "--",
        os.fspath(runtime_helper_path), *podman_arguments,
    ]
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
        "LC_ALL": "C",
    }
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            env=environment,
        )
    except OSError as error:
        status = 127 if error.errno == 2 else 126
        return status, diagnostic("runuser-exec-failed", None)
    status = process_status(result.returncode)
    return status, parse_protocol(result.stdout, status)


def admitted_observation_path(path: Path = OBSERVATION_PATH) -> Path:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise OSError("primary observation path is outside the closed contract")
    return path


def write_observation(path: Path, facts: dict[str, object]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    try:
        payload = (json.dumps(facts, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        if os.write(descriptor, payload) != len(payload):
            raise OSError("primary observation write was incomplete")
    finally:
        os.close(descriptor)


def fallback(arguments: list[str], runuser_path: Path = REAL_RUNUSER) -> int:
    try:
        os.execv(os.fspath(runuser_path), [os.fspath(runuser_path), *arguments])
    except OSError as error:
        return 127 if error.errno == 2 else 126


def main() -> int:
    arguments = sys.argv[1:]
    try:
        runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
        podman_arguments = exact_primary(arguments, runtime)
        if os.geteuid() != 0 or podman_arguments is None:
            return fallback(arguments)
        observation = admitted_observation_path()
    except (KeyError, OSError, ValueError):
        return fallback(arguments)

    # Once the exact primary request starts, observer failure must never replay
    # it through the fallback path.  The target status remains authoritative.
    status, facts = execute_primary(podman_arguments)
    try:
        write_observation(observation, facts)
    except (KeyError, OSError, ValueError):
        pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
