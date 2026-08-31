#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Execute the exact primary Podman request as the runtime account."""

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
REAL_PODMAN = Path("/usr/bin/podman")
FIXTURE = "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
CONTAINER = re.compile(r"^secpal-host-qualification-([A-Za-z0-9]{6})-a$")


def emit(document: dict[str, object]) -> None:
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def exact_arguments(arguments: list[str]) -> list[str]:
    if len(arguments) != 17 or arguments[:3] != ["run", "--detach", "--name"]:
        raise ValueError("Podman arguments are outside the primary contract")
    match = CONTAINER.fullmatch(arguments[3])
    if match is None:
        raise ValueError("primary container name is outside the closed contract")
    expected = [
        "run", "--detach", "--name", arguments[3],
        "--security-opt", "no-new-privileges", "--cap-drop", "all",
        "--user", "65532:65532", "--network", "pasta", "-v",
        f"/var/tmp/secpal-host-qualification-{match.group(1)}/state-a:/state:Z",
        FIXTURE, "sleep", "infinity",
    ]
    if arguments != expected:
        raise ValueError("Podman arguments are outside the primary contract")
    return arguments


def runtime_environment(runtime: Any) -> dict[str, str]:
    if (
        os.getresuid() != (runtime.pw_uid,) * 3
        or os.getresgid() != (runtime.pw_gid,) * 3
    ):
        raise ValueError("runtime identity is outside the closed contract")
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
        "LC_ALL": "C",
        "HOME": runtime.pw_dir,
        "XDG_RUNTIME_DIR": f"/run/user/{runtime.pw_uid}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{runtime.pw_uid}/bus",
    }


def process_status(returncode: int) -> int:
    return min(returncode if returncode >= 0 else 128 + abs(returncode), 255)


def execute(
    arguments: list[str], *, runtime: Any, podman_path: Path = REAL_PODMAN
) -> tuple[int, str, int | None]:
    exact = exact_arguments(arguments)
    environment = runtime_environment(runtime)
    try:
        result = subprocess.run(
            [os.fspath(podman_path), *exact],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=sys.stderr,
            env=environment,
        )
    except OSError as error:
        return (127 if error.errno == 2 else 126), "podman-exec-failed", None
    status = process_status(result.returncode)
    if status == 0:
        return status, "success", status
    if status == 125:
        return status, "podman-internal-failed", status
    if status == 126:
        return status, "podman-oci-status-126", status
    if status == 127:
        return status, "podman-oci-status-127", status
    return status, "podman-request-failed", status


def main() -> int:
    emit({"kind": "runtime", "schema_version": 1, "stage": "runtime-entered"})
    try:
        runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
        status, stage, podman_status = execute(sys.argv[1:], runtime=runtime)
    except (KeyError, OSError, ValueError):
        status, stage, podman_status = 126, "env-preparation-failed", None
    emit(
        {
            "kind": "runtime",
            "podman_status": podman_status,
            "schema_version": 1,
            "stage": stage,
        }
    )
    return status


if __name__ == "__main__":
    raise SystemExit(main())
