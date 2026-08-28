#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Observe bounded negative facts adjacent to the exact d892 daemon reload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import select
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import IO, Any


EVENT = re.compile(
    rb"^SECPAL_QUADLET_RELOAD_FAILURE_V1:([1-9][0-9]{0,2}):"
    rb"([1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3}){0,7})\n$"
)
SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
INPUT_NAME = re.compile(r"^secpal-host-qualification-[A-Za-z0-9]{6}\.container$")
SAFE_BASENAME = re.compile(r"^[A-Za-z0-9_.@+-]{1,128}$")
GENERATOR_MESSAGE = re.compile(
    r"^(?P<path>/[^\r\n]{1,384}) failed with exit status "
    r"(?P<status>[1-9][0-9]{0,2}), ignoring\.$"
)
MAX_INPUT_BYTES = 4_096
MAX_COMMAND_BYTES = 65_536
MAX_OBSERVATION_BYTES = 4_096
COMMAND_TIMEOUT_SECONDS = 3
GENERATOR_TIMEOUT_SECONDS = 8
CAPTURE_DEADLINE_SECONDS = 22
RUNTIME_ACCOUNT = "secpal-runtime"
GENERATOR_CANDIDATES = (
    Path("/usr/lib/systemd/user-generators/podman-system-generator"),
    Path("/usr/local/lib/systemd/user-generators/podman-system-generator"),
    Path("/usr/lib/systemd/system-generators/podman-system-generator"),
)
ADMITTED_USER_GENERATOR_ROOTS = (
    Path("/run/systemd/user-generators"),
    Path("/etc/systemd/user-generators"),
    Path("/usr/local/lib/systemd/user-generators"),
    Path("/usr/lib/systemd/user-generators"),
)
ADMITTED_PODMAN_GENERATOR_ROOTS = (
    *ADMITTED_USER_GENERATOR_ROOTS,
    Path("/usr/lib/systemd/system-generators"),
)


class ObservationError(RuntimeError):
    """The failure-time observation could not stay inside its closed contract."""


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def command_status(command: list[str], *, timeout: int = COMMAND_TIMEOUT_SECONDS) -> int:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        status = process.wait(timeout=timeout)
    except OSError:
        return 125
    except subprocess.TimeoutExpired:
        terminate_group(process)
        return 124
    return status if 0 <= status <= 255 else 125


def bounded_command_output(command: list[str], *, timeout: int) -> tuple[int, bytes]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return 125, b""
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    observed = 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if readable:
                chunk = os.read(descriptor, min(8_192, MAX_COMMAND_BYTES + 1 - observed))
                if not chunk:
                    return process.wait(timeout=max(0.1, remaining)), b"".join(chunks)
                chunks.append(chunk)
                observed += len(chunk)
                if observed > MAX_COMMAND_BYTES:
                    terminate_group(process)
                    return 125, b""
            elif process.poll() is not None:
                return process.returncode, b"".join(chunks)
    except (OSError, subprocess.TimeoutExpired):
        terminate_group(process)
        return 124, b""


def admitted_generator(path: Path, *, podman: bool = False) -> Path | None:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not SAFE_BASENAME.fullmatch(resolved.name)
    ):
        return None
    roots = (
        ADMITTED_PODMAN_GENERATOR_ROOTS if podman else ADMITTED_USER_GENERATOR_ROOTS
    )
    if not any(resolved.is_relative_to(root) for root in roots):
        return None
    if podman and resolved.name != "podman-system-generator":
        return None
    return resolved


def podman_generator_path() -> Path | None:
    admitted = {
        resolved
        for candidate in GENERATOR_CANDIDATES
        if (resolved := admitted_generator(candidate, podman=True)) is not None
    }
    return next(iter(admitted)) if len(admitted) == 1 else None


def input_facts(runtime_uid: int) -> tuple[dict[str, Any], Path | None]:
    directory = Path(f"/etc/containers/systemd/users/{runtime_uid}")
    try:
        directory_metadata = directory.lstat()
        directory_admitted = (
            stat.S_ISDIR(directory_metadata.st_mode)
            and not stat.S_ISLNK(directory_metadata.st_mode)
            and directory_metadata.st_uid == 0
            and directory_metadata.st_gid == 0
            and not directory_metadata.st_mode & 0o022
            and directory.resolve(strict=True) == directory
        )
    except OSError:
        directory_admitted = False
    try:
        matches = (
            sorted(
                entry
                for entry in directory.iterdir()
                if INPUT_NAME.fullmatch(entry.name)
            )
            if directory_admitted
            else []
        )
    except OSError:
        matches = []
    facts: dict[str, Any] = {
        "match_count": min(len(matches), 2),
        "present": len(matches) == 1,
        "regular_file": False,
        "not_symlink": False,
        "owner_uid": None,
        "owner_gid": None,
        "mode": None,
        "size": None,
        "sha256": None,
    }
    if len(matches) != 1:
        return facts, None
    path = matches[0]
    try:
        metadata = path.lstat()
    except OSError:
        return facts, None
    facts.update(
        {
            "regular_file": stat.S_ISREG(metadata.st_mode),
            "not_symlink": not stat.S_ISLNK(metadata.st_mode),
            "owner_uid": metadata.st_uid,
            "owner_gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "size": min(metadata.st_size, MAX_INPUT_BYTES + 1),
        }
    )
    if not facts["regular_file"] or not facts["not_symlink"]:
        return facts, None
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size > MAX_INPUT_BYTES
        ):
            return facts, None
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            payload = source.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            return facts, None
    except OSError:
        return facts, None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    facts["sha256"] = hashlib.sha256(payload).hexdigest()
    return facts, path


def generator_failures(
    payload: bytes, runtime_uid: int, boot_id: str
) -> tuple[list[dict[str, Any]], bool]:
    failures: list[dict[str, Any]] = []
    ambiguous = False
    for raw_line in payload.splitlines():
        if len(raw_line) > 2_048:
            ambiguous = True
            continue
        try:
            entry = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            ambiguous = True
            continue
        if not isinstance(entry, dict):
            ambiguous = True
            continue
        if str(entry.get("_UID")) != str(runtime_uid):
            continue
        if entry.get("_BOOT_ID") != boot_id.replace("-", ""):
            continue
        if entry.get("CODE_FUNC") != "do_execute" or not str(
            entry.get("CODE_FILE", "")
        ).endswith("src/shared/exec-util.c"):
            continue
        match = GENERATOR_MESSAGE.fullmatch(str(entry.get("MESSAGE", "")))
        if match is None:
            continue
        generator_path = Path(match.group("path"))
        resolved = admitted_generator(
            generator_path,
            podman=generator_path.name == "podman-system-generator",
        )
        status = int(match.group("status"))
        if resolved is None or status > 255:
            ambiguous = True
            continue
        failure = {"basename": resolved.name, "exit_status": status}
        if failure not in failures:
            failures.append(failure)
        if len(failures) > 3:
            ambiguous = True
            failures = failures[:3]
    return failures, ambiguous


def selinux_adjacency(
    payload: bytes, input_path: Path | None
) -> tuple[bool, dict[str, str] | None, bool]:
    observations: list[dict[str, str]] = []
    input_tokens = set()
    if input_path is not None:
        input_tokens = {str(input_path), input_path.name}
    for event in payload.decode("utf-8", errors="replace").split("----"):
        if "avc:  denied" not in event or "permissive=0" not in event:
            continue
        relevant = any(token and token in event for token in input_tokens) or any(
            marker in event
            for marker in (
                'comm="systemd"',
                'comm="podman-system-g',
                'exe="/usr/lib/systemd/',
            )
        )
        if not relevant:
            continue
        context = re.search(
            r"scontext=([^\s]+).*tcontext=([^\s]+).*tclass=([a-z_]{1,32})",
            event,
            re.DOTALL,
        )
        permission = re.search(r"avc:\s+denied\s+\{\s*([a-z_]{1,32})", event)
        if context is None or permission is None:
            return True, None, True
        source = context.group(1).split(":")
        target = context.group(2).split(":")
        if len(source) < 3 or len(target) < 3:
            return True, None, True
        observation = {
            "source_type": source[2],
            "target_type": target[2],
            "object_class": context.group(3),
            "denied_permission": permission.group(1),
        }
        if observation not in observations:
            observations.append(observation)
    if not observations:
        return False, None, False
    return True, observations[0], len(observations) > 1


def collect_observation(
    arguments: argparse.Namespace, failure_status: int, event: bytes
) -> dict[str, Any]:
    runtime = pwd.getpwnam(RUNTIME_ACCOUNT)
    runtime_uid = runtime.pw_uid
    bus_path = Path(f"/run/user/{runtime_uid}/bus")
    manager_active = command_status(
        ["systemctl", "is-active", "--quiet", f"user@{runtime_uid}.service"]
    ) == 0
    try:
        bus_available = stat.S_ISSOCK(bus_path.stat().st_mode)
    except OSError:
        bus_available = False
    control_reachable = command_status(
        [
            "systemctl",
            f"--machine={RUNTIME_ACCOUNT}@.host",
            "--user",
            "show-environment",
        ]
    ) == 0
    quadlet_input, input_path = input_facts(runtime_uid)
    generator = podman_generator_path()
    generator_executed = input_path is not None and generator is not None
    generator_status: int | None = None
    if generator_executed:
        generator_status = command_status(
            [
                "runuser",
                "--user",
                RUNTIME_ACCOUNT,
                "--",
                "env",
                f"HOME={runtime.pw_dir}",
                f"XDG_RUNTIME_DIR=/run/user/{runtime_uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime_uid}/bus",
                f"QUADLET_UNIT_DIRS={input_path.parent}",
                str(generator),
                "--user",
                "--dryrun",
            ],
            timeout=GENERATOR_TIMEOUT_SECONDS,
        )
    journal_status, journal = bounded_command_output(
        [
            "journalctl",
            "--no-pager",
            "--output=json",
            f"--boot={arguments.boot_id}",
            f"--since={arguments.journal_baseline}",
            f"_UID={runtime_uid}",
        ],
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    failures, generator_ambiguous = (
        generator_failures(journal, runtime_uid, arguments.boot_id)
        if journal_status == 0
        else ([], True)
    )
    audit_status, audit = bounded_command_output(
        ["ausearch", "-m", "AVC", "-ts", arguments.audit_baseline, "-i"],
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    avc_observed, avc, avc_ambiguous = (
        selinux_adjacency(audit, input_path)
        if audit_status in (0, 1)
        else (False, None, True)
    )
    return {
        "schema_version": 1,
        "target_sha": arguments.target_sha,
        "trusted_control_sha": arguments.control_sha,
        "qualification_run_id": arguments.run_id,
        "qualification_run_attempt": arguments.run_attempt,
        "boot_id": arguments.boot_id,
        "failure_status": failure_status,
        "failure_event_sha256": hashlib.sha256(event).hexdigest(),
        "captured_before_cleanup": True,
        "capture_monotonic_ns": time.monotonic_ns(),
        "manager_active_after_reload_failure": manager_active,
        "bus_available_after_reload_failure": bus_available,
        "control_reachable_after_reload_failure": control_reachable,
        "quadlet_input": quadlet_input,
        "podman_generator_executed": generator_executed,
        "podman_generator_exit_status": generator_status,
        "podman_generator_accepted_actual_input": generator_status == 0,
        "generator_failures": failures,
        "generator_failure_ambiguous": generator_ambiguous,
        "selinux_avc_observed": avc_observed,
        "selinux_avc": avc,
        "selinux_avc_ambiguous": avc_ambiguous,
    }


def write_document(path: Path, document: dict[str, Any], deadline: float) -> None:
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(encoded) > MAX_OBSERVATION_BYTES:
        raise ObservationError("adjacency observation exceeds its byte bound")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".reload-adjacency.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o600)
        if time.monotonic() > deadline:
            raise ObservationError("adjacency publication missed its pre-cleanup bound")
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def admitted_fifo(path: Path, flags: int) -> IO[bytes]:
    descriptor = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISFIFO(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise ObservationError("adjacency channel is outside the closed contract")
    mode = "rb" if flags == os.O_RDONLY else "wb"
    return os.fdopen(descriptor, mode, buffering=0)


def observe(arguments: argparse.Namespace) -> int:
    acknowledgement: IO[bytes] | None = None
    try:
        event_channel = admitted_fifo(arguments.event, os.O_RDONLY)
        acknowledgement = admitted_fifo(arguments.ack, os.O_WRONLY)
        with event_channel:
            event = event_channel.readline(513)
        match = EVENT.fullmatch(event)
        if match is None or len(event) > 512:
            raise ObservationError("daemon-reload event is malformed")
        failure_status = int(match.group(1))
        frames = {int(frame) for frame in match.group(2).split(b",")}
        if failure_status > 255 or 242 not in frames:
            raise ObservationError("daemon-reload event is outside the exact call site")
        deadline = time.monotonic() + CAPTURE_DEADLINE_SECONDS
        document = collect_observation(arguments, failure_status, event)
        write_document(arguments.output, document, deadline)
        acknowledgement.write(b"SECPAL_RELOAD_ADJACENCY_CAPTURED_V1\n")
        return 0
    except (OSError, ObservationError, KeyError, pwd.error, ValueError):
        if acknowledgement is not None:
            try:
                acknowledgement.write(b"SECPAL_RELOAD_ADJACENCY_FAILED_V1\n")
            except OSError:
                pass
        return 1
    finally:
        if acknowledgement is not None:
            acknowledgement.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--event", required=True, type=Path)
    result.add_argument("--ack", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--target-sha", required=True)
    result.add_argument("--control-sha", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--run-attempt", required=True)
    result.add_argument("--boot-id", required=True)
    result.add_argument("--journal-baseline", required=True)
    result.add_argument("--audit-baseline", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    if (
        SHA.fullmatch(arguments.target_sha) is None
        or SHA.fullmatch(arguments.control_sha) is None
        or RUN_ID.fullmatch(arguments.run_id) is None
        or RUN_ATTEMPT.fullmatch(arguments.run_attempt) is None
        or BOOT_ID.fullmatch(arguments.boot_id) is None
    ):
        return 64
    return observe(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
