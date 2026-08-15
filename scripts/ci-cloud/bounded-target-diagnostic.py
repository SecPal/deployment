#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Capture and emit one bounded, inert target-phase failure diagnostic."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path


MAX_CAPTURE_BYTES = 16 * 1024
MAX_EMITTED_BYTES = 8 * 1024
PHASES = frozenset({"host", "workload-prepare-start", "workload-cleanup"})
OUTPUT_PREFIX = "Target phase diagnostic: "
TARGET_STAGE_PREFIX = b"SECPAL_TARGET_DIAGNOSTIC_V1:"
MAX_STAGE_LINE_BYTES = len(TARGET_STAGE_PREFIX) + 64
PHASE_STAGES = {
    "host": frozenset({"host-contract"}),
    "workload-prepare-start": frozenset(
        {
            "workload-target-entrypoint",
            "workload-fixture-initialization",
            "workload-runtime-admission",
            "workload-gh-cli-staging",
            "workload-api-attestation-fetch",
            "workload-api-attestation-verify",
            "workload-api-image-pull",
            "workload-api-image-admission",
            "workload-api-image-alias",
            "workload-frontend-attestation-fetch",
            "workload-frontend-attestation-verify",
            "workload-frontend-image-pull",
            "workload-frontend-image-admission",
            "workload-frontend-image-alias",
            "workload-postgres-attestation-fetch",
            "workload-postgres-attestation-verify",
            "workload-postgres-image-pull",
            "workload-postgres-image-admission",
            "workload-postgres-image-alias",
            "workload-valkey-attestation-fetch",
            "workload-valkey-attestation-verify",
            "workload-valkey-image-pull",
            "workload-valkey-image-admission",
            "workload-valkey-image-alias",
            "workload-quadlet-render-publish",
        }
    ),
    "workload-cleanup": frozenset({"workload-cleanup"}),
}
ADMITTED_STAGES = frozenset().union(*PHASE_STAGES.values())
UNREPORTED_STAGE = "unreported"


def admitted_stage(line: bytes, current: str) -> str:
    if not line.startswith(TARGET_STAGE_PREFIX):
        return current
    value = line.removeprefix(TARGET_STAGE_PREFIX)
    try:
        candidate = value.decode("ascii")
    except UnicodeDecodeError:
        return current
    return candidate if candidate in ADMITTED_STAGES else current


def admitted_file(path: Path, *, require_empty: bool) -> os.stat_result:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or (require_empty and metadata.st_size != 0)
        or metadata.st_size > MAX_CAPTURE_BYTES
    ):
        raise ValueError("target diagnostic file is outside the closed contract")
    return metadata


def capture(path: Path) -> None:
    admitted_file(path, require_empty=True)
    observed_bytes = 0
    truncated = False
    stage = UNREPORTED_STAGE
    stage_line = b""
    discarding_stage_line = False
    while chunk := sys.stdin.buffer.read(64 * 1024):
        remaining = max(0, MAX_CAPTURE_BYTES - observed_bytes)
        observed_bytes += min(len(chunk), remaining)
        if len(chunk) > remaining:
            truncated = True
        segments = chunk.split(b"\n")
        for index, segment in enumerate(segments):
            line_complete = index < len(segments) - 1
            if not discarding_stage_line:
                if len(stage_line) + len(segment) <= MAX_STAGE_LINE_BYTES:
                    stage_line += segment
                else:
                    stage_line = b""
                    discarding_stage_line = True
            if line_complete:
                if not discarding_stage_line:
                    stage = admitted_stage(stage_line, stage)
                stage_line = b""
                discarding_stage_line = False
    if stage_line and not discarding_stage_line:
        stage = admitted_stage(stage_line, stage)
    metadata = f"{observed_bytes} {int(truncated)} {stage}\n".encode("ascii")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        remaining = memoryview(metadata)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("target diagnostic write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    written_metadata = admitted_file(path, require_empty=False)
    if written_metadata.st_size != len(metadata):
        raise ValueError("target diagnostic write was incomplete")


def captured_metadata(path: Path) -> tuple[int, bool, str]:
    admitted_file(path, require_empty=False)
    payload = path.read_bytes()
    match = re.fullmatch(
        rb"(0|[1-9][0-9]{0,4}) ([01]) ([a-z0-9-]{1,64})\n",
        payload,
    )
    if match is None:
        raise ValueError("target diagnostic metadata is malformed")
    observed_bytes = int(match.group(1))
    truncated = match.group(2) == b"1"
    if observed_bytes > MAX_CAPTURE_BYTES or (
        truncated and observed_bytes != MAX_CAPTURE_BYTES
    ):
        raise ValueError("target diagnostic metadata is outside its bound")
    stage = match.group(3).decode("ascii")
    if stage != UNREPORTED_STAGE and stage not in ADMITTED_STAGES:
        raise ValueError("target diagnostic stage is outside the closed contract")
    return observed_bytes, truncated, stage


def rendered_diagnostic(path: Path, phase: str, status: int) -> str:
    output_bytes, output_truncated, captured_stage = captured_metadata(path)
    stage = (
        captured_stage
        if captured_stage in PHASE_STAGES.get(phase, frozenset())
        else UNREPORTED_STAGE
    )
    document = {
        "phase": phase,
        "status": status,
        "stage": stage,
        "output_bytes": output_bytes,
        "output_truncated": output_truncated,
    }
    rendered = OUTPUT_PREFIX + json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    if len((rendered + "\n").encode("utf-8")) > MAX_EMITTED_BYTES:
        raise ValueError("target diagnostic metadata exceeds its byte limit")
    return rendered


def emit(path: Path, phase: str, status_value: str) -> None:
    if phase not in PHASES or re.fullmatch(r"[1-9][0-9]{0,2}", status_value) is None:
        raise ValueError("target diagnostic identity is outside the closed contract")
    status = int(status_value)
    if status > 255:
        raise ValueError("target diagnostic status is outside the closed contract")
    print(rendered_diagnostic(path, phase, status))


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "capture":
        operation = lambda: capture(Path(sys.argv[2]))
    elif len(sys.argv) == 5 and sys.argv[1] == "emit":
        operation = lambda: emit(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        print("ERROR: bounded target diagnostic arguments are invalid.", file=sys.stderr)
        return 64
    try:
        operation()
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: bounded target diagnostic failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
