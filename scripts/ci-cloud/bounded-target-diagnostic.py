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
MAX_EMITTED_CHARACTERS = 8 * 1024
PHASES = frozenset({"host", "workload-prepare-start", "workload-cleanup"})


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
    tail = bytearray()
    while chunk := sys.stdin.buffer.read(64 * 1024):
        tail.extend(chunk)
        if len(tail) > MAX_CAPTURE_BYTES:
            del tail[:-MAX_CAPTURE_BYTES]
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    try:
        os.write(descriptor, tail)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    admitted_file(path, require_empty=False)


def sanitized_output(path: Path) -> str:
    admitted_file(path, require_empty=False)
    payload = path.read_bytes()
    value = payload.decode("utf-8", errors="replace")
    value = "".join(
        character
        if character in "\n\t" or ord(character) >= 0x20
        else " "
        for character in value
    )
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value).strip()
    return value[-MAX_EMITTED_CHARACTERS:]


def emit(path: Path, phase: str, status_value: str) -> None:
    if phase not in PHASES or re.fullmatch(r"[1-9][0-9]{0,2}", status_value) is None:
        raise ValueError("target diagnostic identity is outside the closed contract")
    status = int(status_value)
    if status > 255:
        raise ValueError("target diagnostic status is outside the closed contract")
    document = {
        "phase": phase,
        "status": status,
        "output": sanitized_output(path),
    }
    print(
        "Target phase diagnostic: "
        + json.dumps(document, separators=(",", ":"))
    )


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
