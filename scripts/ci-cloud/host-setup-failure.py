#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Write or read the closed, non-secret conformance host-setup failure marker."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path


MARKER_PATH = Path("/run/secpal-ci-evidence/host-setup-failure.json")
MAX_MARKER_BYTES = 128
STAGES = (
    "initialize",
    "subordinate-ids",
    "service-policy",
    "apparmor",
    "ssh",
)


def fail(message: str) -> None:
    raise ValueError(message)


def validate_directory(
    path: Path,
    required_uid: int,
    required_gid: int | None = None,
) -> None:
    if required_gid is None:
        required_gid = required_uid
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        fail("host-setup diagnostic directory has unsafe ownership or mode")


def validate_document(document: object) -> dict[str, object]:
    if not isinstance(document, dict) or set(document) != {"stage", "exit_status"}:
        fail("host-setup failure marker is not closed")
    stage = document["stage"]
    exit_status = document["exit_status"]
    if stage not in STAGES:
        fail("host-setup failure stage is invalid")
    if type(exit_status) is not int or not 1 <= exit_status <= 255:
        fail("host-setup failure status is invalid")
    return document


def validate_file_metadata(
    metadata: os.stat_result,
    required_uid: int,
    required_gid: int | None = None,
) -> None:
    if required_gid is None:
        required_gid = required_uid
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != required_uid
        or metadata.st_gid != required_gid
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or not 1 <= metadata.st_size <= MAX_MARKER_BYTES
    ):
        fail("host-setup failure marker has unsafe metadata")


def read_marker(
    path: Path,
    *,
    required_uid: int = 0,
    required_gid: int | None = None,
) -> dict[str, object]:
    validate_directory(path.parent, required_uid, required_gid)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        validate_file_metadata(os.fstat(descriptor), required_uid, required_gid)
        content = os.read(descriptor, MAX_MARKER_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(content) > MAX_MARKER_BYTES:
        fail("host-setup failure marker is oversized")
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        fail("host-setup failure marker is invalid JSON")
    return validate_document(document)


def write_marker(
    path: Path,
    stage: str,
    exit_status: int,
    *,
    required_uid: int = 0,
    required_gid: int | None = None,
) -> None:
    document = validate_document({"stage": stage, "exit_status": exit_status})
    validate_directory(path.parent, required_uid, required_gid)
    if path.exists() or path.is_symlink():
        metadata = path.stat(follow_symlinks=False)
        validate_file_metadata(metadata, required_uid, required_gid)
    content = (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )
    if len(content) > MAX_MARKER_BYTES:
        fail("host-setup failure marker is oversized")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary_path = Path(temporary_name)
    published = False
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary_path, path)
            published = True
            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if published:
            path.unlink(missing_ok=True)
        temporary_path.unlink(missing_ok=True)
        raise


def main(arguments: list[str]) -> int:
    try:
        if arguments == ["read"]:
            document = read_marker(MARKER_PATH)
            print(json.dumps(document, separators=(",", ":"), sort_keys=True))
        elif len(arguments) == 3 and arguments[0] == "write":
            if os.geteuid() != 0:
                fail("only root may write the host-setup failure marker")
            try:
                exit_status = int(arguments[2])
            except ValueError:
                fail("host-setup failure status is invalid")
            write_marker(MARKER_PATH, arguments[1], exit_status)
        else:
            fail("expected read or write with a closed stage and exit status")
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: host-setup failure marker: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
