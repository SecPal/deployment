#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Publish and await one fixed-path Quadlet fixture request."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time


SCHEMA_VERSION = 1
MAX_UNIT_BYTES = 64 * 1024
INSTANCE_PATTERN = re.compile(r"[a-z0-9]{8,24}\Z")
CONTAINER_ROLES = (
    "secrets-init", "postgres", "valkey", "migrate", "api",
    "worker-general", "worker-hash-chain", "scheduler", "frontend", "gateway",
)
NETWORKS = ("application", "edge")
VOLUMES = ("secrets", "private-storage", "postgres")
TRUSTED_SERVICE_SECTION = (
    b"\n[Service]\n"
    b"Environment=CONTAINERS_CONF=/dev/null\n"
    b"Environment=CONTAINERS_CONF_OVERRIDE=/dev/null\n"
    b"Environment=CONTAINERS_CONF_MODULES=\n"
    b"Environment=PODMAN_USERNS=\n"
)


@dataclass(frozen=True)
class Layout:
    staging_root: Path = Path("/srv/secpal-ci")
    state_root: Path = Path("/run/secpal-ci-quadlet-fixture")

    def request_path(self, operation: str) -> Path:
        return self.staging_root / f"quadlet-{operation}-request"

    def result_path(self, operation: str) -> Path:
        return self.state_root / f"{operation}-result.json"


def expected_unit_names(instance: str) -> tuple[str, ...]:
    if not INSTANCE_PATTERN.fullmatch(instance):
        raise ValueError("invalid fixture instance")
    prefix = f"secpal-int-{instance}"
    names = [f"{prefix}-{role}.container" for role in CONTAINER_ROLES]
    names.extend(f"{prefix}-{name}.network" for name in NETWORKS)
    names.extend(f"{prefix}-{name}.volume" for name in VOLUMES)
    names.append(f"{prefix}.target")
    return tuple(sorted(names))


def secure_read(source: Path) -> tuple[bytes, int]:
    metadata = source.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= MAX_UNIT_BYTES
    ):
        raise ValueError("source unit is not a bounded owned regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        if (
            metadata.st_dev != before.st_dev
            or metadata.st_ino != before.st_ino
            or metadata.st_mode != before.st_mode
            or metadata.st_uid != before.st_uid
            or metadata.st_gid != before.st_gid
            or metadata.st_nlink != before.st_nlink
            or metadata.st_size != before.st_size
            or metadata.st_mtime_ns != before.st_mtime_ns
            or metadata.st_ctime_ns != before.st_ctime_ns
        ):
            raise ValueError("source unit changed or is not bounded text")
        chunks: list[bytes] = []
        remaining = MAX_UNIT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(content) > MAX_UNIT_BYTES
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mode != after.st_mode
        or before.st_uid != after.st_uid
        or before.st_gid != after.st_gid
        or before.st_nlink != after.st_nlink
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or b"\0" in content
        or not content.endswith(b"\n")
    ):
        raise ValueError("source unit changed or is not bounded text")
    content.decode("utf-8")
    return content, stat.S_IMODE(before.st_mode)


def canonical_unit_content(name: str, content: bytes) -> bytes:
    if not name.endswith(".target") and not content.endswith(TRUSTED_SERVICE_SECTION):
        content += TRUSTED_SERVICE_SECTION
    if len(content) > MAX_UNIT_BYTES:
        raise ValueError("trusted unit expansion exceeds the size limit")
    return content


def atomic_replace_owned_source(path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def stage_request(
    operation: str,
    instance: str,
    source: Path | None,
    layout: Layout = Layout(),
) -> str:
    if operation not in {"install", "remove"}:
        raise ValueError("invalid operation")
    names = expected_unit_names(instance)
    request = layout.request_path(operation)
    if request.exists() or request.is_symlink():
        raise ValueError("a request is already pending")
    if layout.staging_root.is_symlink() or not layout.staging_root.is_dir():
        raise ValueError("fixed staging root is unavailable")
    temporary = Path(
        tempfile.mkdtemp(prefix=f".quadlet-{operation}.", dir=layout.staging_root)
    )
    temporary.chmod(0o700)
    request_id = secrets.token_hex(16)
    try:
        if operation == "install":
            if source is None or source.is_symlink() or not source.is_dir():
                raise ValueError("install source must be a real directory")
            if {path.name for path in source.iterdir()} != set(names):
                raise ValueError("install source differs from the closed filename set")
            units = temporary / "units"
            units.mkdir(mode=0o700)
            snapshots: dict[str, tuple[bytes, bytes, int]] = {}
            for name in names:
                content, mode = secure_read(source / name)
                snapshots[name] = (
                    content,
                    canonical_unit_content(name, content),
                    mode,
                )
            for name in names:
                original, content, mode = snapshots[name]
                if content != original:
                    atomic_replace_owned_source(source / name, content, mode)
                destination = units / name
                destination.write_bytes(content)
                destination.chmod(0o600)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "operation": operation,
            "instance": instance,
            "request_id": request_id,
        }
        manifest_path = temporary / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        ready = temporary / "ready"
        ready.write_text(f"{request_id}\n", encoding="ascii")
        ready.chmod(0o600)
        temporary.rename(request)
    except BaseException:
        shutil.rmtree(temporary)
        raise
    return request_id


def clear_request(operation: str, layout: Layout = Layout()) -> None:
    request = layout.request_path(operation)
    if request.exists() and not request.is_symlink():
        shutil.rmtree(request)


def wait_for_result(
    operation: str,
    instance: str,
    request_id: str,
    layout: Layout = Layout(),
) -> bool:
    expected = "installed" if operation == "install" else "removed"
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        path = layout.result_path(operation)
        try:
            metadata = path.lstat()
            if (
                stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and metadata.st_uid == 0
                and metadata.st_gid == 0
                and stat.S_IMODE(metadata.st_mode) == 0o444
                and metadata.st_nlink == 1
                and 0 < metadata.st_size <= 512
            ):
                result = json.loads(path.read_text(encoding="utf-8"))
                if (
                    isinstance(result, dict)
                    and set(result) == {
                        "schema_version",
                        "operation",
                        "instance",
                        "request_id",
                        "reason",
                        "result",
                    }
                    and type(result["schema_version"]) is int
                    and result["schema_version"] == SCHEMA_VERSION
                    and result["operation"] == operation
                    and result["instance"] == instance
                    and result["request_id"] == request_id
                    and isinstance(result["reason"], str)
                    and re.fullmatch(r"[a-z0-9-]{1,64}", result["reason"])
                    is not None
                    and (
                        (result["result"] == expected and result["reason"] == "none")
                        or (
                            result["result"] == "rejected"
                            and result["reason"] != "none"
                        )
                    )
                ):
                    return result["result"] == expected
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
        time.sleep(0.1)
    return False


def main(argv: list[str]) -> int:
    if os.getuid() != 20000 or os.getgid() != 20000:
        return 1
    if len(argv) not in {2, 3} or argv[0] not in {"install", "remove"}:
        return 1
    operation, instance = argv[:2]
    source = Path(argv[2]) if len(argv) == 3 else None
    if (operation == "install") != (source is not None):
        return 1
    try:
        request_id = stage_request(operation, instance, source)
        accepted = wait_for_result(operation, instance, request_id)
    except (OSError, UnicodeError, ValueError):
        return 1
    finally:
        try:
            clear_request(operation)
        except OSError:
            pass
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
