#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Install one bounded target-produced Quadlet snapshot as root-owned input."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Callable


SCHEMA_VERSION = 1
MAX_UNIT_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 512 * 1024
INSTANCE_PATTERN = re.compile(r"[a-z0-9]{8,24}\Z")
REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
INSTALL_PATH_UNIT = "secpal-ci-quadlet-install.path"
REMOVE_PATH_UNIT = "secpal-ci-quadlet-remove.path"
REJECTION_CODES = frozenset(
    {
        "active-state-invalid",
        "cleanup-mismatch",
        "content-invalid",
        "destination-collision",
        "directory-changed",
        "file-changed",
        "file-metadata-invalid",
        "file-open-failed",
        "filenames-changed",
        "filenames-invalid",
        "fixture-active",
        "fixture-file-changed",
        "fixture-file-missing",
        "internal-error",
        "manifest-invalid",
        "operation-busy",
        "path-metadata-invalid",
        "path-unavailable",
        "request-entries-invalid",
        "request-id-invalid",
        "size-limit",
        "snapshot-incomplete",
        "trigger-stop-failed",
        "trusted-directory-invalid",
        "trusted-unit-collision",
    }
)
CONTAINER_ROLES = (
    "secrets-init",
    "postgres",
    "valkey",
    "migrate",
    "api",
    "worker-general",
    "worker-hash-chain",
    "scheduler",
    "frontend",
    "gateway",
)
NETWORKS = ("application", "edge")
VOLUMES = ("secrets", "private-storage", "postgres")


class RequestError(RuntimeError):
    """A request is incomplete, ambiguous, or outside the closed contract."""

    def __init__(self, code: str) -> None:
        if code not in REJECTION_CODES:
            raise ValueError("unknown fixture rejection code")
        super().__init__(code)
        self.code = code


class DuplicateJSONKey(ValueError):
    """A JSON object repeated a key and is therefore ambiguous."""


@dataclass(frozen=True)
class Layout:
    staging_root: Path = Path("/srv/secpal-ci")
    quadlet_root: Path = Path("/etc/containers/systemd/users/20000")
    systemd_root: Path = Path("/etc/systemd/user")
    state_root: Path = Path("/run/secpal-ci-quadlet-fixture")
    operator_uid: int = 20000
    operator_gid: int = 20000
    trusted_uid: int = 0
    trusted_gid: int = 0

    def request_path(self, operation: str) -> Path:
        validate_operation(operation)
        return self.staging_root / f"quadlet-{operation}-request"

    def ready_path(self, operation: str) -> Path:
        return self.request_path(operation) / "ready"

    def result_path(self, operation: str) -> Path:
        validate_operation(operation)
        return self.state_root / f"{operation}-result.json"

    @property
    def active_state(self) -> Path:
        return self.state_root / "active.json"

    @property
    def operation_lock(self) -> Path:
        return self.state_root / "operation.lock"

    def destination(self, name: str) -> Path:
        return (self.systemd_root if name.endswith(".target") else self.quadlet_root) / name


@dataclass(frozen=True)
class Request:
    operation: str
    instance: str
    request_id: str
    files: dict[str, bytes]


def validate_operation(operation: str) -> None:
    if operation not in {"install", "remove"}:
        raise ValueError("operation is outside the closed contract")


def expected_unit_names(instance: str) -> tuple[str, ...]:
    if not INSTANCE_PATTERN.fullmatch(instance):
        raise ValueError("invalid fixture instance")
    prefix = f"secpal-int-{instance}"
    names = [f"{prefix}-{role}.container" for role in CONTAINER_ROLES]
    names.extend(f"{prefix}-{name}.network" for name in NETWORKS)
    names.extend(f"{prefix}-{name}.volume" for name in VOLUMES)
    names.append(f"{prefix}.target")
    return tuple(sorted(names))


def exact_json_document(content: bytes, rejection_code: str) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise DuplicateJSONKey(key)
            document[key] = value
        return document

    try:
        document = json.loads(content, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJSONKey) as error:
        raise RequestError(rejection_code) from error
    if not isinstance(document, dict) or content != canonical_json(document):
        raise RequestError(rejection_code)
    return document


def exact_metadata(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    directory: bool,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RequestError("path-unavailable") from error
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
        or (not directory and metadata.st_nlink != 1)
    ):
        raise RequestError("path-metadata-invalid")
    return metadata


def bounded_regular_file(path: Path, layout: Layout, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RequestError("file-open-failed") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != layout.operator_uid
            or before.st_gid != layout.operator_gid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise RequestError("file-metadata-invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if len(content) > maximum or identity(before) != identity(after):
            raise RequestError("file-changed")
        return content
    finally:
        os.close(descriptor)


def bounded_trusted_file(
    path: Path,
    layout: Layout,
    *,
    mode: int,
    maximum: int,
    rejection_code: str,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RequestError(rejection_code) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != layout.trusted_uid
            or before.st_gid != layout.trusted_gid
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise RequestError(rejection_code)
        content = b""
        while len(content) <= maximum:
            chunk = os.read(descriptor, min(maximum + 1 - len(content), 65536))
            if not chunk:
                break
            content += chunk
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_gid,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if len(content) > maximum or identity(before) != identity(after):
            raise RequestError(rejection_code)
        return content
    finally:
        os.close(descriptor)


def request_directory_identity(operation: str, layout: Layout) -> tuple[int, int]:
    metadata = exact_metadata(
        layout.request_path(operation),
        uid=layout.operator_uid,
        gid=layout.operator_gid,
        mode=0o700,
        directory=True,
    )
    return metadata.st_dev, metadata.st_ino


def parse_request(
    operation: str,
    layout: Layout,
    directory_identity: tuple[int, int] | None = None,
) -> Request:
    validate_operation(operation)
    request_root = layout.request_path(operation)
    observed_identity = request_directory_identity(operation, layout)
    if directory_identity is not None and observed_identity != directory_identity:
        raise RequestError("directory-changed")
    expected_entries = {"manifest.json", "ready"}
    if operation == "install":
        expected_entries.add("units")
    try:
        if {path.name for path in request_root.iterdir()} != expected_entries:
            raise RequestError("request-entries-invalid")
    except OSError as error:
        raise RequestError("request-entries-invalid") from error

    ready = bounded_regular_file(request_root / "ready", layout, 33)
    try:
        request_id = ready.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError as error:
        raise RequestError("request-id-invalid") from error
    if not REQUEST_ID_PATTERN.fullmatch(request_id) or ready != f"{request_id}\n".encode():
        raise RequestError("request-id-invalid")

    manifest_bytes = bounded_regular_file(request_root / "manifest.json", layout, 512)
    manifest = exact_json_document(manifest_bytes, "manifest-invalid")
    if set(manifest) != {
        "schema_version",
        "operation",
        "instance",
        "request_id",
    }:
        raise RequestError("manifest-invalid")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != SCHEMA_VERSION
        or manifest["operation"] != operation
        or manifest["request_id"] != request_id
        or not isinstance(manifest["instance"], str)
    ):
        raise RequestError("manifest-invalid")
    instance = manifest["instance"]
    try:
        names = expected_unit_names(instance)
    except ValueError as error:
        raise RequestError("manifest-invalid") from error
    files: dict[str, bytes] = {}
    if operation == "install":
        units_root = request_root / "units"
        exact_metadata(
            units_root,
            uid=layout.operator_uid,
            gid=layout.operator_gid,
            mode=0o700,
            directory=True,
        )
        try:
            observed_names = {path.name for path in units_root.iterdir()}
        except OSError as error:
            raise RequestError("filenames-invalid") from error
        if observed_names != set(names):
            raise RequestError("filenames-invalid")
        total = 0
        for name in names:
            content = bounded_regular_file(units_root / name, layout, MAX_UNIT_BYTES)
            if b"\0" in content or not content.endswith(b"\n"):
                raise RequestError("content-invalid")
            try:
                content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RequestError("content-invalid") from error
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise RequestError("size-limit")
            files[name] = content
        if {path.name for path in units_root.iterdir()} != set(names):
            raise RequestError("filenames-changed")
    return Request(operation, instance, request_id, files)


def atomic_bytes(path: Path, content: bytes, mode: int) -> None:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("unable to complete atomic fixture write")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def remove_interrupted_atomic_writes(path: Path, layout: Layout) -> None:
    prefix = f".{path.name}."
    candidate_pattern = re.compile(
        rf"{re.escape(prefix)}(?:[a-z0-9_]{{8}}|[0-9a-f]{{32}})\Z"
    )
    try:
        candidates = tuple(
            candidate
            for candidate in path.parent.iterdir()
            if candidate_pattern.fullmatch(candidate.name)
        )
    except OSError as error:
        raise RequestError("fixture-file-changed") from error
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise RequestError("fixture-file-changed") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != layout.trusted_uid
            or metadata.st_gid != layout.trusted_gid
            or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o644}
            or metadata.st_nlink != 1
        ):
            raise RequestError("fixture-file-changed")
        try:
            candidate.unlink()
        except OSError as error:
            raise RequestError("fixture-file-changed") from error


def canonical_json(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def file_record(content: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


def validate_trusted_directory(path: Path, layout: Layout) -> None:
    exact_metadata(
        path,
        uid=layout.trusted_uid,
        gid=layout.trusted_gid,
        mode=0o755,
        directory=True,
    )


@contextmanager
def operation_lock(layout: Layout):
    validate_trusted_directory(layout.state_root, layout)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(layout.operation_lock, flags, 0o600)
    except OSError as error:
        raise RequestError("active-state-invalid") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != layout.trusted_uid
            or metadata.st_gid != layout.trusted_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise RequestError("active-state-invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RequestError("operation-busy") from error
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def ensure_trusted_directory(path: Path, layout: Layout) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o755)
        except OSError as error:
            raise RequestError("trusted-directory-invalid") from error
    validate_trusted_directory(path, layout)


def install_trusted_document(path: Path, content: bytes, layout: Layout) -> None:
    if path.exists() or path.is_symlink():
        if not trusted_file_matches(path, file_record(content), layout):
            raise RequestError("trusted-unit-collision")
        return
    atomic_bytes(path, content, 0o644)


def install(request: Request, layout: Layout) -> None:
    validate_trusted_directory(layout.quadlet_root, layout)
    validate_trusted_directory(layout.systemd_root, layout)
    validate_trusted_directory(layout.state_root, layout)
    if layout.active_state.exists() or layout.active_state.is_symlink():
        raise RequestError("fixture-active")
    if any(layout.quadlet_root.iterdir()):
        raise RequestError("destination-collision")
    names = expected_unit_names(request.instance)
    if set(request.files) != set(names):
        raise RequestError("snapshot-incomplete")
    for name in names:
        destination = layout.destination(name)
        if destination.exists() or destination.is_symlink():
            raise RequestError("destination-collision")
    state: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "state": "installing",
        "instance": request.instance,
        "files": {name: file_record(request.files[name]) for name in names},
    }
    atomic_bytes(layout.active_state, canonical_json(state), 0o400)
    installed: list[Path] = []
    try:
        for name in names:
            destination = layout.destination(name)
            atomic_bytes(destination, request.files[name], 0o644)
            installed.append(destination)
        state["state"] = "active"
        atomic_bytes(layout.active_state, canonical_json(state), 0o400)
    except BaseException:
        for destination in reversed(installed):
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
        try:
            layout.active_state.unlink()
        except FileNotFoundError:
            pass
        raise


def read_active_state(layout: Layout) -> dict[str, object]:
    content = bounded_trusted_file(
        layout.active_state,
        layout,
        mode=0o400,
        maximum=8192,
        rejection_code="active-state-invalid",
    )
    document = exact_json_document(content, "active-state-invalid")
    if set(document) != {
        "schema_version",
        "state",
        "instance",
        "files",
    } or type(document["schema_version"]) is not int:
        raise RequestError("active-state-invalid")
    return document


def trusted_file_matches(path: Path, record: object, layout: Layout) -> bool:
    if (
        not isinstance(record, dict)
        or set(record) != {"sha256", "size"}
        or type(record["size"]) is not int
        or not 0 < record["size"] <= MAX_UNIT_BYTES
        or not isinstance(record["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
    ):
        return False
    try:
        content = bounded_trusted_file(
            path,
            layout,
            mode=0o644,
            maximum=record["size"],
            rejection_code="fixture-file-changed",
        )
    except RequestError:
        return False
    return bool(
        record["size"] == len(content)
        and record["sha256"] == hashlib.sha256(content).hexdigest()
    )


def remove(request: Request, layout: Layout) -> None:
    validate_trusted_directory(layout.quadlet_root, layout)
    validate_trusted_directory(layout.systemd_root, layout)
    validate_trusted_directory(layout.state_root, layout)
    state = read_active_state(layout)
    names = expected_unit_names(request.instance)
    if (
        state["schema_version"] != SCHEMA_VERSION
        or state["state"] not in {"installing", "active", "removing"}
        or state["instance"] != request.instance
        or not isinstance(state["files"], dict)
        or set(state["files"]) != set(names)
    ):
        raise RequestError("cleanup-mismatch")
    existing: list[Path] = []
    for name in names:
        destination = layout.destination(name)
        remove_interrupted_atomic_writes(destination, layout)
        if not destination.exists() and not destination.is_symlink():
            if state["state"] == "active":
                raise RequestError("fixture-file-missing")
            continue
        if not trusted_file_matches(destination, state["files"][name], layout):
            raise RequestError("fixture-file-changed")
        existing.append(destination)
    if state["state"] != "removing":
        state["state"] = "removing"
        atomic_bytes(layout.active_state, canonical_json(state), 0o400)
    for destination in existing:
        destination.unlink()
    layout.active_state.unlink()


def publish_result(
    operation: str,
    request_id: str,
    instance: str,
    result: str,
    reason: str,
    layout: Layout,
) -> None:
    if result not in {"installed", "removed", "rejected", "retrying"}:
        raise ValueError("invalid fixture result")
    if reason != "none" and reason not in REJECTION_CODES:
        raise ValueError("invalid fixture result reason")
    if (result in {"rejected", "retrying"}) == (reason == "none"):
        raise ValueError("fixture result and reason do not match")
    document = {
        "schema_version": SCHEMA_VERSION,
        "operation": operation,
        "instance": instance,
        "request_id": request_id,
        "result": result,
        "reason": reason,
    }
    atomic_bytes(layout.result_path(operation), canonical_json(document), 0o444)


def ready_identity(operation: str, layout: Layout) -> str:
    try:
        content = bounded_regular_file(layout.ready_path(operation), layout, 33)
        value = content.decode("ascii").removesuffix("\n")
    except (RequestError, UnicodeDecodeError):
        return "0" * 32
    return value if REQUEST_ID_PATTERN.fullmatch(value) else "0" * 32


def stop_path_trigger(
    trigger: str,
    stop_trigger: Callable[[str], object] | None,
) -> None:
    if stop_trigger is None:
        try:
            subprocess.run(
                ["systemctl", "stop", trigger],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RequestError("trigger-stop-failed") from error
    else:
        stop_trigger(trigger)


def handle_request(
    operation: str,
    layout: Layout = Layout(),
    stop_trigger: Callable[[str], object] | None = None,
) -> bool:
    validate_operation(operation)
    trigger = INSTALL_PATH_UNIT if operation == "install" else REMOVE_PATH_UNIT
    request_id = "0" * 32
    instance = "unknown"
    try:
        if operation == "install":
            stop_path_trigger(trigger, stop_trigger)
        with operation_lock(layout):
            request_id = ready_identity(operation, layout)
            directory_identity = request_directory_identity(operation, layout)
            request = parse_request(operation, layout, directory_identity)
            request_id = request.request_id
            instance = request.instance
            if operation == "install":
                install(request, layout)
                result = "installed"
            else:
                remove(request, layout)
                result = "removed"
                stop_path_trigger(trigger, stop_trigger)
            publish_result(operation, request_id, instance, result, "none", layout)
        return True
    except RequestError as error:
        if operation == "remove":
            try:
                stop_path_trigger(trigger, stop_trigger)
            except RequestError:
                error = RequestError("trigger-stop-failed")
        try:
            publish_result(
                operation, request_id, instance, "rejected", error.code, layout
            )
        except OSError:
            pass
        return False
    except Exception:
        retrying = False
        if operation == "remove":
            try:
                retrying = read_active_state(layout)["state"] == "removing"
            except RequestError:
                pass
        if retrying:
            try:
                publish_result(
                    operation,
                    request_id,
                    instance,
                    "retrying",
                    "internal-error",
                    layout,
                )
            except OSError:
                pass
            return False
        if operation == "remove":
            try:
                stop_path_trigger(trigger, stop_trigger)
            except RequestError:
                pass
        try:
            publish_result(
                operation, request_id, instance, "rejected", "internal-error", layout
            )
        except OSError:
            pass
        return False


def systemd_unit_documents(layout: Layout = Layout()) -> dict[str, str]:
    documents: dict[str, str] = {}
    for operation, path_unit in (
        ("install", INSTALL_PATH_UNIT),
        ("remove", REMOVE_PATH_UNIT),
    ):
        service_unit = path_unit.removesuffix(".path") + ".service"
        service = f"""[Unit]
Description=Process one bounded SecPal CI Quadlet {operation} request

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/secpal-ci-quadlet-fixture-installer process {operation}
NoNewPrivileges=true
PrivateDevices=true
PrivateNetwork=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={layout.quadlet_root} {layout.systemd_root} {layout.state_root}
RestrictAddressFamilies=AF_UNIX
UMask=0077
TimeoutStartSec=30s
"""
        path = f"""[Unit]
Description=Watch the fixed SecPal CI Quadlet {operation} request

[Path]
PathExists={layout.ready_path(operation)}
Unit={service_unit}
TriggerLimitIntervalSec=60s
TriggerLimitBurst=3

[Install]
WantedBy=multi-user.target
"""
        documents[service_unit] = service
        documents[path_unit] = path
    return documents


def setup(layout: Layout = Layout()) -> None:
    if os.geteuid() != 0:
        raise RequestError("trusted-directory-invalid")
    for path in (layout.quadlet_root, layout.systemd_root, layout.state_root):
        ensure_trusted_directory(path, layout)
    unit_root = Path("/etc/systemd/system")
    validate_trusted_directory(unit_root, layout)
    unit_paths: list[str] = []
    for name, document in systemd_unit_documents(layout).items():
        destination = unit_root / name
        install_trusted_document(destination, document.encode(), layout)
        unit_paths.append(os.fspath(destination))
    subprocess.run(
        ["systemd-analyze", "verify", *unit_paths],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=15)
    subprocess.run(
        ["systemctl", "start", INSTALL_PATH_UNIT, REMOVE_PATH_UNIT],
        check=True,
        timeout=15,
    )
    subprocess.run(
        ["systemctl", "is-active", "--quiet", INSTALL_PATH_UNIT, REMOVE_PATH_UNIT],
        check=True,
        timeout=15,
    )


def main(argv: list[str]) -> int:
    if os.geteuid() != 0:
        return 1
    if argv == ["setup"]:
        try:
            setup()
        except (OSError, RequestError, subprocess.SubprocessError):
            return 1
        return 0
    if len(argv) == 2 and argv[0] == "process" and argv[1] in {"install", "remove"}:
        handle_request(argv[1])
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
