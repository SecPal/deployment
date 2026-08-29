#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate and prepare the closed production state contract.

Production mode validates exact canonical paths and metadata. Fixture mode is
explicitly rooted in a disposable directory and never mutates a production
path. This tool creates directories only; production secret bytes are always
created and delivered by their named external authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config" / "production" / "state-contract.json"
APP_KEY_PATTERN = re.compile(rb"base64:[A-Za-z0-9+/]{43}=\n?\Z")
PASSWORD_PATTERN = re.compile(rb"[A-Za-z0-9._~!#$%&*+\-/=?^]{24,128}\n?\Z")
EXPECTED_OBJECTS_DIGEST = "41b846f699d09344fefb12746ae8cf720307edaec579b4f476fad97490b610b2"
EXPECTED_TOP_LEVEL = {
    "$comment",
    "schema_version",
    "rootless_mapping",
    "state_policy",
    "log_policy",
    "secret_policy",
    "secret_delivery",
    "objects",
}
EXPECTED_ROW_FIELDS = {
    "authority",
    "durability",
    "reconstructable",
    "loss_acceptable",
    "restore_required",
    "backup",
    "confidentiality",
    "integrity",
    "location",
    "consumers",
    "container_identity",
    "host_ownership",
    "type",
    "owner",
    "group",
    "mode",
    "acl",
    "initialization_authority",
    "rotation_migration_authority",
    "destruction_authority",
}
EXPECTED_OBJECTS = {
    "postgresql_data",
    "private_application_storage",
    "public_application_storage",
    "app_key",
    "app_previous_keys",
    "tenant_kek",
    "postgresql_credentials",
    "valkey_credentials",
    "external_service_credentials",
    "valkey_state",
    "acme_state",
    "crowdsec_state",
    "logs",
    "configuration",
    "deployment_state",
    "backup_encryption_credentials",
    "tls_private_keys",
    "operator_ssh_credentials",
    "github_credentials",
    "registry_credentials",
}
ACTIVE_STATE_OBJECTS = (
    "postgresql_data",
    "private_application_storage",
    "public_application_storage",
    "valkey_state",
    "logs",
    "configuration",
    "deployment_state",
)
RESERVED_STATE_OBJECTS = ("acme_state", "crowdsec_state")
EXPECTED_STATE_LAYOUT = {
    "postgresql_data": (
        "/srv/secpal/postgresql",
        "mapped-container-uid-999",
        "mapped-container-gid-999",
        "0700",
    ),
    "private_application_storage": (
        "/srv/secpal/private-storage",
        "mapped-container-uid-10001",
        "mapped-container-gid-10001",
        "0750",
    ),
    "public_application_storage": (
        "/srv/secpal/public-storage",
        "mapped-container-uid-10001",
        "mapped-container-gid-10001",
        "0750",
    ),
    "valkey_state": (
        "/srv/secpal/valkey",
        "mapped-container-uid-10002",
        "mapped-container-gid-10002",
        "0700",
    ),
    "logs": ("/srv/secpal/logs", "service-account-uid", "service-account-gid", "0750"),
    "configuration": ("/srv/secpal/config", "root", "service-account-gid", "0750"),
    "deployment_state": (
        "/srv/secpal/deployment-state",
        "root",
        "service-account-gid",
        "0750",
    ),
}
EXPECTED_RESERVED_LAYOUT = {
    "acme_state": ("/srv/secpal/acme", "0700"),
    "crowdsec_state": ("/srv/secpal/crowdsec", "0750"),
}
EXPECTED_SECRET_DELIVERY = {
    "api": {
        "directory": "/run/secpal/secrets/api",
        "container_uid": 10001,
        "container_gid": 10001,
        "directory_mode": "0710",
        "consumers": ["api", "migrate", "scheduler", "worker-general", "worker-hash-chain"],
        "files": {
            "app-key": {"mode": "0400", "type": "app-key"},
            "app-previous-keys": {"mode": "0400", "type": "app-previous-keys"},
            "tenant-kek": {"mode": "0600", "type": "tenant-kek"},
            "postgres-password": {"mode": "0400", "type": "password"},
            "valkey-password": {"mode": "0400", "type": "password"},
        },
    },
    "valkey": {
        "directory": "/run/secpal/secrets/valkey",
        "container_uid": 10002,
        "container_gid": 10002,
        "directory_mode": "0710",
        "consumers": ["valkey"],
        "files": {"password": {"mode": "0400", "type": "password"}},
    },
}


class ContractError(RuntimeError):
    """A bounded contract failure that never includes secret content."""


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def fail(message: str) -> None:
    raise ContractError(message)


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            fail("production state contract path is unsafe")
        contract = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_closed_json_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ContractError("production state contract cannot be read") from error
    if not isinstance(contract, dict) or set(contract) != EXPECTED_TOP_LEVEL:
        fail("production state contract has an unexpected top-level shape")
    if contract["schema_version"] != 1:
        fail("production state contract schema version is unsupported")
    if contract["$comment"] != (
        "SPDX-FileCopyrightText: 2026 SecPal Contributors; "
        "SPDX-License-Identifier: CC0-1.0"
    ):
        fail("production state contract provenance is unsupported")
    objects = contract.get("objects")
    if not isinstance(objects, dict) or set(objects) != EXPECTED_OBJECTS:
        fail("production persistence matrix is incomplete")
    for row in objects.values():
        if not isinstance(row, dict) or set(row) != EXPECTED_ROW_FIELDS:
            fail("production persistence matrix row has an unexpected shape")
    objects_digest = hashlib.sha256(
        json.dumps(objects, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if objects_digest != EXPECTED_OBJECTS_DIGEST:
        fail("production persistence matrix semantics are unsupported")
    mapping = contract.get("rootless_mapping")
    if not isinstance(mapping, dict) or set(mapping) != {
        "method", "service_uid", "service_gid", "uid_start", "gid_start", "count"
    }:
        fail("rootless mapping contract is malformed")
    if mapping["method"] != "podman-default-single-range" or mapping["count"] != 65536:
        fail("rootless mapping method is unsupported")
    for kind in ("uid", "gid"):
        service_id = mapping[f"service_{kind}"]
        start = mapping[f"{kind}_start"]
        if (
            isinstance(service_id, bool)
            or not isinstance(service_id, int)
            or not 1000 <= service_id <= 60000
            or isinstance(start, bool)
            or not isinstance(start, int)
            or start <= 60000
            or start <= service_id < start + mapping["count"]
            or start + mapping["count"] - 1 > 4294967294
        ):
            fail("rootless mapping host ranges are unsupported")
    for identity in (101, 999, 10001, 10002):
        map_rootless_id(identity, mapping, "uid")
        map_rootless_id(identity, mapping, "gid")
    log_policy = contract.get("log_policy")
    if not isinstance(log_policy, dict) or log_policy != {
        "driver": "k8s-file",
        "directory": objects["logs"]["location"],
        "file_name": "{container_name}.log",
        "maximum_file_size": "10mb",
        "consumer_access": "none",
    }:
        fail("production log policy is malformed")
    state_policy = contract.get("state_policy")
    if not isinstance(state_policy, dict) or set(state_policy) != {
        "initialization_marker",
        "marker_mode",
        "marker_content",
        "first_install_requires_explicit_ack",
    }:
        fail("production state policy is malformed")
    if (
        state_policy["initialization_marker"]
        != "/srv/secpal/deployment-state/state-layout-v1"
        or state_policy["marker_mode"] != "0640"
        or state_policy["marker_content"] != "secpal-production-state-v1"
        or state_policy["first_install_requires_explicit_ack"] is not True
    ):
        fail("production state initialization policy is unsupported")
    secret_policy = contract.get("secret_policy")
    if secret_policy != {
        "max_previous_keys": 3,
        "delivery_root": "/run/secpal/secrets",
        "publication": "operator-atomic-complete-set",
        "acl": "access-only-base-entries-no-default-acl",
    }:
        fail("production secret policy is unsupported")
    if contract.get("secret_delivery") != EXPECTED_SECRET_DELIVERY:
        fail("production secret consumer contract is unsupported")
    for name, expected in EXPECTED_STATE_LAYOUT.items():
        row = objects[name]
        observed = (row["location"], row["owner"], row["group"], row["mode"])
        if observed != expected:
            fail("production state layout row is unsupported")
    for name, expected in EXPECTED_RESERVED_LAYOUT.items():
        row = objects[name]
        if (row["location"], row["mode"]) != expected:
            fail("reserved production state row is unsupported")
    return contract


def map_rootless_id(container_id: object, mapping: dict[str, Any], kind: str) -> int:
    if kind not in {"uid", "gid"}:
        fail("rootless mapping identity kind is unsupported")
    if isinstance(container_id, bool) or not isinstance(container_id, int):
        fail("container identity is not an integer")
    count = mapping.get("count")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count != 65536
        or container_id < 0
        or container_id > count
    ):
        fail("container identity is outside the reviewed rootless mapping")
    service_id = mapping[f"service_{kind}"]
    start = mapping[f"{kind}_start"]
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (service_id, start)):
        fail("rootless mapping contains a malformed host identity")
    host_id = service_id if container_id == 0 else start + container_id - 1
    if not 0 <= host_id <= 4294967294:
        fail("mapped host identity is outside the supported system range")
    return host_id


def _fixture_path(root: Path, absolute: str) -> Path:
    pure = PurePosixPath(absolute)
    if not pure.is_absolute() or pure == PurePosixPath("/") or ".." in pure.parts:
        fail("state path is not a canonical absolute path")
    return root.joinpath(*pure.parts[1:])


def _validate_fixture_root(root: Path) -> Path:
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        fail("fixture root is unsafe")
    _assert_safe_component(root, True)
    metadata = root.lstat()
    if (
        metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        fail("fixture root ownership or mode is unsafe")
    _assert_no_extended_acl(root)
    return root


def _validate_fixture_chain(root: Path, path: Path, *, create: bool) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ContractError("fixture path escaped its root") from error
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            _assert_safe_component(current, True)
            continue
        if not create:
            fail("required state artifact is missing")
        current.mkdir(mode=0o700)


def _mode(value: str) -> int:
    if re.fullmatch(r"0[0-7]{3}", value) is None:
        fail("state mode is malformed")
    return int(value, 8)


def _assert_safe_component(path: Path, expected_directory: bool, mode: int | None = None) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ContractError("required state artifact is missing") from error
    if stat.S_ISLNK(metadata.st_mode):
        fail("state path contains a symbolic link")
    if expected_directory and not stat.S_ISDIR(metadata.st_mode):
        fail("state path has the wrong file type")
    if not expected_directory and not stat.S_ISREG(metadata.st_mode):
        fail("secret path has the wrong file type")
    if not expected_directory and metadata.st_nlink != 1:
        fail("secret file has an unexpected hard link")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        fail("state artifact mode is unsafe")


def _assert_no_extended_acl(path: Path) -> None:
    if shutil.which("getfacl") is None:
        fail("required ACL inspection tool is unavailable")
    result = subprocess.run(
        ["getfacl", "-cp", "--", os.fspath(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail("state ACL cannot be inspected")
    entries = [line for line in result.stdout.splitlines() if line and not line.startswith("#")]
    allowed = {"user::", "group::", "other::"}
    for entry in entries:
        prefix = ":".join(entry.split(":")[:2]) + ":"
        if prefix not in allowed:
            fail("state ACL grants unexpected effective access")


def _assert_owner(path: Path, uid: int, gid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ContractError("state ownership cannot be inspected") from error
    if metadata.st_uid != uid or metadata.st_gid != gid:
        fail("state artifact owner or group is incorrect")


def _production_identity(
    contract: dict[str, Any], symbolic: str, kind: str, *, namespace_view: bool
) -> int:
    mapping = contract["rootless_mapping"]
    container_id_match = re.fullmatch(r"mapped-container-(?:uid|gid)-([0-9]+)", symbolic)
    if container_id_match is not None:
        container_id = int(container_id_match.group(1))
        return container_id if namespace_view else map_rootless_id(container_id, mapping, kind)
    if symbolic == "service-account-uid":
        return 0 if namespace_view else mapping["service_uid"]
    if symbolic == "service-account-gid":
        return 0 if namespace_view else mapping["service_gid"]
    if symbolic == "root":
        return 65534 if namespace_view else 0
    fail("state owner is not materialized by D.2")


def _validate_trusted_ancestors(
    path: Path, stop: Path = Path("/"), *, expected_uid: int = 0
) -> None:
    current = path.parent
    while True:
        _assert_safe_component(current, True)
        metadata = current.lstat()
        if metadata.st_uid != expected_uid:
            fail("trusted state ancestor is not root-owned")
        _assert_no_extended_acl(current)
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            fail("trusted state ancestor is group-writable or world-writable")
        if current == stop:
            break
        parent = current.parent
        if parent == current:
            fail("trusted state ancestor boundary is unreachable")
        current = parent


def _state_directories(contract: dict[str, Any], include_reserved: bool = False):
    names = (*ACTIVE_STATE_OBJECTS, *(RESERVED_STATE_OBJECTS if include_reserved else ()))
    for name in names:
        row = contract["objects"][name]
        yield name, row["location"], _mode(row["mode"])


def initialize_fixture(contract: dict[str, Any], root: Path) -> None:
    root = _validate_fixture_root(root)
    for _name, absolute, mode in _state_directories(contract):
        path = _fixture_path(root, absolute)
        _validate_fixture_chain(root, path.parent, create=True)
        if path.exists() or path.is_symlink():
            _assert_safe_component(path, True, mode)
            _assert_no_extended_acl(path)
            continue
        path.mkdir(mode=mode)
        path.chmod(mode)
    for delivery in contract["secret_delivery"].values():
        path = _fixture_path(root, delivery["directory"])
        _validate_fixture_chain(root, path.parent, create=True)
        if path.exists() or path.is_symlink():
            _assert_safe_component(path, True, _mode(delivery["directory_mode"]))
        else:
            path.mkdir(mode=_mode(delivery["directory_mode"]))
            path.chmod(_mode(delivery["directory_mode"]))
        _assert_no_extended_acl(path)
    validate_fixture(contract, root)


def _validate_secret(path: Path, secret_type: str, mode: int, max_previous: int) -> None:
    _assert_safe_component(path, False, mode)
    _assert_no_extended_acl(path)
    try:
        value = path.read_bytes()
    except OSError as error:
        raise ContractError("secret file cannot be read") from error
    if secret_type == "app-key":
        valid = APP_KEY_PATTERN.fullmatch(value) is not None
    elif secret_type == "app-previous-keys":
        normalized = value[:-1] if value.endswith(b"\n") else value
        lines = [] if normalized == b"" else normalized.split(b"\n")
        valid = len(lines) <= max_previous and len(set(lines)) == len(lines) and all(
            APP_KEY_PATTERN.fullmatch(line) is not None for line in lines
        )
    elif secret_type == "tenant-kek":
        valid = len(value) == 32
    elif secret_type == "password":
        valid = PASSWORD_PATTERN.fullmatch(value) is not None
    else:
        fail("secret type is unsupported")
    if not valid:
        fail("secret file is malformed")


def validate_fixture(
    contract: dict[str, Any], root: Path, *, require_secrets: bool = False
) -> None:
    root = _validate_fixture_root(root)
    for _name, absolute, mode in _state_directories(contract):
        path = _fixture_path(root, absolute)
        _validate_fixture_chain(root, path.parent, create=False)
        _assert_safe_component(path, True, mode)
        _assert_no_extended_acl(path)
    expected_files: set[Path] = set()
    for delivery in contract["secret_delivery"].values():
        directory = _fixture_path(root, delivery["directory"])
        _validate_fixture_chain(root, directory.parent, create=False)
        _assert_safe_component(directory, True, _mode(delivery["directory_mode"]))
        _assert_no_extended_acl(directory)
        for name, spec in delivery["files"].items():
            path = directory / name
            expected_files.add(path)
            if require_secrets:
                _validate_secret(
                    path,
                    spec["type"],
                    _mode(spec["mode"]),
                    contract["secret_policy"]["max_previous_keys"],
                )
        if require_secrets:
            actual = {entry for entry in directory.iterdir()}
            if actual != {path for path in expected_files if path.parent == directory}:
                fail("secret delivery contains a partial set or unexpected material")


def _production_secret_expected_owner(
    contract: dict[str, Any], delivery: dict[str, Any], *, namespace_view: bool
) -> tuple[int, int]:
    uid = delivery["container_uid"]
    gid = delivery["container_gid"]
    if namespace_view:
        return uid, gid
    mapping = contract["rootless_mapping"]
    return map_rootless_id(uid, mapping, "uid"), map_rootless_id(gid, mapping, "gid")


def _validate_secret_deliveries(
    contract: dict[str, Any], *, namespace_view: bool, require_secrets: bool
) -> None:
    root = Path(contract["secret_policy"]["delivery_root"])
    _assert_safe_component(root, True, 0o710)
    _assert_no_extended_acl(root)
    retired_server_delivery = root / "postgres"
    if retired_server_delivery.exists() or retired_server_delivery.is_symlink():
        fail("retired PostgreSQL server secret delivery remains")
    expected_root_uid = 65534 if namespace_view else 0
    expected_root_gid = 0 if namespace_view else contract["rootless_mapping"]["service_gid"]
    _assert_owner(root, expected_root_uid, expected_root_gid)
    for delivery in contract["secret_delivery"].values():
        directory = Path(delivery["directory"])
        _assert_safe_component(directory, True, _mode(delivery["directory_mode"]))
        _assert_no_extended_acl(directory)
        _assert_owner(directory, expected_root_uid, expected_root_gid)
        expected_paths = {directory / name for name in delivery["files"]}
        if require_secrets and not namespace_view:
            actual_paths = set(directory.iterdir())
            if actual_paths != expected_paths:
                fail("secret delivery contains a partial set or unexpected material")
        owner_uid, owner_gid = _production_secret_expected_owner(
            contract, delivery, namespace_view=namespace_view
        )
        if require_secrets:
            for name, spec in delivery["files"].items():
                path = directory / name
                _assert_owner(path, owner_uid, owner_gid)
                if namespace_view:
                    _assert_safe_component(path, False, _mode(spec["mode"]))
                    _assert_no_extended_acl(path)
                else:
                    _validate_secret(
                        path,
                        spec["type"],
                        _mode(spec["mode"]),
                        contract["secret_policy"]["max_previous_keys"],
                    )
    if require_secrets and not namespace_view:
        api = Path(contract["secret_delivery"]["api"]["directory"])
        valkey = Path(contract["secret_delivery"]["valkey"]["directory"])
        if (api / "valkey-password").read_bytes() != (valkey / "password").read_bytes():
            fail("Valkey consumer credential copies do not match")
        active_raw = (api / "app-key").read_bytes()
        active_key = active_raw[:-1] if active_raw.endswith(b"\n") else active_raw
        previous_raw = (api / "app-previous-keys").read_bytes()
        previous_normalized = previous_raw[:-1] if previous_raw.endswith(b"\n") else previous_raw
        previous_keys = [] if previous_normalized == b"" else previous_normalized.split(b"\n")
        if active_key in previous_keys:
            fail("active APP_KEY is duplicated in APP_PREVIOUS_KEYS")


def validate_production(
    contract: dict[str, Any],
    *,
    namespace_view: bool,
    require_secrets: bool,
    require_marker: bool = True,
) -> None:
    for name, absolute, mode in _state_directories(contract):
        path = Path(absolute)
        _assert_safe_component(path, True, mode)
        _assert_no_extended_acl(path)
        row = contract["objects"][name]
        expected_uid = _production_identity(
            contract, row["owner"], "uid", namespace_view=namespace_view
        )
        expected_gid = _production_identity(
            contract, row["group"], "gid", namespace_view=namespace_view
        )
        _assert_owner(path, expected_uid, expected_gid)
        _validate_trusted_ancestors(path, expected_uid=65534 if namespace_view else 0)
    _validate_secret_deliveries(
        contract, namespace_view=namespace_view, require_secrets=require_secrets
    )
    secret_parent = Path(contract["secret_policy"]["delivery_root"]).parent
    _assert_safe_component(secret_parent, True, 0o710)
    parent_uid = 65534 if namespace_view else 0
    parent_gid = 0 if namespace_view else contract["rootless_mapping"]["service_gid"]
    _assert_owner(secret_parent, parent_uid, parent_gid)
    _assert_no_extended_acl(secret_parent)
    ancestor_uid = 65534 if namespace_view else 0
    _validate_trusted_ancestors(secret_parent, expected_uid=ancestor_uid)
    _validate_trusted_ancestors(
        Path(contract["secret_policy"]["delivery_root"]), expected_uid=ancestor_uid
    )
    if require_marker:
        marker = Path(contract["state_policy"]["initialization_marker"])
        _assert_safe_component(marker, False, _mode(contract["state_policy"]["marker_mode"]))
        expected_uid = 65534 if namespace_view else 0
        expected_gid = 0 if namespace_view else contract["rootless_mapping"]["service_gid"]
        _assert_owner(marker, expected_uid, expected_gid)
        expected = (contract["state_policy"]["marker_content"] + "\n").encode()
        if marker.read_bytes() != expected:
            fail("production state initialization marker is malformed")


def _create_production_directory(path: Path, mode: int, uid: int, gid: int) -> None:
    if path.exists() or path.is_symlink():
        _assert_safe_component(path, True, mode)
        _assert_owner(path, uid, gid)
        _assert_no_extended_acl(path)
        return
    if not path.parent.is_dir() or path.parent.is_symlink():
        fail("production state parent must be prepared explicitly")
    _validate_trusted_ancestors(path)
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)
    _assert_no_extended_acl(path)


def initialize_production(
    contract: dict[str, Any],
    *,
    first_install_ack: bool,
    initial_secret_source: Path | None,
) -> None:
    if os.geteuid() != 0:
        fail("production initialization requires operator root authority")
    if not first_install_ack or not contract["state_policy"][
        "first_install_requires_explicit_ack"
    ]:
        fail("production initialization requires explicit first-install acknowledgement")
    marker = Path(contract["state_policy"]["initialization_marker"])
    if marker.exists() or marker.is_symlink():
        if initial_secret_source is not None:
            fail("initial secret source is invalid after state initialization")
        validate_production(
            contract, namespace_view=False, require_secrets=True, require_marker=True
        )
        return
    mapping = contract["rootless_mapping"]
    srv_root = Path("/srv/secpal")
    run_root = Path("/run/secpal")
    _create_production_directory(srv_root, 0o755, 0, 0)
    _create_production_directory(run_root, 0o710, 0, mapping["service_gid"])
    for name, absolute, mode in _state_directories(contract):
        row = contract["objects"][name]
        uid = _production_identity(contract, row["owner"], "uid", namespace_view=False)
        gid = _production_identity(contract, row["group"], "gid", namespace_view=False)
        _create_production_directory(Path(absolute), mode, uid, gid)
    secret_root = Path(contract["secret_policy"]["delivery_root"])
    if initial_secret_source is not None:
        publish_initial_secret_tree(contract, initial_secret_source, secret_root)
    # The external security authority publishes the complete root atomically.
    # State preparation never creates a partial secret tree.
    validate_production(
        contract, namespace_view=False, require_secrets=True, require_marker=False
    )
    marker_temporary = marker.with_name(".state-layout-v1.new")
    if marker_temporary.exists() or marker_temporary.is_symlink():
        fail("production state marker staging path is not empty")
    descriptor = -1
    try:
        descriptor = os.open(
            marker_temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        content = (contract["state_policy"]["marker_content"] + "\n").encode()
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                fail("production state marker write did not progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.chown(marker_temporary, 0, mapping["service_gid"])
        marker_temporary.chmod(_mode(contract["state_policy"]["marker_mode"]))
        marker_temporary.rename(marker)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if marker_temporary.exists() or marker_temporary.is_symlink():
            marker_temporary.unlink()
    deployment_descriptor = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(deployment_descriptor)
    finally:
        os.close(deployment_descriptor)
    validate_production(
        contract, namespace_view=False, require_secrets=True, require_marker=True
    )


def publish_initial_secret_tree(
    contract: dict[str, Any],
    source_root: Path,
    destination_root: Path,
    *,
    fixture: bool = False,
    interrupt_after: int | None = None,
) -> None:
    """Atomically publish one complete initial secret delivery tree."""
    if source_root.is_symlink():
        fail("secret publication source is unsafe")
    source_root = source_root.resolve(strict=True)
    if not source_root.is_dir():
        fail("secret publication source is unsafe")
    canonical_destination = Path(contract["secret_policy"]["delivery_root"])
    if not fixture and destination_root != canonical_destination:
        fail("secret publication destination is not canonical")
    if destination_root.exists() or destination_root.is_symlink():
        fail("secret publication refuses to overwrite existing material")
    parent = destination_root.parent
    _assert_safe_component(parent, True)
    if not fixture:
        _assert_safe_component(parent, True, 0o710)
        _assert_owner(parent, 0, contract["rootless_mapping"]["service_gid"])
        _assert_no_extended_acl(parent)
        _validate_trusted_ancestors(parent)
    staging = Path(tempfile.mkdtemp(prefix=".secpal-secrets.", dir=parent))
    published = False
    copied = 0
    try:
        staging.chmod(0o710)
        if not fixture:
            os.chown(staging, 0, contract["rootless_mapping"]["service_gid"])
        _assert_no_extended_acl(staging)
        expected_source_entries = {source_root / name for name in contract["secret_delivery"]}
        if set(source_root.iterdir()) != expected_source_entries:
            fail("secret publication source has an incomplete consumer set")
        for delivery_name, delivery in contract["secret_delivery"].items():
            source_directory = source_root / delivery_name
            _assert_safe_component(source_directory, True)
            if set(source_directory.iterdir()) != {
                source_directory / name for name in delivery["files"]
            }:
                fail("secret publication source has a partial set or unexpected material")
            destination_directory = staging / delivery_name
            destination_directory.mkdir(mode=_mode(delivery["directory_mode"]))
            destination_directory.chmod(_mode(delivery["directory_mode"]))
            if not fixture:
                os.chown(
                    destination_directory, 0, contract["rootless_mapping"]["service_gid"]
                )
            _assert_no_extended_acl(destination_directory)
            owner_uid, owner_gid = _production_secret_expected_owner(
                contract, delivery, namespace_view=fixture
            )
            if fixture:
                owner_uid, owner_gid = os.getuid(), os.getgid()
            for name, spec in delivery["files"].items():
                source = source_directory / name
                _assert_safe_component(source, False, _mode(spec["mode"]))
                destination = destination_directory / name
                try:
                    descriptor = os.open(
                        source,
                        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    )
                    try:
                        value = os.read(descriptor, 4097)
                    finally:
                        os.close(descriptor)
                    if len(value) > 4096:
                        fail("secret publication source file is too large")
                    output = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                    )
                    try:
                        remaining = memoryview(value)
                        while remaining:
                            written = os.write(output, remaining)
                            if written <= 0:
                                fail("secret publication write did not progress")
                            remaining = remaining[written:]
                        os.fsync(output)
                    finally:
                        os.close(output)
                except OSError as error:
                    raise ContractError("secret publication copy failed") from error
                destination.chmod(_mode(spec["mode"]))
                os.chown(destination, owner_uid, owner_gid)
                _validate_secret(
                    destination,
                    spec["type"],
                    _mode(spec["mode"]),
                    contract["secret_policy"]["max_previous_keys"],
                )
                copied += 1
                if interrupt_after is not None and copied == interrupt_after:
                    fail("secret publication was interrupted")
            directory_descriptor = os.open(destination_directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        if (staging / "api/valkey-password").read_bytes() != (
            staging / "valkey/password"
        ).read_bytes():
            fail("Valkey consumer credential copies do not match")
        active_raw = (staging / "api/app-key").read_bytes()
        active = active_raw[:-1] if active_raw.endswith(b"\n") else active_raw
        previous_raw = (staging / "api/app-previous-keys").read_bytes()
        previous_normalized = previous_raw[:-1] if previous_raw.endswith(b"\n") else previous_raw
        previous_keys = [] if previous_normalized == b"" else previous_normalized.split(b"\n")
        if active in previous_keys:
            fail("active APP_KEY is duplicated in APP_PREVIOUS_KEYS")
        staging_descriptor = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(staging_descriptor)
        finally:
            os.close(staging_descriptor)
        staging.rename(destination_root)
        published = True
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging)


def prove_fixture_lifecycle(contract: dict[str, Any], root: Path) -> list[str]:
    """Model the exact native lifecycle without invoking a live production runtime."""
    initialize_fixture(contract, root)
    private = _fixture_path(root, contract["objects"]["private_application_storage"]["location"])
    postgres = _fixture_path(root, contract["objects"]["postgresql_data"]["location"])
    valkey = _fixture_path(root, contract["objects"]["valkey_state"]["location"])
    markers = {
        private / ".fixture-private": b"private-metadata\n",
        postgres / ".fixture-postgres": b"postgres-state\n",
        valkey / ".fixture-valkey": b"valkey-aof\n",
    }
    before: dict[Path, tuple[int, int, int, bytes]] = {}
    for path, value in markers.items():
        path.write_bytes(value)
        metadata = path.stat()
        before[path] = (metadata.st_ino, metadata.st_uid, metadata.st_gid, value)
    # A native container recreation removes transient container identity only;
    # bind-mounted host paths are deliberately untouched.
    validate_fixture(contract, root)
    for path, expected in before.items():
        metadata = path.stat()
        observed = (metadata.st_ino, metadata.st_uid, metadata.st_gid, path.read_bytes())
        if observed != expected:
            fail("native recreation model lost persistent state or metadata")
    return [
        "initialize",
        "quadlet-generate",
        "systemd-user-start",
        "roles-start",
        "systemd-user-stop",
        "systemd-user-restart",
        "container-recreate",
        "state-preserved",
        "metadata-preserved",
        "fixture-cleanup-bounded",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--initialize-fixture", action="store_true")
    parser.add_argument("--initialize-production", action="store_true")
    parser.add_argument("--acknowledge-first-install", action="store_true")
    parser.add_argument("--initial-secret-source", type=Path)
    parser.add_argument("--validate-production", action="store_true")
    parser.add_argument("--validate-namespace", action="store_true")
    parser.add_argument("--publish-initial-secrets", type=Path)
    parser.add_argument("--require-secrets", action="store_true")
    args = parser.parse_args()
    def interrupted(_number: int, _frame: object) -> None:
        fail("production state operation was interrupted")

    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled_signal, interrupted)
    try:
        contract = load_contract(args.contract)
        operation_count = sum(
            bool(value)
            for value in (
                args.initialize_fixture,
                args.initialize_production,
                args.validate_production,
                args.validate_namespace,
                args.publish_initial_secrets is not None,
            )
        )
        if operation_count > 1:
            fail("exactly one production state operation may be selected")
        if args.initialize_production:
            initialize_production(
                contract,
                first_install_ack=args.acknowledge_first_install,
                initial_secret_source=args.initial_secret_source,
            )
            print("Production state paths initialized without creating secret values.")
            return 0
        if args.acknowledge_first_install:
            fail("first-install acknowledgement is valid only with initialization")
        if args.initial_secret_source is not None:
            fail("initial secret source is valid only with initialization")
        if args.validate_production or args.validate_namespace:
            validate_production(
                contract,
                namespace_view=args.validate_namespace,
                require_secrets=args.require_secrets,
            )
            print("Production state and secret contract passed without revealing values.")
            return 0
        if args.publish_initial_secrets is not None:
            if os.geteuid() != 0:
                fail("initial secret publication requires operator root authority")
            publish_initial_secret_tree(
                contract,
                args.publish_initial_secrets,
                Path(contract["secret_policy"]["delivery_root"]),
            )
            print("Initial secret set published atomically without revealing values.")
            return 0
        if args.fixture_root is None:
            if args.initialize_fixture or args.require_secrets:
                fail("fixture operation requires an explicit fixture root")
            print("Production state contract is structurally valid; no host path was touched.")
            return 0
        if args.initialize_fixture:
            initialize_fixture(contract, args.fixture_root)
        else:
            validate_fixture(contract, args.fixture_root, require_secrets=args.require_secrets)
        print("Production state fixture contract passed without revealing secret values.")
        return 0
    except ContractError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
