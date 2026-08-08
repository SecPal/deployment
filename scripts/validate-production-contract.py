#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Validate a production inventory against explicitly supplied synthetic facts."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn
from urllib.parse import urlsplit

import jsonschema
import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/production-inventory.schema.json"
MAX_INPUT_BYTES = 1024 * 1024
SUPPORTED_ARCHITECTURES = {"amd64", "arm64"}
REQUIRED_TOOLS = {
    "bash",
    "curl",
    "df",
    "docker",
    "findmnt",
    "getent",
    "gh",
    "id",
    "install",
    "mktemp",
    "python3",
    "realpath",
    "sha256sum",
    "stat",
    "timedatectl",
}
RESERVED_SERVICE_IDS = {10001, 10002}

SECRET_FIELD_NAMES = {
    "password",
    "token",
    "secret",
    "private_key",
    "ssh_key",
    "api_key",
    "github_token",
    "registry_password",
    "app_key",
    "tenant_kek",
}
SUPPLY_CHAIN_FIELD_NAMES = {
    "api_image",
    "frontend_image",
    "api_registry",
    "frontend_registry",
    "registry",
    "api_repository",
    "frontend_repository",
    "repository",
    "api_digest",
    "frontend_digest",
    "digest",
    "image_tag",
    "registry_fallback",
}
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"),
)
HOSTNAME_PATTERN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

CANONICAL_PATHS: dict[str, dict[str, Any]] = {
    "configuration": {
        "owner_role": "service-account",
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": None,
        "identity": "service-account",
    },
    "deployment_state": {
        "owner_role": "service-account",
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": None,
        "identity": "service-account",
    },
    "runtime_secrets": {
        "owner_role": "state-contract",
        "uid": None,
        "gid": None,
        "mode": "0750",
        "lifecycle": "reconstructable",
        "decision_issue": 10,
    },
    "postgresql_data": {
        "owner_role": "state-contract",
        "uid": None,
        "gid": None,
        "mode": "0700",
        "lifecycle": "persistent",
        "decision_issue": 10,
    },
    "private_application_storage": {
        "owner_role": "api-runtime",
        "uid": 10001,
        "gid": 10001,
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": None,
    },
    "public_application_storage": {
        "owner_role": "api-runtime",
        "uid": 10001,
        "gid": 10001,
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": 10,
    },
    "edge_state": {
        "owner_role": "edge-contract",
        "uid": None,
        "gid": None,
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": 11,
    },
    "acme_state": {
        "owner_role": "tls-contract",
        "uid": None,
        "gid": None,
        "mode": "0700",
        "lifecycle": "persistent",
        "decision_issue": 13,
    },
    "crowdsec_state": {
        "owner_role": "crowdsec-contract",
        "uid": None,
        "gid": None,
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": 14,
    },
    "logs": {
        "owner_role": "service-account",
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": None,
        "identity": "service-account",
    },
    "backup_staging": {
        "owner_role": "service-account",
        "mode": "0700",
        "lifecycle": "reconstructable",
        "decision_issue": 15,
        "identity": "service-account",
    },
    "docker_data_root": {
        "owner_role": "docker-daemon",
        "uid": 0,
        "gid": 0,
        "mode": "0711",
        "lifecycle": "persistent",
        "decision_issue": None,
    },
}

STORAGE_PATH_KEYS = {
    "docker_data": "docker_data_root",
    "postgresql_data": "postgresql_data",
    "private_application_storage": "private_application_storage",
    "logs": "logs",
    "edge_state": "edge_state",
    "acme_state": "acme_state",
    "crowdsec_state": "crowdsec_state",
    "backup_staging": "backup_staging",
}

STORAGE_MINIMUMS = {
    "docker_data": (21474836480, 200000),
    "postgresql_data": (21474836480, 200000),
    "private_application_storage": (10737418240, 100000),
    "logs": (5368709120, 50000),
    "edge_state": (2147483648, 20000),
    "acme_state": (1073741824, 20000),
    "crowdsec_state": (2147483648, 50000),
    "backup_staging": (10737418240, 50000),
}


class ContractViolation(Exception):
    """A deterministic contract error that never includes an input value."""


class NoDuplicateSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous explicit mapping keys."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        explicit_keys: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in explicit_keys
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "mapping keys must be scalar",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "duplicate mapping key is forbidden",
                    key_node.start_mark,
                )
            explicit_keys.add(key)
        return super().construct_mapping(node, deep=deep)


def normalize_field_name(name: str) -> str:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")


def field_path(parts: Sequence[object], root: str = "inventory") -> str:
    return ".".join([root, *(str(part) for part in parts)])


def scan_forbidden_input(
    value: Any,
    parts: tuple[object, ...] = (),
    root: str = "inventory",
    active: set[int] | None = None,
) -> None:
    if active is None:
        active = set()
    if isinstance(value, (Mapping, list)):
        identity = id(value)
        if identity in active:
            raise ContractViolation(f"recursive YAML aliases are forbidden at {field_path(parts, root)}")
        active.add(identity)
    try:
        if isinstance(value, Mapping):
            for raw_key, child in value.items():
                if not isinstance(raw_key, str):
                    raise ContractViolation(f"non-string field name at {field_path(parts, root)}")
                normalized = normalize_field_name(raw_key)
                child_parts = (*parts, raw_key)
                if normalized in SECRET_FIELD_NAMES or any(
                    normalized.endswith(f"_{name}") for name in SECRET_FIELD_NAMES
                ):
                    raise ContractViolation(
                        f"secret-bearing field is forbidden at {field_path(child_parts, root)}"
                    )
                if normalized in SUPPLY_CHAIN_FIELD_NAMES:
                    raise ContractViolation(
                        f"image or registry identity field is forbidden at {field_path(child_parts, root)}"
                    )
                scan_forbidden_input(child, child_parts, root, active)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                scan_forbidden_input(child, (*parts, index), root, active)
        elif isinstance(value, str):
            if any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS):
                raise ContractViolation(
                    f"credential material is forbidden at {field_path(parts, root)}"
                )
    finally:
        if isinstance(value, (Mapping, list)):
            active.remove(id(value))


def read_document(path: Path, label: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ContractViolation(f"{label} exceeds the 1 MiB input limit")
        loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=NoDuplicateSafeLoader)
    except ContractViolation:
        raise
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ContractViolation(f"{label} could not be read as one YAML document") from exc
    if not isinstance(loaded, dict):
        raise ContractViolation(f"{label} root must be an object")
    scan_forbidden_input(loaded, root=label.replace(" ", "_"))
    return loaded


def read_schema() -> dict[str, Any]:
    try:
        loaded = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractViolation("repository inventory schema could not be read") from exc
    if not isinstance(loaded, dict):
        raise ContractViolation("repository inventory schema root must be an object")
    return loaded


def schema_error_message(error: jsonschema.ValidationError) -> str:
    location = field_path(tuple(error.absolute_path))
    if error.validator == "required":
        missing = sorted(set(error.validator_value) - set(error.instance))
        suffix = f".{missing[0]}" if missing else ""
        return f"required field missing at {location}{suffix}"
    if error.validator == "additionalProperties":
        known = set(error.schema.get("properties", {}))
        unknown = sorted(set(error.instance) - known)
        suffix = f".{unknown[0]}" if unknown else ""
        return f"unknown field at {location}{suffix}"
    if error.validator in {"const", "enum"}:
        return f"unsupported or fixed value at {location}"
    if error.validator == "format":
        return f"invalid formatted value at {location}"
    return f"inventory schema violation at {location} ({error.validator})"


def validate_schema(inventory: dict[str, Any]) -> None:
    schema = read_schema()
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise ContractViolation("repository inventory schema is invalid") from exc
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    errors = sorted(
        validator.iter_errors(inventory),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise ContractViolation(schema_error_message(errors[0]))


def is_documentation_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in DOCUMENTATION_NETWORKS)


def parse_address(raw: str, location: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ContractViolation(f"invalid IP address at {location}") from exc


def validate_addresses(host: dict[str, Any]) -> None:
    public = parse_address(host["public_address"], "inventory.host.public_address")
    if (
        public.is_loopback
        or public.is_link_local
        or public.is_multicast
        or public.is_unspecified
        or (public.is_private and not is_documentation_address(public))
    ):
        raise ContractViolation("public address is not public or documentation-only")

    private_addresses = [
        parse_address(raw, f"inventory.host.private_addresses.{index}")
        for index, raw in enumerate(host["private_addresses"])
    ]
    if public in private_addresses:
        raise ContractViolation("public and private host addresses conflict")
    for address in private_addresses:
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or not address.is_private
        ):
            raise ContractViolation("private address is not a non-loopback private address")


def validate_hostname(hostname: str, location: str) -> None:
    if not hostname.isascii() or not HOSTNAME_PATTERN.fullmatch(hostname.lower()):
        raise ContractViolation(f"invalid DNS hostname at {location}")
    if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        raise ContractViolation(f"loopback hostname is forbidden at {location}")


def validate_origin(origin: str, location: str) -> str:
    if not origin.isascii():
        raise ContractViolation(f"origin must be ASCII at {location}")
    parsed = urlsplit(origin)
    if parsed.scheme != "https":
        raise ContractViolation(f"origin must use HTTPS at {location}")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query
        or parsed.fragment
    ):
        raise ContractViolation(f"origin must not contain userinfo, path, query, or fragment at {location}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ContractViolation(f"origin has an invalid port at {location}") from exc
    if port not in {None, 443}:
        raise ContractViolation(f"origin must use the default HTTPS port at {location}")
    hostname = parsed.hostname
    if hostname is None:
        raise ContractViolation(f"origin hostname is missing at {location}")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        validate_hostname(hostname, location)
    else:
        raise ContractViolation(f"origin must use a DNS name at {location}")
    return hostname.lower()


def validate_absolute_path(raw: str, location: str) -> None:
    path = PurePosixPath(raw)
    if not path.is_absolute() or raw == "/":
        raise ContractViolation(f"path must be absolute and non-root at {location}")
    if any(part in {".", ".."} for part in raw.split("/")):
        raise ContractViolation(f"path traversal is forbidden at {location}")
    if os.path.normpath(raw) != raw or "//" in raw:
        raise ContractViolation(f"path must be normalized at {location}")
    if raw == "/tmp" or raw.startswith("/tmp/"):
        raise ContractViolation(f"persistent contract path must not use /tmp at {location}")


def validate_path_contracts(inventory: dict[str, Any]) -> None:
    service_account = inventory["service_account"]
    paths = inventory["paths"]
    seen: dict[str, str] = {}
    for name, expected in CANONICAL_PATHS.items():
        contract = paths[name]
        location = f"inventory.paths.{name}"
        raw_path = contract["path"]
        validate_absolute_path(raw_path, f"{location}.path")
        if raw_path in seen:
            raise ContractViolation(
                f"duplicate path between inventory.paths.{seen[raw_path]} and {location}"
            )
        seen[raw_path] = name

        for field in ("owner_role", "mode", "lifecycle", "decision_issue"):
            if contract[field] != expected[field]:
                raise ContractViolation(f"fixed path metadata mismatch at {location}.{field}")
        if expected.get("identity") == "service-account":
            expected_uid = service_account["uid"]
            expected_gid = service_account["gid"]
        else:
            expected_uid = expected["uid"]
            expected_gid = expected["gid"]
        if contract["uid"] != expected_uid or contract["gid"] != expected_gid:
            raise ContractViolation(f"fixed path ownership mismatch at {location}")

    protected_paths = {
        "service_account.home": service_account["home"],
        **{f"paths.{name}": contract["path"] for name, contract in paths.items()},
    }
    protected_items = list(protected_paths.items())
    for index, (left_name, left_raw) in enumerate(protected_items):
        left = PurePosixPath(left_raw)
        for right_name, right_raw in protected_items[index + 1 :]:
            right = PurePosixPath(right_raw)
            if left == right or left in right.parents or right in left.parents:
                raise ContractViolation(
                    f"conflicting path hierarchy between {left_name} and {right_name}"
                )


def validate_storage_requirements(resources: dict[str, Any]) -> None:
    for name, (minimum_bytes, minimum_inodes) in STORAGE_MINIMUMS.items():
        requirement = resources["storage"][name]
        location = f"inventory.resources.storage.{name}"
        if requirement["minimum_free_bytes"] < minimum_bytes:
            raise ContractViolation(f"byte headroom is below the contract floor at {location}")
        if requirement["minimum_free_inodes"] < minimum_inodes:
            raise ContractViolation(f"inode headroom is below the contract floor at {location}")
        if requirement["minimum_free_percent"] < 20:
            raise ContractViolation(f"free-space percentage is below the contract floor at {location}")
        if requirement["minimum_free_inode_percent"] < 20:
            raise ContractViolation(f"free-inode percentage is below the contract floor at {location}")


def validate_inventory(inventory: dict[str, Any]) -> None:
    validate_schema(inventory)
    host = inventory["host"]
    validate_hostname(host["hostname"], "inventory.host.hostname")
    validate_addresses(host)

    service_account = inventory["service_account"]
    if service_account["uid"] in RESERVED_SERVICE_IDS:
        raise ContractViolation("service-account UID conflicts with a container runtime identity")
    if service_account["gid"] in RESERVED_SERVICE_IDS:
        raise ContractViolation("service-account GID conflicts with a container runtime identity")
    validate_absolute_path(service_account["home"], "inventory.service_account.home")

    frontend_hostname = validate_origin(
        inventory["origins"]["frontend"], "inventory.origins.frontend"
    )
    api_hostname = validate_origin(inventory["origins"]["api"], "inventory.origins.api")
    if frontend_hostname == api_hostname:
        raise ContractViolation("frontend and API origins must use different DNS names")
    if host["hostname"].lower() in {frontend_hostname, api_hostname}:
        raise ContractViolation("host hostname must differ from frontend and API origins")

    validate_path_contracts(inventory)
    validate_storage_requirements(inventory["resources"])

    features = inventory["features"]
    if features["opentimestamps"] != features["bitcoin_quorum"]:
        raise ContractViolation(
            "OpenTimestamp and Bitcoin quorum feature gates must be enabled or disabled together"
        )
    if (inventory["backup"]["target_type"] == "object-storage") != features[
        "object_storage"
    ]:
        raise ContractViolation(
            "object-storage target and feature gate must be enabled or disabled together"
        )


def require_exact_keys(value: Any, expected: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractViolation(f"{location} must be an object")
    actual = set(value)
    if actual != expected:
        raise ContractViolation(f"{location} has missing or unknown fields")
    return value


def require_integer(value: Any, location: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractViolation(f"{location} must be an integer at or above its floor")
    return value


def parse_version(raw: Any, location: str) -> tuple[int, int, int]:
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", raw):
        raise ContractViolation(f"{location} must be a three-part numeric version")
    return tuple(int(part) for part in raw.split("."))  # type: ignore[return-value]


def validate_host_facts(inventory: dict[str, Any], facts: dict[str, Any]) -> None:
    facts = require_exact_keys(
        facts,
        {
            "schema_version",
            "hostname",
            "architecture",
            "os",
            "kernel",
            "runtime",
            "clock",
            "network",
            "tools",
            "resources",
        },
        "host facts",
    )
    if facts["schema_version"] != 1:
        raise ContractViolation("unsupported host-facts schema version")
    if facts["hostname"] != inventory["host"]["hostname"]:
        raise ContractViolation("host-facts hostname does not match the inventory")
    if not isinstance(facts["architecture"], str):
        raise ContractViolation("host architecture fact must be a string")
    if facts["architecture"] not in SUPPORTED_ARCHITECTURES:
        raise ContractViolation("host architecture is unsupported")
    if facts["architecture"] != inventory["host"]["architecture"]:
        raise ContractViolation("host architecture does not match the inventory")

    os_facts = require_exact_keys(facts["os"], {"id", "version_id"}, "host facts.os")
    if os_facts != {"id": "ubuntu", "version_id": "24.04"}:
        raise ContractViolation("host OS must be Ubuntu Server 24.04")

    kernel = require_exact_keys(
        facts["kernel"],
        {
            "release",
            "cgroup_version",
            "overlayfs_supported",
            "apparmor_enabled",
            "seccomp_enabled",
        },
        "host facts.kernel",
    )
    if not isinstance(kernel["release"], str):
        raise ContractViolation("host kernel release must be a string")
    kernel_match = re.fullmatch(
        r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
        r"(?:[-+._][A-Za-z0-9][A-Za-z0-9+._-]*)?",
        kernel["release"],
    )
    if kernel_match is None or tuple(map(int, kernel_match.groups())) < (6, 8):
        raise ContractViolation("host kernel must be Linux 6.8 or newer")
    if kernel["cgroup_version"] != 2:
        raise ContractViolation("host must use cgroup v2")
    for feature in ("overlayfs_supported", "apparmor_enabled", "seccomp_enabled"):
        if kernel[feature] is not True:
            raise ContractViolation(f"required kernel feature is disabled at host facts.kernel.{feature}")

    runtime = require_exact_keys(
        facts["runtime"],
        {
            "docker_engine_version",
            "docker_compose_version",
            "rootless",
            "daemon_running",
            "data_root",
        },
        "host facts.runtime",
    )
    engine_version = parse_version(
        runtime["docker_engine_version"], "host facts.runtime.docker_engine_version"
    )
    if engine_version < (29, 6, 2) or engine_version >= (30, 0, 0):
        raise ContractViolation("Docker Engine must be supported 29.x at or above 29.6.2")
    compose_version = parse_version(
        runtime["docker_compose_version"], "host facts.runtime.docker_compose_version"
    )
    if compose_version < (2, 40, 3) or compose_version >= (3, 0, 0):
        raise ContractViolation("Docker Compose must be supported v2 at or above 2.40.3")
    if runtime["rootless"] is not False:
        raise ContractViolation("rootless Docker Engine is not supported by this contract")
    if runtime["daemon_running"] is not True:
        raise ContractViolation("Docker daemon fact must report running")
    if runtime["data_root"] != inventory["paths"]["docker_data_root"]["path"]:
        raise ContractViolation("Docker data root does not match the inventory")

    clock = require_exact_keys(
        facts["clock"], {"synchronized", "offset_milliseconds"}, "host facts.clock"
    )
    if clock["synchronized"] is not True:
        raise ContractViolation("host clock is not synchronized")
    offset = require_integer(clock["offset_milliseconds"], "host facts.clock.offset_milliseconds")
    if offset > 1000:
        raise ContractViolation("host clock offset exceeds 1000 milliseconds")

    network = require_exact_keys(
        facts["network"], {"public_address", "private_addresses"}, "host facts.network"
    )
    if network["public_address"] != inventory["host"]["public_address"]:
        raise ContractViolation("host public-address fact does not match the inventory")
    if network["private_addresses"] != inventory["host"]["private_addresses"]:
        raise ContractViolation("host private-address facts do not match the inventory")

    tools = facts["tools"]
    if not isinstance(tools, list) or any(not isinstance(tool, str) for tool in tools):
        raise ContractViolation("host tools must be a string array")
    missing_tools = sorted(REQUIRED_TOOLS - set(tools))
    if missing_tools:
        raise ContractViolation(f"required host tool is missing: {missing_tools[0]}")

    resource_facts = require_exact_keys(
        facts["resources"],
        {"logical_cpus", "memory_bytes", "storage_total_bytes", "total_inodes", "storage"},
        "host facts.resources",
    )
    for field in ("logical_cpus", "memory_bytes", "storage_total_bytes", "total_inodes"):
        actual = require_integer(resource_facts[field], f"host facts.resources.{field}")
        if actual < inventory["resources"][field]:
            raise ContractViolation(f"host resource is below inventory floor: {field}")

    storage_facts = require_exact_keys(
        resource_facts["storage"], set(STORAGE_PATH_KEYS), "host facts.resources.storage"
    )
    seen_paths: set[str] = set()
    for name, inventory_path_name in STORAGE_PATH_KEYS.items():
        storage = require_exact_keys(
            storage_facts[name],
            {
                "path",
                "filesystem",
                "local",
                "d_type",
                "xfs_ftype",
                "free_bytes",
                "free_percent",
                "free_inodes",
                "free_inode_percent",
            },
            f"host facts.resources.storage.{name}",
        )
        expected_path = inventory["paths"][inventory_path_name]["path"]
        if storage["path"] != expected_path:
            raise ContractViolation(f"storage path does not match inventory at {name}")
        if storage["path"] in seen_paths:
            raise ContractViolation("host storage facts contain duplicate mount or state paths")
        seen_paths.add(storage["path"])
        if not isinstance(storage["filesystem"], str):
            raise ContractViolation(f"storage filesystem fact must be a string at {name}")
        if storage["filesystem"] not in {"ext4", "xfs"} or storage["local"] is not True:
            raise ContractViolation(f"storage must use local ext4 or XFS at {name}")
        if storage["d_type"] is not True:
            raise ContractViolation(f"storage must support d_type at {name}")
        if storage["filesystem"] == "xfs" and storage["xfs_ftype"] is not True:
            raise ContractViolation(f"XFS storage must use ftype=1 at {name}")
        if storage["filesystem"] == "ext4" and storage["xfs_ftype"] is not None:
            raise ContractViolation(f"ext4 storage must not report an XFS ftype value at {name}")

        requirement = inventory["resources"]["storage"][name]
        checks = (
            ("free_bytes", "minimum_free_bytes"),
            ("free_percent", "minimum_free_percent"),
            ("free_inodes", "minimum_free_inodes"),
            ("free_inode_percent", "minimum_free_inode_percent"),
        )
        for fact_name, requirement_name in checks:
            actual = require_integer(
                storage[fact_name], f"host facts.resources.storage.{name}.{fact_name}"
            )
            if fact_name.endswith("percent") and actual > 100:
                raise ContractViolation(f"storage percentage exceeds 100 at {name}.{fact_name}")
            if actual < requirement[requirement_name]:
                raise ContractViolation(f"storage headroom is insufficient at {name}.{fact_name}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a SecPal production inventory and supplied host-fact document."
    )
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--host-facts", required=True, type=Path)
    return parser.parse_args()


def abort(message: str) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    arguments = parse_arguments()
    try:
        inventory = read_document(arguments.inventory, "inventory")
        validate_inventory(inventory)
        host_facts = read_document(arguments.host_facts, "host facts")
        validate_host_facts(inventory, host_facts)
    except ContractViolation as exc:
        abort(str(exc))
    print("Production inventory and supplied host facts satisfy schema version 1.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
