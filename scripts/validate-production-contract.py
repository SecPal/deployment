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
    re.compile(r"(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}"),
    re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"),
)
HOSTNAME_PATTERN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
NUMERIC_HOST_LABEL_PATTERN = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)\Z", re.IGNORECASE)
VERSION_COMPONENT = r"(?:0|[1-9][0-9]{0,8})"
RUNTIME_VERSION_PATTERN = re.compile(
    rf"({VERSION_COMPONENT})\.({VERSION_COMPONENT})\.({VERSION_COMPONENT})\Z"
)
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
PRIVATE_USE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def is_strict_integer(_checker: Any, value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def contains_ascii_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


STRICT_TYPE_CHECKER = jsonschema.Draft202012Validator.TYPE_CHECKER.redefine(
    "integer", is_strict_integer
)
StrictDraft202012Validator = jsonschema.validators.extend(
    jsonschema.Draft202012Validator, type_checker=STRICT_TYPE_CHECKER
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
    "public_application_storage": "public_application_storage",
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
    "public_application_storage": (1073741824, 20000),
    "logs": (5368709120, 50000),
    "edge_state": (2147483648, 20000),
    "acme_state": (1073741824, 20000),
    "crowdsec_state": (2147483648, 50000),
    "backup_staging": (10737418240, 50000),
}


class ContractViolation(Exception):
    """A deterministic contract error that never includes an input value."""


class NoDuplicateSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate effective mapping keys."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        effective_keys: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in effective_keys
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
            effective_keys.add(key)
        return super().construct_mapping(node, deep=deep)


def normalize_field_name(name: str) -> str:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")


def field_path(parts: Sequence[object], root: str = "inventory") -> str:
    safe_parts: list[str] = []
    for part in parts:
        if isinstance(part, int):
            safe_parts.append(str(part))
        elif (
            isinstance(part, str)
            and re.fullmatch(r"[a-z][a-z0-9_]*", part)
            and not any(pattern.search(part) for pattern in SENSITIVE_VALUE_PATTERNS)
        ):
            safe_parts.append(part)
        else:
            safe_parts.append("<redacted-field>")
    return ".".join([root, *safe_parts])


def scan_forbidden_input(
    value: Any,
    parts: tuple[object, ...] = (),
    root: str = "inventory",
    active: set[int] | None = None,
    visited: set[int] | None = None,
) -> None:
    if active is None:
        active = set()
    if visited is None:
        visited = set()
    if isinstance(value, (Mapping, list)):
        identity = id(value)
        if identity in active:
            raise ContractViolation(f"recursive YAML aliases are forbidden at {field_path(parts, root)}")
        if identity in visited:
            return
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
                scan_forbidden_input(child, child_parts, root, active, visited)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                scan_forbidden_input(child, (*parts, index), root, active, visited)
        elif isinstance(value, str):
            if any(pattern.search(value) for pattern in SENSITIVE_VALUE_PATTERNS):
                raise ContractViolation(
                    f"credential material is forbidden at {field_path(parts, root)}"
                )
    finally:
        if isinstance(value, (Mapping, list)):
            active.remove(id(value))
            visited.add(id(value))


def read_document(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ContractViolation(f"{label} exceeds the 1 MiB input limit")
        loaded = yaml.load(raw.decode("utf-8"), Loader=NoDuplicateSafeLoader)
        if not isinstance(loaded, dict):
            raise ContractViolation(f"{label} root must be an object")
        scan_forbidden_input(loaded, root=label.replace(" ", "_"))
    except ContractViolation:
        raise
    except RecursionError as exc:
        raise ContractViolation(f"{label} exceeds the maximum structural depth") from exc
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        raise ContractViolation(f"{label} could not be read as one YAML document") from exc
    return loaded


def read_schema() -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        loaded = json.loads(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ContractViolation("repository inventory schema could not be read") from exc
    if not isinstance(loaded, dict):
        raise ContractViolation("repository inventory schema root must be an object")
    return loaded


def schema_error_message(error: jsonschema.ValidationError) -> str:
    path = tuple(error.absolute_path)
    location = field_path(path)
    if error.validator == "required":
        missing = sorted(set(error.validator_value) - set(error.instance))
        missing_location = field_path((*path, missing[0])) if missing else location
        return f"required field missing at {missing_location}"
    if error.validator == "additionalProperties":
        known = set(error.schema.get("properties", {}))
        unknown = sorted(set(error.instance) - known)
        unknown_location = field_path((*path, unknown[0])) if unknown else location
        return f"unknown field at {unknown_location}"
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
    validator = StrictDraft202012Validator(
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


def parse_address(raw: Any, location: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(raw, str):
        raise ContractViolation(f"IP address must be a string at {location}")
    try:
        return ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ContractViolation(f"invalid IP address at {location}") from exc


def parse_unique_addresses(
    raw: Any, location: str
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if not isinstance(raw, list) or any(not isinstance(address, str) for address in raw):
        raise ContractViolation(f"{location} must be a string array")
    parsed = tuple(
        parse_address(address, f"{location}.{index}")
        for index, address in enumerate(raw)
    )
    if len(set(parsed)) != len(parsed):
        raise ContractViolation(f"{location} contains duplicate addresses")
    return parsed


def validate_addresses(host: dict[str, Any]) -> None:
    public = parse_address(host["public_address"], "inventory.host.public_address")
    deprecated_site_local = (
        isinstance(public, ipaddress.IPv6Address) and public.is_site_local
    )
    if public.is_multicast or deprecated_site_local or (
        not public.is_global and not is_documentation_address(public)
    ):
        raise ContractViolation("public address is not public or documentation-only")

    private_addresses = parse_unique_addresses(
        host["private_addresses"], "inventory.host.private_addresses"
    )
    if public in private_addresses:
        raise ContractViolation("public and private host addresses conflict")
    for address in private_addresses:
        if not any(
            address.version == network.version and address in network
            for network in PRIVATE_USE_NETWORKS
        ):
            raise ContractViolation("private address is not in a supported private-use range")


def validate_hostname(hostname: Any, location: str) -> str:
    if (
        not isinstance(hostname, str)
        or not hostname.isascii()
        or not HOSTNAME_PATTERN.fullmatch(hostname.lower())
    ):
        raise ContractViolation(f"invalid DNS hostname at {location}")
    normalized = hostname.lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        raise ContractViolation(f"loopback hostname is forbidden at {location}")
    return normalized


def validate_origin(origin: Any, location: str) -> str:
    if not isinstance(origin, str) or not origin.isascii():
        raise ContractViolation(f"origin must be ASCII at {location}")
    if contains_ascii_control(origin):
        raise ContractViolation(f"origin must not contain control characters at {location}")
    if "?" in origin or "#" in origin:
        raise ContractViolation(
            f"origin must not contain a query or fragment delimiter at {location}"
        )
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not origin.startswith("https://"):
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
    canonical_authority = hostname if port is None else f"{hostname}:443"
    if parsed.netloc.lower() != canonical_authority.lower():
        raise ContractViolation(f"origin authority is not canonical at {location}")
    if all(NUMERIC_HOST_LABEL_PATTERN.fullmatch(label) for label in hostname.split(".")):
        raise ContractViolation(f"origin must use a DNS name at {location}")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        validate_hostname(hostname, location)
    else:
        raise ContractViolation(f"origin must use a DNS name at {location}")
    return hostname.lower()


def validate_absolute_path(raw: Any, location: str) -> None:
    if not isinstance(raw, str):
        raise ContractViolation(f"path must be a string at {location}")
    if contains_ascii_control(raw):
        raise ContractViolation(f"path must not contain control characters at {location}")
    try:
        encoded_path = raw.encode("utf-8")
        encoded_parts = tuple(part.encode("utf-8") for part in raw.split("/"))
    except UnicodeEncodeError as exc:
        raise ContractViolation(f"path must be valid UTF-8 at {location}") from exc
    if len(encoded_path) > 4095:
        raise ContractViolation(f"path exceeds the Linux byte limit at {location}")
    if any(len(part) > 255 for part in encoded_parts):
        raise ContractViolation(
            f"path component exceeds the filesystem byte limit at {location}"
        )
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
    schema_version = require_integer(
        inventory["schema_version"], "inventory.schema_version", minimum=1
    )
    if schema_version != 1:
        raise ContractViolation("unsupported inventory schema version")
    host = inventory["host"]
    host_hostname = validate_hostname(host["hostname"], "inventory.host.hostname")
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
    if host_hostname in {frontend_hostname, api_hostname}:
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
    match = RUNTIME_VERSION_PATTERN.fullmatch(raw) if isinstance(raw, str) else None
    if match is None:
        raise ContractViolation(f"{location} must be a three-part numeric version")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def validate_platform_facts(inventory: dict[str, Any], facts: dict[str, Any]) -> None:
    fact_hostname = validate_hostname(facts["hostname"], "host facts.hostname")
    inventory_hostname = validate_hostname(
        inventory["host"]["hostname"], "inventory.host.hostname"
    )
    if fact_hostname != inventory_hostname:
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


def validate_kernel_facts(value: Any) -> None:
    kernel = require_exact_keys(
        value,
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
        rf"({VERSION_COMPONENT})\.({VERSION_COMPONENT})\.({VERSION_COMPONENT})"
        r"(?P<suffix>[-+._][A-Za-z0-9][A-Za-z0-9+._-]*)?",
        kernel["release"],
    )
    if kernel_match is None:
        raise ContractViolation("host kernel must be Linux 6.8 or newer")
    kernel_version = tuple(int(kernel_match.group(index)) for index in (1, 2, 3))
    kernel_suffix = kernel_match.group("suffix") or ""
    if kernel_version < (6, 8) or kernel_suffix.lower().startswith("-rc"):
        raise ContractViolation("host kernel must be Linux 6.8 or newer")
    if kernel["cgroup_version"] != 2:
        raise ContractViolation("host must use cgroup v2")
    for feature in ("overlayfs_supported", "apparmor_enabled", "seccomp_enabled"):
        if kernel[feature] is not True:
            raise ContractViolation(f"required kernel feature is disabled at host facts.kernel.{feature}")


def validate_runtime_facts(inventory: dict[str, Any], value: Any) -> None:
    runtime = require_exact_keys(
        value,
        {
            "docker_engine_version",
            "docker_compose_version",
            "rootless",
            "daemon_running",
            "daemon_endpoint",
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
    if runtime["daemon_endpoint"] != "unix:///var/run/docker.sock":
        raise ContractViolation("Docker daemon endpoint must be the local rootful Unix socket")
    if runtime["data_root"] != inventory["paths"]["docker_data_root"]["path"]:
        raise ContractViolation("Docker data root does not match the inventory")


def validate_clock_facts(value: Any) -> None:
    clock = require_exact_keys(
        value, {"synchronized", "offset_milliseconds"}, "host facts.clock"
    )
    if clock["synchronized"] is not True:
        raise ContractViolation("host clock is not synchronized")
    offset = require_integer(clock["offset_milliseconds"], "host facts.clock.offset_milliseconds")
    if offset > 1000:
        raise ContractViolation("host clock offset exceeds 1000 milliseconds")


def validate_network_facts(inventory: dict[str, Any], value: Any) -> None:
    network = require_exact_keys(
        value, {"public_address", "private_addresses"}, "host facts.network"
    )
    fact_public_address = parse_address(
        network["public_address"], "host facts.network.public_address"
    )
    inventory_public_address = parse_address(
        inventory["host"]["public_address"], "inventory.host.public_address"
    )
    if fact_public_address != inventory_public_address:
        raise ContractViolation("host public-address fact does not match the inventory")
    parsed_fact_addresses = parse_unique_addresses(
        network["private_addresses"], "host facts.network.private_addresses"
    )
    parsed_inventory_addresses = parse_unique_addresses(
        inventory["host"]["private_addresses"], "inventory.host.private_addresses"
    )
    if set(parsed_fact_addresses) != set(parsed_inventory_addresses):
        raise ContractViolation("host private-address facts do not match the inventory")


def validate_tool_facts(tools: Any) -> None:
    if not isinstance(tools, list) or any(not isinstance(tool, str) for tool in tools):
        raise ContractViolation("host tools must be a string array")
    missing_tools = sorted(REQUIRED_TOOLS - set(tools))
    if missing_tools:
        raise ContractViolation(f"required host tool is missing: {missing_tools[0]}")


def validate_storage_fact(
    inventory: dict[str, Any],
    name: str,
    inventory_path_name: str,
    value: Any,
    resource_totals: dict[str, int],
    seen_paths: set[str],
) -> None:
    storage = require_exact_keys(
        value,
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
        if fact_name == "free_bytes" and actual > resource_totals["storage_total_bytes"]:
            raise ContractViolation(f"storage free bytes exceed host total at {name}")
        if fact_name == "free_inodes" and actual > resource_totals["total_inodes"]:
            raise ContractViolation(f"storage free inodes exceed host total at {name}")
        if actual < requirement[requirement_name]:
            raise ContractViolation(f"storage headroom is insufficient at {name}.{fact_name}")


def validate_resource_facts(inventory: dict[str, Any], value: Any) -> None:
    resource_facts = require_exact_keys(
        value,
        {"logical_cpus", "memory_bytes", "storage_total_bytes", "total_inodes", "storage"},
        "host facts.resources",
    )
    resource_totals: dict[str, int] = {}
    for field in ("logical_cpus", "memory_bytes", "storage_total_bytes", "total_inodes"):
        actual = require_integer(resource_facts[field], f"host facts.resources.{field}")
        resource_totals[field] = actual
        if actual < inventory["resources"][field]:
            raise ContractViolation(f"host resource is below inventory floor: {field}")

    storage_facts = require_exact_keys(
        resource_facts["storage"], set(STORAGE_PATH_KEYS), "host facts.resources.storage"
    )
    seen_paths: set[str] = set()
    for name, inventory_path_name in STORAGE_PATH_KEYS.items():
        validate_storage_fact(
            inventory,
            name,
            inventory_path_name,
            storage_facts[name],
            resource_totals,
            seen_paths,
        )


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
    schema_version = require_integer(
        facts["schema_version"], "host facts.schema_version", minimum=1
    )
    if schema_version != 1:
        raise ContractViolation("unsupported host-facts schema version")
    validate_platform_facts(inventory, facts)
    validate_kernel_facts(facts["kernel"])
    validate_runtime_facts(inventory, facts["runtime"])
    validate_clock_facts(facts["clock"])
    validate_network_facts(inventory, facts["network"])
    validate_tool_facts(facts["tools"])
    validate_resource_facts(inventory, facts["resources"])


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
