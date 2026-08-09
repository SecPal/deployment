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
INVENTORY_SCHEMA_PATH = ROOT / "schemas/production-inventory.schema.json"
HOST_FACTS_SCHEMA_PATH = ROOT / "schemas/production-host-facts.schema.json"
MAX_INPUT_BYTES = 1024 * 1024
REQUIRED_TOOLS = {
    "bash",
    "curl",
    "df",
    "findmnt",
    "getent",
    "gh",
    "id",
    "install",
    "loginctl",
    "mktemp",
    "newgidmap",
    "newuidmap",
    "podman",
    "python3",
    "realpath",
    "sha256sum",
    "stat",
    "systemctl",
    "timedatectl",
}
MANAGED_PATH_ROOTS = {
    "runtime_secrets": PurePosixPath("/run/secpal"),
}
DEFAULT_MANAGED_PATH_ROOT = PurePosixPath("/srv/secpal")
QUADLET_DEFINITION_ROOT = PurePosixPath("/etc/containers/systemd/users")
MAX_SYSTEM_ID = 4294967294
SUBORDINATE_ID_COUNT = 65536
OWNER_ROLE_SERVICE_ACCOUNT_WRITE = {
    "operator-root": False,
    "state-contract": False,
    "edge-contract": False,
    "tls-contract": False,
    "crowdsec-contract": False,
    "service-account": True,
    "rootless-container-storage": True,
}

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
DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOSTNAME_PATTERN = re.compile(
    rf"(?=^.{{1,253}}$){DNS_LABEL}(?:\.{DNS_LABEL})*\Z"
)
NUMERIC_HOST_LABEL_PATTERN = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)\Z", re.IGNORECASE)
VERSION_COMPONENT = r"(?:0|[1-9][0-9]{0,8})"
RUNTIME_VERSION_PATTERN = re.compile(
    rf"({VERSION_COMPONENT})\.({VERSION_COMPONENT})\.({VERSION_COMPONENT})\Z"
)
KERNEL_RELEASE_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z])rc(?:[0-9]+|(?=$|[-+._]))", re.IGNORECASE
)
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("3fff::/20"),
)
PRIVATE_USE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
IPV6_GLOBAL_UNICAST_NETWORK = ipaddress.ip_network("2000::/3")
# Reviewed against the IANA IPv4 and IPv6 special-purpose registries whose
# current revisions were last updated on 2025-10-09. Documentation networks
# remain separate because checked-in synthetic fixtures may use them.
PUBLIC_ADDRESS_EXCLUDED_NETWORKS = {
    4: (
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.31.196.0/24"),
        ipaddress.ip_network("192.52.193.0/24"),
        ipaddress.ip_network("192.88.99.0/24"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("192.175.48.0/24"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
    ),
    6: (
        ipaddress.ip_network("2001::/23"),
        ipaddress.ip_network("2002::/16"),
        ipaddress.ip_network("2620:4f:8000::/48"),
    ),
}
DOCUMENTATION_DNS_SUFFIXES = (
    "invalid",
    "test",
    "example",
    "example.com",
    "example.net",
    "example.org",
)
NON_DOCUMENTATION_SPECIAL_USE_DNS_SUFFIXES = (
    "alt",
    "arpa",
    "local",
    "localhost",
    "onion",
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
        "owner_role": "operator-root",
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": None,
        "identity": "operator-readable",
    },
    "deployment_state": {
        "owner_role": "operator-root",
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": None,
        "identity": "operator-readable",
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
        "owner_role": "state-contract",
        "uid": None,
        "gid": None,
        "container_uid": 10001,
        "container_gid": 10001,
        "mode": "0750",
        "lifecycle": "persistent",
        "decision_issue": 10,
    },
    "public_application_storage": {
        "owner_role": "state-contract",
        "uid": None,
        "gid": None,
        "container_uid": 10001,
        "container_gid": 10001,
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
    "podman_graph_root": {
        "owner_role": "rootless-container-storage",
        "mode": "0700",
        "lifecycle": "reconstructable",
        "decision_issue": None,
        "identity": "service-account",
    },
    "quadlet_definitions": {
        "owner_role": "operator-root",
        "uid": 0,
        "gid": 0,
        "mode": "0755",
        "lifecycle": "reconstructable",
        "decision_issue": None,
    },
}

HEADROOM_MINIMUMS = {
    "podman_graph_root": (21474836480, 200000),
    "postgresql_data": (21474836480, 200000),
    "private_application_storage": (10737418240, 100000),
    "public_application_storage": (1073741824, 20000),
    "logs": (5368709120, 50000),
    "edge_state": (2147483648, 20000),
    "acme_state": (1073741824, 20000),
    "crowdsec_state": (2147483648, 50000),
    "backup_staging": (10737418240, 50000),
}

FILESYSTEM_PATH_KEYS = tuple(
    name
    for name, contract in CANONICAL_PATHS.items()
    if contract["lifecycle"] == "persistent" or name in HEADROOM_MINIMUMS
)


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
                        f"secret-bearing field is forbidden below {field_path(parts, root)}"
                    )
                if normalized in SUPPLY_CHAIN_FIELD_NAMES:
                    raise ContractViolation(
                        "image or registry identity field is forbidden below "
                        f"{field_path(parts, root)}"
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


def read_schema(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        loaded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ContractViolation(f"repository {label} schema could not be read") from exc
    if not isinstance(loaded, dict):
        raise ContractViolation(f"repository {label} schema root must be an object")
    return loaded


def schema_error_message(
    error: jsonschema.ValidationError, root: str, label: str
) -> str:
    path = tuple(error.absolute_path)
    location = field_path(path, root)
    if error.validator == "required":
        missing = sorted(set(error.validator_value) - set(error.instance))
        missing_location = field_path((*path, missing[0]), root) if missing else location
        return f"required field missing at {missing_location}"
    if error.validator == "additionalProperties":
        known = set(error.schema.get("properties", {}))
        unknown = sorted(set(error.instance) - known)
        unknown_location = field_path((*path, unknown[0]), root) if unknown else location
        return f"unknown field at {unknown_location}"
    if error.validator in {"const", "enum"}:
        return f"unsupported or fixed value at {location}"
    if error.validator == "format":
        return f"invalid formatted value at {location}"
    return f"{label} schema violation at {location} ({error.validator})"


def validate_document_schema(
    document: dict[str, Any], schema_path: Path, root: str, label: str
) -> None:
    schema = read_schema(schema_path, label)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise ContractViolation(f"repository {label} schema is invalid") from exc
    validator = StrictDraft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise ContractViolation(schema_error_message(errors[0], root, label))


def validate_inventory_schema(inventory: dict[str, Any]) -> None:
    validate_document_schema(
        inventory, INVENTORY_SCHEMA_PATH, "inventory", "inventory"
    )


def validate_host_facts_schema(facts: dict[str, Any]) -> None:
    validate_document_schema(
        facts, HOST_FACTS_SCHEMA_PATH, "host_facts", "host-facts"
    )


def is_documentation_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in DOCUMENTATION_NETWORKS)


def is_eligible_public_host_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if is_documentation_address(address):
        return False
    if (
        isinstance(address, ipaddress.IPv6Address)
        and address not in IPV6_GLOBAL_UNICAST_NETWORK
    ):
        return False
    return not any(
        address in network
        for network in PUBLIC_ADDRESS_EXCLUDED_NETWORKS[address.version]
    )


def parse_address(raw: Any, location: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(raw, str):
        raise ContractViolation(f"IP address must be a string at {location}")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ContractViolation(f"invalid IP address at {location}") from exc
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            raise ContractViolation(f"scoped IPv6 address is forbidden at {location}")
        if address.ipv4_mapped is not None:
            raise ContractViolation(f"IPv4-mapped IPv6 address is forbidden at {location}")
    return address


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


def validate_addresses(host: dict[str, Any], *, synthetic: bool) -> None:
    public = parse_address(host["public_address"], "inventory.host.public_address")
    documentation_address = is_documentation_address(public)
    if documentation_address:
        if not synthetic:
            raise ContractViolation(
                "documentation public address requires explicit synthetic mode"
            )
    elif not is_eligible_public_host_address(public):
        raise ContractViolation(
            "public address is not an eligible global-unicast host address"
        )

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
    if all(
        NUMERIC_HOST_LABEL_PATTERN.fullmatch(label)
        for label in normalized.split(".")
    ):
        raise ContractViolation(f"IP literals are forbidden at {location}")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise ContractViolation(f"IP literals are forbidden at {location}")
    return normalized


def hostname_has_suffix(hostname: str, suffixes: Sequence[str]) -> bool:
    normalized = hostname.lower()
    return any(
        normalized == suffix or normalized.endswith(f".{suffix}")
        for suffix in suffixes
    )


def is_documentation_hostname(hostname: str) -> bool:
    return hostname_has_suffix(hostname, DOCUMENTATION_DNS_SUFFIXES)


def validate_origin(origin: Any, location: str, *, synthetic: bool = False) -> str:
    if not isinstance(origin, str) or not origin.isascii():
        raise ContractViolation(f"origin must be ASCII at {location}")
    if contains_ascii_control(origin):
        raise ContractViolation(f"origin must not contain control characters at {location}")
    if "?" in origin or "#" in origin:
        raise ContractViolation(
            f"origin must not contain a query or fragment delimiter at {location}"
        )
    try:
        parsed = urlsplit(origin)
    except ValueError as exc:
        raise ContractViolation(f"origin is malformed at {location}") from exc
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
        normalized_hostname = validate_hostname(hostname, location)
    else:
        raise ContractViolation(f"origin must use a DNS name at {location}")
    if "." not in normalized_hostname:
        raise ContractViolation(
            f"origin must use a fully qualified DNS name at {location}"
        )
    if is_documentation_hostname(normalized_hostname) and not synthetic:
        raise ContractViolation(
            f"reserved DNS name requires explicit synthetic mode at {location}"
        )
    if hostname_has_suffix(
        normalized_hostname, NON_DOCUMENTATION_SPECIAL_USE_DNS_SUFFIXES
    ):
        raise ContractViolation(f"special-use DNS name is forbidden at {location}")
    return normalized_hostname


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


def require_managed_descendant(raw: str, root: PurePosixPath, location: str) -> None:
    if root not in PurePosixPath(raw).parents:
        raise ContractViolation(
            f"managed path must be a strict descendant of {root} at {location}"
        )


def validate_path_contracts(inventory: dict[str, Any]) -> None:
    service_account = inventory["service_account"]
    paths = inventory["paths"]
    seen: dict[str, str] = {}
    for name, expected in CANONICAL_PATHS.items():
        contract = paths[name]
        location = f"inventory.paths.{name}"
        raw_path = contract["path"]
        validate_absolute_path(raw_path, f"{location}.path")
        if name == "quadlet_definitions":
            expected_path = QUADLET_DEFINITION_ROOT / str(service_account["uid"])
            if PurePosixPath(raw_path) != expected_path:
                raise ContractViolation(
                    "Quadlet definitions must use the administrator-managed per-user path"
                )
        else:
            managed_root = MANAGED_PATH_ROOTS.get(name, DEFAULT_MANAGED_PATH_ROOT)
            require_managed_descendant(raw_path, managed_root, f"{location}.path")
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
        elif expected.get("identity") == "operator-readable":
            expected_uid = 0
            expected_gid = service_account["gid"]
        else:
            expected_uid = expected["uid"]
            expected_gid = expected["gid"]
        if contract["uid"] != expected_uid or contract["gid"] != expected_gid:
            raise ContractViolation(f"fixed path ownership mismatch at {location}")
        if (
            contract["container_uid"] != expected.get("container_uid")
            or contract["container_gid"] != expected.get("container_gid")
        ):
            raise ContractViolation(
                f"fixed container ownership mismatch at {location}"
            )

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
    for name, (minimum_bytes, minimum_inodes) in HEADROOM_MINIMUMS.items():
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


def validate_subordinate_id_contract(service_account: dict[str, Any]) -> None:
    subordinate_ids = service_account["subordinate_ids"]
    account_ids = {
        "uid": service_account["uid"],
        "gid": service_account["gid"],
    }
    for dimension in ("uid", "gid"):
        selected_range = subordinate_ids[dimension]
        start = selected_range["start"]
        count = selected_range["count"]
        location = f"inventory.service_account.subordinate_ids.{dimension}"
        if count != SUBORDINATE_ID_COUNT:
            raise ContractViolation(
                f"subordinate {dimension} range must contain 65536 identities"
            )
        end = start + count - 1
        if end > MAX_SYSTEM_ID:
            raise ContractViolation(
                f"subordinate {dimension} range exceeds the Linux identity limit"
            )
        if start <= account_ids[dimension] <= end:
            raise ContractViolation(
                f"subordinate {dimension} range overlaps the service account at {location}"
            )
def validate_inventory(inventory: dict[str, Any], *, synthetic: bool = False) -> None:
    validate_inventory_schema(inventory)
    host = inventory["host"]
    host_hostname = validate_hostname(host["hostname"], "inventory.host.hostname")
    validate_addresses(host, synthetic=synthetic)

    service_account = inventory["service_account"]
    validate_absolute_path(service_account["home"], "inventory.service_account.home")
    validate_subordinate_id_contract(service_account)

    frontend_hostname = validate_origin(
        inventory["origins"]["frontend"],
        "inventory.origins.frontend",
        synthetic=synthetic,
    )
    api_hostname = validate_origin(
        inventory["origins"]["api"],
        "inventory.origins.api",
        synthetic=synthetic,
    )
    if frontend_hostname == api_hostname:
        raise ContractViolation("frontend and API origins must use different DNS names")
    if host_hostname in {frontend_hostname, api_hostname}:
        raise ContractViolation("host hostname must differ from frontend and API origins")

    validate_path_contracts(inventory)
    validate_storage_requirements(inventory["resources"])


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
    if facts["architecture"] != inventory["host"]["architecture"]:
        raise ContractViolation("host architecture does not match the inventory")


def validate_kernel_facts(kernel: dict[str, Any], architecture: str) -> None:
    kernel_match = re.fullmatch(
        rf"({VERSION_COMPONENT})\.({VERSION_COMPONENT})\.({VERSION_COMPONENT})"
        r"(?P<suffix>[-+._][A-Za-z0-9][A-Za-z0-9+._-]*)?",
        kernel["release"],
    )
    if kernel_match is None:
        raise ContractViolation(
            "host kernel must be the Debian 13 stable Linux 6.12 series"
        )
    kernel_version = tuple(int(kernel_match.group(index)) for index in (1, 2, 3))
    kernel_suffix = kernel_match.group("suffix") or ""
    if (
        kernel_version[:2] != (6, 12)
        or kernel_suffix.lower().startswith("-rc")
        or KERNEL_RELEASE_CANDIDATE_PATTERN.search(kernel_suffix)
    ):
        raise ContractViolation(
            "host kernel must be the Debian 13 stable Linux 6.12 series"
        )
    if kernel["package_architecture"] != architecture:
        raise ContractViolation(
            "kernel package architecture does not match the admitted host architecture"
        )
    apparmor = kernel["apparmor"]
    if apparmor["profiles_in_enforce_mode"] > apparmor["profiles_loaded"]:
        raise ContractViolation(
            "AppArmor enforcing-profile count exceeds the loaded-profile count"
        )


def validate_runtime_facts(
    inventory: dict[str, Any], facts: dict[str, Any]
) -> None:
    runtime = facts["runtime"]
    service_account = inventory["service_account"]
    podman_version = parse_version(runtime["version"], "host facts.runtime.version")
    if podman_version < (5, 4, 2) or podman_version >= (6, 0, 0):
        raise ContractViolation("Podman must be supported 5.x at or above 5.4.2")
    if (
        runtime["owner_uid"] != service_account["uid"]
        or runtime["owner_gid"] != service_account["gid"]
    ):
        raise ContractViolation(
            "rootless Podman authority does not belong to the service account"
        )

    user_namespace = runtime["user_namespace"]
    if user_namespace["account"] != service_account["name"]:
        raise ContractViolation(
            "rootless user-namespace account does not match the inventory"
        )
    for fact_name, inventory_name, source in (
        ("subuid", "uid", "/etc/subuid"),
        ("subgid", "gid", "/etc/subgid"),
    ):
        fact_range = user_namespace[fact_name]
        expected_range = service_account["subordinate_ids"][inventory_name]
        if fact_range["source"] != source or any(
            fact_range[field] != expected_range[field]
            for field in ("start", "count")
        ):
            raise ContractViolation(
                f"effective {fact_name} mapping does not match the inventory"
            )

    expected_runtime_directory = f"/run/user/{service_account['uid']}"
    expected_quadlet_path = inventory["paths"]["quadlet_definitions"]["path"]
    quadlet = runtime["quadlet"]
    if quadlet["effective_search_paths"] != [expected_quadlet_path]:
        raise ContractViolation(
            "effective Quadlet search path is not restricted to the reviewed tree"
        )

    storage = runtime["storage"]
    if storage["graphroot"] != inventory["paths"]["podman_graph_root"]["path"]:
        raise ContractViolation("Podman graphroot does not match the inventory")
    expected_runroot = f"{expected_runtime_directory}/containers"
    if storage["runroot"] != expected_runroot:
        raise ContractViolation(
            "rootless Podman runroot does not match the user runtime boundary"
        )
    validate_absolute_path(storage["graphroot"], "host facts.runtime.storage.graphroot")
    validate_absolute_path(storage["runroot"], "host facts.runtime.storage.runroot")


def validate_service_account_facts(
    inventory: dict[str, Any], facts: dict[str, Any]
) -> None:
    service_account = facts["service_account"]
    expected_account = inventory["service_account"]
    for field in ("name", "group", "uid", "gid", "home"):
        if service_account[field] != expected_account[field]:
            raise ContractViolation(
                "effective service-account identity does not match the inventory"
            )


def validate_network_facts(inventory: dict[str, Any], network: dict[str, Any]) -> None:
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


def validate_tool_facts(tools: list[str]) -> None:
    missing_tools = sorted(REQUIRED_TOOLS - set(tools))
    if missing_tools:
        raise ContractViolation(f"required host tool is missing: {missing_tools[0]}")


def posix_mode_grants_service_account_write(
    access: dict[str, Any], service_account: dict[str, Any]
) -> bool:
    mode = int(access["mode"], 8)
    return (
        access["uid"] == service_account["uid"] and bool(mode & 0o200)
    ) or (
        access["gid"] == service_account["gid"] and bool(mode & 0o020)
    ) or bool(mode & 0o002)


def validate_path_access_fact(
    service_account: dict[str, Any],
    name: str,
    access: dict[str, Any],
    *,
    expected_path: str,
    expected_uid: int | None,
    expected_gid: int | None,
    expected_mode: str,
    expected_service_write: bool,
    expected_ancestor_write: bool,
) -> None:
    if access["path"] != expected_path:
        raise ContractViolation(f"effective path does not match inventory at {name}")
    if (
        expected_uid is not None
        and access["uid"] != expected_uid
    ) or (
        expected_gid is not None
        and access["gid"] != expected_gid
    ):
        raise ContractViolation(
            f"effective path ownership does not match inventory at {name}"
        )
    if access["mode"] != expected_mode:
        raise ContractViolation(
            f"effective path mode does not match inventory at {name}"
        )
    if posix_mode_grants_service_account_write(
        access, service_account
    ) and not access["service_account_can_write"]:
        raise ContractViolation(
            f"effective path access contradicts ownership or mode at {name}"
        )
    if access["service_account_can_write"] is not expected_service_write:
        raise ContractViolation(
            f"effective path access does not match inventory at {name}"
        )
    if (
        access["ancestors_service_account_can_write"]
        is not expected_ancestor_write
    ):
        raise ContractViolation(
            f"effective path ancestry does not match the trust boundary at {name}"
        )


def validate_filesystem_fact(
    inventory: dict[str, Any],
    name: str,
    filesystem: dict[str, Any],
) -> None:
    path_contract = inventory["paths"][name]
    owner_role = path_contract["owner_role"]
    try:
        expected_service_write = OWNER_ROLE_SERVICE_ACCOUNT_WRITE[owner_role]
    except KeyError as exc:
        raise ContractViolation(f"unsupported path owner role at {name}") from exc
    validate_path_access_fact(
        inventory["service_account"],
        name,
        filesystem["access"],
        expected_path=path_contract["path"],
        expected_uid=path_contract["uid"],
        expected_gid=path_contract["gid"],
        expected_mode=path_contract["mode"],
        expected_service_write=expected_service_write,
        expected_ancestor_write=False,
    )
    if filesystem["filesystem"] == "xfs" and filesystem["xfs_ftype"] is not True:
        raise ContractViolation(f"XFS storage must use ftype=1 at {name}")
    if filesystem["filesystem"] == "ext4" and filesystem["xfs_ftype"] is not None:
        raise ContractViolation(f"ext4 storage must not report an XFS ftype value at {name}")


def validate_filesystem_facts(
    inventory: dict[str, Any], filesystems: dict[str, Any]
) -> None:
    for name in FILESYSTEM_PATH_KEYS:
        validate_filesystem_fact(inventory, name, filesystems[name])


def validate_path_access_facts(
    inventory: dict[str, Any], path_access: dict[str, Any]
) -> None:
    service_account = inventory["service_account"]
    runtime_directory = f"/run/user/{service_account['uid']}"
    expectations = (
        (
            "service_account_home",
            service_account["home"],
            0,
            service_account["gid"],
            "0750",
            False,
            False,
        ),
        (
            "systemd_runtime_directory",
            runtime_directory,
            service_account["uid"],
            service_account["gid"],
            "0700",
            True,
            False,
        ),
        (
            "podman_runroot",
            f"{runtime_directory}/containers",
            service_account["uid"],
            service_account["gid"],
            "0700",
            True,
            True,
        ),
        (
            "quadlet_definitions",
            inventory["paths"]["quadlet_definitions"]["path"],
            0,
            0,
            "0755",
            False,
            False,
        ),
    )
    for name, path, uid, gid, mode, service_write, ancestor_write in expectations:
        validate_path_access_fact(
            service_account,
            name,
            path_access[name],
            expected_path=path,
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=mode,
            expected_service_write=service_write,
            expected_ancestor_write=ancestor_write,
        )


def validate_headroom_fact(
    inventory: dict[str, Any],
    name: str,
    headroom: dict[str, Any],
    resource_totals: dict[str, int],
) -> None:
    requirement = inventory["resources"]["storage"][name]
    checks = (
        ("free_bytes", "minimum_free_bytes"),
        ("free_percent", "minimum_free_percent"),
        ("free_inodes", "minimum_free_inodes"),
        ("free_inode_percent", "minimum_free_inode_percent"),
    )
    for fact_name, requirement_name in checks:
        actual = headroom[fact_name]
        if fact_name == "free_bytes" and actual > resource_totals["storage_total_bytes"]:
            raise ContractViolation(f"storage free bytes exceed host total at {name}")
        if fact_name == "free_inodes" and actual > resource_totals["total_inodes"]:
            raise ContractViolation(f"storage free inodes exceed host total at {name}")
        if actual < requirement[requirement_name]:
            raise ContractViolation(f"storage headroom is insufficient at {name}.{fact_name}")

    consistency_checks = (
        ("free_bytes", "free_percent", "storage_total_bytes"),
        ("free_inodes", "free_inode_percent", "total_inodes"),
    )
    for absolute_name, percentage_name, total_name in consistency_checks:
        free = headroom[absolute_name]
        percentage = headroom[percentage_name]
        total = resource_totals[total_name]
        if free * 100 >= total * (percentage + 1):
            raise ContractViolation(
                f"storage absolute and percentage facts conflict at {name}"
            )


def validate_resource_facts(
    inventory: dict[str, Any], resource_facts: dict[str, Any]
) -> None:
    resource_totals: dict[str, int] = {}
    for field in ("logical_cpus", "memory_bytes", "storage_total_bytes", "total_inodes"):
        actual = resource_facts[field]
        resource_totals[field] = actual
        if actual < inventory["resources"][field]:
            raise ContractViolation(f"host resource is below inventory floor: {field}")

    headroom_facts = resource_facts["storage"]
    for name in HEADROOM_MINIMUMS:
        validate_headroom_fact(
            inventory,
            name,
            headroom_facts[name],
            resource_totals,
        )


def validate_host_facts(inventory: dict[str, Any], facts: dict[str, Any]) -> None:
    validate_host_facts_schema(facts)
    validate_platform_facts(inventory, facts)
    validate_kernel_facts(facts["kernel"], facts["architecture"])
    validate_runtime_facts(inventory, facts)
    validate_service_account_facts(inventory, facts)
    validate_network_facts(inventory, facts["network"])
    validate_path_access_facts(inventory, facts["path_access"])
    validate_tool_facts(facts["tools"])
    validate_filesystem_facts(inventory, facts["filesystems"])
    validate_resource_facts(inventory, facts["resources"])


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a SecPal production inventory and supplied host-fact document."
    )
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--host-facts", required=True, type=Path)
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="permit reserved documentation addresses in synthetic fixtures",
    )
    return parser.parse_args()


def abort(message: str) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    arguments = parse_arguments()
    try:
        inventory = read_document(arguments.inventory, "inventory")
        validate_inventory(inventory, synthetic=arguments.synthetic)
        host_facts = read_document(arguments.host_facts, "host facts")
        validate_host_facts(inventory, host_facts)
    except ContractViolation as exc:
        abort(str(exc))
    print("Production inventory and supplied host facts satisfy schema version 1.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
