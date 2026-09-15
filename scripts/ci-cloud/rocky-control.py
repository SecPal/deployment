#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Closed admission and discovery utility for the Rocky GCP control plane."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import ipaddress
import json
import os
import re
import stat
import struct
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
INSTALLED_TARGET_FAILURE_CLASSIFIER = Path(
    "/usr/local/sbin/secpal-classify-rocky-target-failure"
)
INSTALLED_TARGET_REPLAY_VERIFIER = Path(
    "/usr/local/sbin/secpal-verify-rocky-target-replay"
)
CLASSIFIER_TRUSTED_UID = 0
CLASSIFIER_TRUSTED_GID = 0
MAX_TARGET_FAILURE_CLASSIFIER_BYTES = 131_072
TARGET_FAILURE_CLASSIFIER_SYMBOL = "validate_admitted_daemon_reload_adjacency"
TARGET_START_CLASSIFIER_SYMBOL = "validate_admitted_quadlet_start_diagnostic"
TARGET_ACTIVE_CLASSIFIER_SYMBOL = "validate_admitted_quadlet_active_diagnostic"
TARGET_PRIMARY_CLASSIFIER_SYMBOL = "validate_admitted_primary_workload_diagnostic"
TARGET_REPLAY_VERIFIER_SYMBOL = "validate_replay_witness"
SELINUX_ISOLATION_CONTRACT_PATH = ROOT / "scripts/selinux_isolation_contract.py"
SELINUX_ISOLATION_INVARIANT_OWNER = (
    "selinux_isolation_contract.admit_selinux_isolation"
)
QUADLET_AUTHORITY_CONTRACT_PATH = ROOT / "scripts/quadlet_authority_contract.py"
QUADLET_AUTHORITY_INVARIANT_OWNER = (
    "quadlet_authority_contract.admit_quadlet_authority"
)
ARM64_PROFILE = "gcp-rocky-10-2-arm64"
X86_64_PROFILE = "gcp-rocky-10-2-x86-64"
PROFILE_PATHS = {
    ARM64_PROFILE: ROOT / f"config/ci-cloud/{ARM64_PROFILE}.json",
    X86_64_PROFILE: ROOT / f"config/ci-cloud/{X86_64_PROFILE}.json",
}
SCHEMAS = {
    "discovery": ROOT / "schemas/rocky-cloud-discovery-evidence.schema.json",
    "continuation": ROOT / "schemas/rocky-cloud-continuation.schema.json",
    "preparation": ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json",
    "preparation-failure": ROOT
    / "schemas/rocky-cloud-preparation-failure-evidence.schema.json",
    "qualification": ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json",
    "qualification-readiness-failure": ROOT
    / "schemas/rocky-cloud-qualification-readiness-failure.schema.json",
    "target-source-failure": ROOT
    / "schemas/rocky-cloud-target-source-failure.schema.json",
    "target-qualification-failure": ROOT
    / "schemas/rocky-cloud-target-qualification-failure.schema.json",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
AUTHENTICATED_PACKAGE_INVARIANT_OWNER = (
    "rocky_preparation_contract.admit_package"
)
ROCKY_PACKAGES = (
    "podman", "conmon", "crun", "netavark", "aardvark-dns", "passt",
    "shadow-utils-subid", "systemd", "container-selinux", "audit",
    "policycoreutils", "policycoreutils-python-utils",
    "selinux-policy-targeted", "curl", "dnf", "git", "jq", "nftables",
    "openssh-server", "sudo", "python3-jsonschema", "dnf-plugins-core",
)
PODMAN_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
ACCESS_REQUEST_FIELDS = {
    "runner_ipv4",
    "run_attempt",
    "run_id",
    "ssh_public_key",
    "target_sha",
}
ACCESS_REQUEST_MAX_BYTES = 1024
ED25519_KEY = re.compile(
    r"^ssh-ed25519 ([A-Za-z0-9+/]+={0,2}) "
    r"(secpal-rocky-([1-9][0-9]{0,19})-([1-9][0-9]{0,2}))$"
)
IMAGE_PREFIX = (
    "https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/"
    "global/images/"
)
DISCOVERY_ROOT = (
    "https://compute.googleapis.com/compute/v1/projects/rocky-linux-cloud/"
    "global/images/family/"
)
PROVIDER_ARCHITECTURES = {"aarch64": "ARM64", "x86_64": "X86_64"}
REPOSITORY_DIAGNOSTIC_REASONS = {
    "validate-dnf4": {"command-failed", "postcondition-failed"},
    "load-reviewed-provider-repositories": {"profile-invalid"},
    "observe-initial-enabled-repositories": {
        "command-failed",
        "parse-failed",
        "observation-limit-exceeded",
        "invalid-repository-id",
    },
    "validate-initial-pre-admission": {"postcondition-failed"},
    "observe-available-repository-definitions": {
        "command-failed",
        "parse-failed",
        "observation-limit-exceeded",
        "invalid-repository-id",
    },
    "validate-required-repository-definitions": {
        "required-repository-definition-unavailable"
    },
    "install-repository-management-prerequisite": {"package-transaction-failed"},
    "enable-required-rocky-repository": {"repository-mutation-failed"},
    "observe-normalized-pre-removal-state": {
        "command-failed",
        "parse-failed",
        "observation-limit-exceeded",
        "invalid-repository-id",
    },
    "validate-normalized-pre-removal-state": {"postcondition-failed"},
    "disable-reviewed-provider-repository": {"repository-mutation-failed"},
    "observe-final-repository-state": {
        "command-failed",
        "parse-failed",
        "observation-limit-exceeded",
        "invalid-repository-id",
    },
    "validate-final-repository-state": {"postcondition-failed"},
}
# Repository IDs are only meaningful for operations on a single reviewed
# repository.  Their allowed domain is bound to the canonical profile.
REPOSITORY_ID_OPERATION_DOMAINS = {
    "validate-required-repository-definitions": "final",
    "enable-required-rocky-repository": "final",
    "disable-reviewed-provider-repository": "provider",
}
FIXTURE_DIAGNOSTIC_REASONS = {
    "pull-immutable-fixture": {"command-failed"},
    "verify-immutable-fixture-present": {"command-failed"},
    "inspect-resolved-arm64-child": {"command-failed"},
    "validate-resolved-arm64-child": {"postcondition-failed"},
    "inspect-resolved-amd64-child": {"command-failed"},
    "validate-resolved-amd64-child": {"postcondition-failed"},
}
PACKAGE_COLLECTION_OPERATIONS = {
    "query-package-nevra",
    "resolve-package-repository",
    "inspect-installed-signed-header",
    "normalize-package-evidence",
    "normalize-installed-signed-header",
    "admit-package-repository",
    "admit-package-signature",
    "admit-package-identity",
}
UNIT_COLLECTION_OPERATIONS = {"query-update-unit", "query-podman-socket"}


class ControlError(RuntimeError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ControlError("JSON input contains a duplicate object key")
        result[key] = value
    return result


def load_bounded_object(path: Path, maximum_bytes: int) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ControlError(f"cannot read {path}") from error
    if len(payload) > maximum_bytes:
        raise ControlError(f"JSON input is too large: {path}")
    try:
        document = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError(f"invalid JSON: {path}") from error
    if not isinstance(document, dict):
        raise ControlError(f"JSON input must be an object: {path}")
    return document


def load_object(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ControlError(f"cannot read {path}") from error
    if len(payload) > 1_000_000:
        raise ControlError(f"JSON input is too large: {path}")
    try:
        document = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError(f"invalid JSON: {path}") from error
    if not isinstance(document, dict):
        raise ControlError(f"JSON input must be an object: {path}")
    return document


def validate_ed25519_public_key(value: str, run_id: str, run_attempt: str) -> None:
    if len(value.encode("utf-8")) > 128:
        raise ControlError("access request public key exceeds the size bound")
    match = ED25519_KEY.fullmatch(value)
    if match is None or match.group(3) != run_id or match.group(4) != run_attempt:
        raise ControlError("access request public key is outside the per-run format")
    try:
        blob = base64.b64decode(match.group(1), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ControlError("access request public key is not valid base64") from error
    try:
        algorithm_size = struct.unpack(">I", blob[:4])[0]
        algorithm_end = 4 + algorithm_size
        key_size = struct.unpack(">I", blob[algorithm_end : algorithm_end + 4])[0]
        key_end = algorithm_end + 4 + key_size
    except struct.error as error:
        raise ControlError("access request public key blob is malformed") from error
    if (
        blob[4:algorithm_end] != b"ssh-ed25519"
        or key_size != 32
        or key_end != len(blob)
    ):
        raise ControlError("access request public key is not an Ed25519 key")


def validate_access_request(
    path: Path, target_sha: str, run_id: str, run_attempt: str
) -> None:
    if (
        SHA.fullmatch(target_sha) is None
        or RUN_ID.fullmatch(run_id) is None
        or RUN_ATTEMPT.fullmatch(run_attempt) is None
    ):
        raise ControlError("access request bindings are outside the closed format")
    document = load_bounded_object(path, ACCESS_REQUEST_MAX_BYTES)
    if set(document) != ACCESS_REQUEST_FIELDS:
        raise ControlError("access request does not contain the exact field set")
    if any(type(document[field]) is not str for field in ACCESS_REQUEST_FIELDS):
        raise ControlError("access request fields must be strings")
    if (
        document["target_sha"] != target_sha
        or document["run_id"] != run_id
        or document["run_attempt"] != run_attempt
    ):
        raise ControlError("access request does not match this qualification run")
    try:
        address = ipaddress.ip_address(document["runner_ipv4"])
    except ValueError as error:
        raise ControlError("access request runner address is malformed") from error
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise ControlError("access request runner address is not public IPv4")
    validate_ed25519_public_key(document["ssh_public_key"], run_id, run_attempt)


def write_object(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def canonical_profile(profile_name: str = ARM64_PROFILE) -> dict[str, Any]:
    path = PROFILE_PATHS.get(profile_name)
    if path is None:
        raise ControlError("profile identity is outside the closed reviewed set")
    document = load_object(path)
    if document.get("profile") != profile_name:
        raise ControlError("profile identity contradicts its reviewed filename")
    return document


def validate_profile(profile_name: str) -> None:
    profile = canonical_profile(profile_name)
    expected_common = {
        "schema_version": 1,
        "profile": profile_name,
        "provider": "google",
        "project": "secpal-dev",
        "region": "europe-west3",
        "zone": "europe-west3-a",
        "disk": {"type": "hyperdisk-balanced", "size_gib": 120},
        "instance_count": 1,
        "guest": {"id": "rocky", "version_id": "10.2"},
        "repositories": {
            "final_enabled_repositories": ["appstream", "baseos", "extras"],
            "pre_admission_provider_repositories": [
                "google-cloud-sdk",
                "google-compute-engine",
            ],
        },
        "ttl_seconds": 10800,
    }
    expected_specific = {
        ARM64_PROFILE: {
            "machine_type": "c4a-standard-4",
            "architecture": "aarch64",
            "image": {
                "project": "rocky-linux-cloud",
                "discovery_family": "rocky-linux-10-arm64",
            },
            "fixture": {
                "input": "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1",
                "arm64_child": "sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192",
            },
        },
        X86_64_PROFILE: {
            "machine_type": "c3-standard-4",
            "architecture": "x86_64",
            "cpu_baseline": "x86-64-v3",
            "image": {
                "project": "rocky-linux-cloud",
                "discovery_family": "rocky-linux-10",
            },
            "fixture": {
                "input": "docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1",
                "amd64_child": "sha256:eafc1edb577d2e9b458664a15f23ea1c370214193226069eb22921169fc7e43f",
            },
        },
    }
    if profile != {**expected_common, **expected_specific[profile_name]}:
        raise ControlError("profile differs from its reviewed Rocky contract")


def image_matches_profile(profile: dict[str, Any], self_link: object) -> bool:
    if not isinstance(self_link, str) or not self_link.startswith(IMAGE_PREFIX):
        return False
    name = self_link.removeprefix(IMAGE_PREFIX)
    pattern = (
        r"^rocky-linux-10-[a-z0-9-]*arm64[a-z0-9-]*$"
        if profile["architecture"] == "aarch64"
        else r"^rocky-linux-10-v[0-9]{8}$"
    )
    return re.fullmatch(pattern, name) is not None


def validate_authenticated_package_semantics(
    packages: list[dict[str, Any]], host_architecture: str, podman_version: str
) -> None:
    """Independently enforce rocky_preparation_contract.admit_package."""
    if len(packages) != len(ROCKY_PACKAGES):
        raise ControlError("authenticated package set has invalid cardinality")
    for package_key, package in zip(ROCKY_PACKAGES, packages, strict=True):
        name = package["name"]
        epoch = package["epoch"]
        version = package["version"]
        release = package["release"]
        architecture = package["architecture"]
        epoch_prefix = "" if epoch == "0" else f"{epoch}:"
        expected_nevra = (
            f"{name}-{epoch_prefix}{version}-{release}.{architecture}"
        )
        if (
            name != package_key
            or architecture not in {host_architecture, "noarch"}
            or package["nevra"] != expected_nevra
        ):
            raise ControlError(
                "authenticated package identity contradicts its package key or host architecture"
            )
    podman = packages[0]
    match = PODMAN_VERSION.fullmatch(podman["version"])
    if match is None:
        raise ControlError("Podman package version representation is malformed")
    version = tuple(int(part) for part in match.groups())
    if (
        not (5, 8, 2) <= version < (6, 0, 0)
        or podman_version != podman["version"]
    ):
        raise ControlError("Podman package version is outside the admitted range")


def validate_preparation_package_semantics(document: dict[str, Any]) -> None:
    validate_authenticated_package_semantics(
        document["packages"],
        document["guest"]["uname_machine"],
        document["runtime"]["podman"],
    )


def validate_profile_evidence_compatibility(
    kind: str, document: dict[str, Any]
) -> None:
    if kind not in {"discovery", "continuation", "preparation"}:
        return
    profile_name = (
        document.get("run", {}).get("profile")
        if kind == "preparation"
        else document.get("profile")
    )
    if not isinstance(profile_name, str):
        raise ControlError(f"{kind} evidence has no reviewed profile identity")
    validate_profile(profile_name)
    profile = canonical_profile(profile_name)
    architecture = profile["architecture"]
    if kind == "discovery":
        expected = {
            "provider": profile["provider"],
            "image_project": profile["image"]["project"],
            "discovery_family": profile["image"]["discovery_family"],
            "architecture": PROVIDER_ARCHITECTURES[architecture],
        }
        if any(document.get(key) != value for key, value in expected.items()):
            raise ControlError("discovery evidence mixes incompatible profile facts")
    elif kind == "continuation":
        if (
            document.get("provider") != profile["provider"]
            or document.get("zone") != profile["zone"]
            or not image_matches_profile(
                profile, document.get("exact_image_self_link")
            )
        ):
            raise ControlError("continuation evidence mixes incompatible profile facts")
    else:
        fixture_key = (
            "resolved_arm64_child"
            if architecture == "aarch64"
            else "resolved_amd64_child"
        )
        expected_fixture = {
            "input": profile["fixture"]["input"],
            fixture_key: profile["fixture"][
                "arm64_child" if architecture == "aarch64" else "amd64_child"
            ],
            "pre_staged": True,
        }
        if (
            document.get("guest", {}).get("uname_machine") != architecture
            or document.get("fixture") != expected_fixture
            or not image_matches_profile(
                profile, document.get("image", {}).get("exact_self_link")
            )
        ):
            raise ControlError("preparation evidence mixes incompatible profile facts")


def validate_evidence(
    kind: str, path: Path, *, authenticated_native: bool = False
) -> dict[str, Any]:
    if kind == "qualification" and not authenticated_native:
        raise ControlError(
            "qualification schema validity is not authenticated native admission"
        )
    schema = load_object(SCHEMAS[kind])
    document = load_object(path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise ControlError(f"{kind} evidence rejected at {location}: {first.message}")
    validate_profile_evidence_compatibility(kind, document)
    if kind == "preparation-failure":
        validate_preparation_failure_semantics(document)
    elif kind == "preparation":
        validate_preparation_package_semantics(document)
    return document


def validate_native_observation(
    path: Path,
    target_sha: str,
    control_sha: str,
    run_id: str,
    run_attempt: str,
) -> dict[str, Any]:
    if (
        SHA.fullmatch(target_sha) is None
        or SHA.fullmatch(control_sha) is None
        or RUN_ID.fullmatch(run_id) is None
        or RUN_ATTEMPT.fullmatch(run_attempt) is None
    ):
        raise ControlError("native observation bindings are outside the closed format")
    schema = load_object(SCHEMAS["qualification"])
    observation_schema = {
        **schema["properties"]["native_observation"],
        "$defs": schema["$defs"],
    }
    observation = load_object(path)
    errors = sorted(
        Draft202012Validator(observation_schema).iter_errors(observation),
        key=lambda item: list(item.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise ControlError(
            f"native observation rejected at {location}: {first.message}"
        )
    expected = {
        "target_sha": target_sha,
        "trusted_control_sha": control_sha,
        "qualification_run_id": run_id,
        "qualification_run_attempt": run_attempt,
    }
    if any(observation[key] != value for key, value in expected.items()):
        raise ControlError("native observation is not bound to this exact run")
    validate_authenticated_package_semantics(
        observation["packages"],
        observation["host"]["architecture"],
        observation["podman_version"],
    )
    return observation


def load_selinux_isolation_contract() -> Any:
    try:
        metadata = SELINUX_ISOLATION_CONTRACT_PATH.lstat()
    except OSError as error:
        raise ControlError("SELinux isolation contract is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or SELINUX_ISOLATION_CONTRACT_PATH.is_symlink()
        or not 0 < metadata.st_size <= 65_536
        or metadata.st_mode & 0o022
        or (ROOT == Path("/opt/secpal-control") and (metadata.st_uid, metadata.st_gid) != (0, 0))
    ):
        raise ControlError("SELinux isolation contract is not trusted")
    loader = SourceFileLoader(
        "selinux_isolation_contract", os.fspath(SELINUX_ISOLATION_CONTRACT_PATH)
    )
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise ControlError("SELinux isolation contract cannot be loaded")
    contract = importlib.util.module_from_spec(specification)
    write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(contract)
    except Exception as error:
        raise ControlError("SELinux isolation contract cannot be loaded") from error
    finally:
        sys.dont_write_bytecode = write_bytecode
    if (
        getattr(contract, "INVARIANT_OWNER", None)
        != SELINUX_ISOLATION_INVARIANT_OWNER
        or not callable(getattr(contract, "validate_isolation_evidence", None))
        or not callable(
            getattr(contract, "validate_avc_correlation_diagnostic", None)
        )
        or not callable(getattr(contract, "canonical_bytes", None))
    ):
        raise ControlError("SELinux isolation contract surface is invalid")
    return contract


def load_quadlet_authority_contract() -> Any:
    try:
        metadata = QUADLET_AUTHORITY_CONTRACT_PATH.lstat()
    except OSError as error:
        raise ControlError("Quadlet authority contract is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or QUADLET_AUTHORITY_CONTRACT_PATH.is_symlink()
        or not 0 < metadata.st_size <= 65_536
        or metadata.st_mode & 0o022
        or (
            ROOT == Path("/opt/secpal-control")
            and (metadata.st_uid, metadata.st_gid) != (0, 0)
        )
    ):
        raise ControlError("Quadlet authority contract is not trusted")
    loader = SourceFileLoader(
        "quadlet_authority_contract", os.fspath(QUADLET_AUTHORITY_CONTRACT_PATH)
    )
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise ControlError("Quadlet authority contract cannot be loaded")
    contract = importlib.util.module_from_spec(specification)
    write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(contract)
    except Exception as error:
        raise ControlError("Quadlet authority contract cannot be loaded") from error
    finally:
        sys.dont_write_bytecode = write_bytecode
    if (
        getattr(contract, "INVARIANT_OWNER", None)
        != QUADLET_AUTHORITY_INVARIANT_OWNER
        or not callable(getattr(contract, "validate_authority_evidence", None))
        or not callable(getattr(contract, "canonical_bytes", None))
    ):
        raise ControlError("Quadlet authority contract surface is invalid")
    return contract


def validate_native_qualification(
    path: Path,
    stdout_path: Path,
    native_observation_path: Path,
    target_sha: str,
    control_sha: str,
    run_id: str,
    run_attempt: str,
) -> None:
    authenticated_observation = validate_native_observation(
        native_observation_path, target_sha, control_sha, run_id, run_attempt
    )
    document = validate_evidence(
        "qualification", path, authenticated_native=True
    )
    if (
        document["target_sha"] != target_sha
        or document["native_observation"] != authenticated_observation
    ):
        raise ControlError(
            "native qualification differs from its authenticated controller binding"
        )
    try:
        stdout = stdout_path.read_bytes()
    except OSError as error:
        raise ControlError("native qualification stdout is unavailable") from error
    if (
        len(stdout) != document["stdout_bytes"]
        or hashlib.sha256(stdout).hexdigest() != document["stdout_sha256"]
    ):
        raise ControlError("native qualification stdout binding is invalid")
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ControlError("native qualification stdout is not UTF-8") from error
    if text.count("PASS: Rocky Linux 10.2 target workload contract") != 1:
        raise ControlError("native qualification success marker is not singular")
    isolation_digests = re.findall(
        r"^selinux_isolation_sha256=([0-9a-f]{64})$", text, re.MULTILINE
    )
    if len(isolation_digests) != 1:
        raise ControlError("native qualification isolation binding is invalid")
    contract = load_selinux_isolation_contract()
    try:
        contract.validate_isolation_evidence(document["selinux_isolation"])
    except contract.IsolationError as error:
        raise ControlError("native SELinux isolation evidence is invalid") from error
    if (
        hashlib.sha256(
            contract.canonical_bytes(document["selinux_isolation"])
        ).hexdigest()
        != isolation_digests[0]
    ):
        raise ControlError("native SELinux isolation normalization binding is invalid")
    authority_encodings = re.findall(
        r"^quadlet_authority_base64=([A-Za-z0-9+/]+={0,2})$", text, re.MULTILINE
    )
    if len(authority_encodings) != 1:
        raise ControlError("native Quadlet authority binding is invalid")
    authority_contract = load_quadlet_authority_contract()
    try:
        authority_bytes = base64.b64decode(authority_encodings[0], validate=True)
        if len(authority_bytes) > 16_384:
            raise ValueError("Quadlet authority evidence exceeds its closed bound")
        authority = json.loads(authority_bytes)
        authority_contract.validate_authority_evidence(authority)
        if authority_contract.canonical_bytes(authority) != authority_bytes:
            raise ValueError("Quadlet authority evidence is not canonical")
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        authority_contract.AuthorityError,
    ) as error:
        raise ControlError("native Quadlet authority binding is invalid") from error
    if document["quadlet_authority"] != authority:
        raise ControlError(
            "target and trusted Quadlet authority normalization disagree"
        )


def validate_target_source_failure(
    path: Path,
    target_sha: str,
    control_sha: str,
    run_id: str,
    run_attempt: str,
) -> None:
    if (
        SHA.fullmatch(target_sha) is None
        or SHA.fullmatch(control_sha) is None
        or RUN_ID.fullmatch(run_id) is None
        or RUN_ATTEMPT.fullmatch(run_attempt) is None
    ):
        raise ControlError("target source failure bindings are outside the closed format")
    document = validate_evidence("target-source-failure", path)
    if (
        document["target_sha"] != target_sha
        or document["trusted_control_sha"] != control_sha
        or document["qualification_run_id"] != run_id
        or document["qualification_run_attempt"] != run_attempt
    ):
        raise ControlError("target source failure is not bound to this qualification run")


def load_target_failure_classifier() -> Any:
    """Load one admitted, exact-path classifier without module-path resolution."""
    repository_path = ROOT / "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
    if repository_path.exists():
        classifier_path = repository_path
        installed = False
    else:
        classifier_path = INSTALLED_TARGET_FAILURE_CLASSIFIER
        installed = True

    try:
        metadata = classifier_path.lstat()
    except OSError as error:
        raise ControlError("target qualification classifier is unavailable") from error
    if not classifier_path.is_absolute() or not stat.S_ISREG(metadata.st_mode):
        raise ControlError("target qualification classifier representation is invalid")
    if metadata.st_mode & 0o022:
        raise ControlError("target qualification classifier representation is invalid")
    if not 0 < metadata.st_size <= MAX_TARGET_FAILURE_CLASSIFIER_BYTES:
        raise ControlError("target qualification classifier representation is invalid")
    if installed and (
        metadata.st_uid != CLASSIFIER_TRUSTED_UID
        or metadata.st_gid != CLASSIFIER_TRUSTED_GID
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ControlError("target qualification classifier representation is invalid")

    loader = SourceFileLoader(
        "secpal_target_qualification_failure", os.fspath(classifier_path)
    )
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise ControlError("target qualification classifier cannot be loaded")
    classifier = importlib.util.module_from_spec(specification)
    write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(classifier)
    except Exception as error:
        raise ControlError("target qualification classifier cannot be loaded") from error
    finally:
        sys.dont_write_bytecode = write_bytecode
    if not callable(getattr(classifier, TARGET_FAILURE_CLASSIFIER_SYMBOL, None)):
        raise ControlError("target qualification classifier cannot be loaded")
    if not callable(getattr(classifier, TARGET_START_CLASSIFIER_SYMBOL, None)):
        raise ControlError("target qualification classifier cannot be loaded")
    if not callable(getattr(classifier, TARGET_ACTIVE_CLASSIFIER_SYMBOL, None)):
        raise ControlError("target qualification classifier cannot be loaded")
    if not callable(getattr(classifier, TARGET_PRIMARY_CLASSIFIER_SYMBOL, None)):
        raise ControlError("target qualification classifier cannot be loaded")
    return classifier


def load_target_replay_verifier() -> Any:
    """Load the independent exact-path replay verifier without path lookup."""
    repository_path = (
        ROOT / "scripts/ci-cloud/verify-rocky-target-qualification-replay.py"
    )
    if repository_path.exists():
        verifier_path = repository_path
        installed = False
    else:
        verifier_path = INSTALLED_TARGET_REPLAY_VERIFIER
        installed = True
    try:
        metadata = verifier_path.lstat()
    except OSError as error:
        raise ControlError("target qualification replay verifier is unavailable") from error
    if (
        not verifier_path.is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o022
        or not 0 < metadata.st_size <= MAX_TARGET_FAILURE_CLASSIFIER_BYTES
    ):
        raise ControlError("target qualification replay verifier is invalid")
    if installed and (
        metadata.st_uid != CLASSIFIER_TRUSTED_UID
        or metadata.st_gid != CLASSIFIER_TRUSTED_GID
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ControlError("target qualification replay verifier is invalid")
    loader = SourceFileLoader("secpal_target_qualification_replay", os.fspath(verifier_path))
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise ControlError("target qualification replay verifier cannot be loaded")
    verifier = importlib.util.module_from_spec(specification)
    write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(verifier)
    except Exception as error:
        raise ControlError("target qualification replay verifier cannot be loaded") from error
    finally:
        sys.dont_write_bytecode = write_bytecode
    if not callable(getattr(verifier, TARGET_REPLAY_VERIFIER_SYMBOL, None)):
        raise ControlError("target qualification replay verifier cannot be loaded")
    return verifier


def validate_target_qualification_failure(
    path: Path,
    target_sha: str,
    control_sha: str,
    run_id: str,
    run_attempt: str,
) -> None:
    if SHA.fullmatch(target_sha) is None or SHA.fullmatch(control_sha) is None:
        raise ControlError("target and control SHAs must be exact lowercase commits")
    if RUN_ID.fullmatch(run_id) is None or RUN_ATTEMPT.fullmatch(run_attempt) is None:
        raise ControlError("qualification run identity is outside the closed format")
    document = validate_evidence("target-qualification-failure", path)
    expected = {
        "target_sha": target_sha,
        "trusted_control_sha": control_sha,
        "qualification_run_id": run_id,
        "qualification_run_attempt": run_attempt,
    }
    if any(document[key] != value for key, value in expected.items()):
        raise ControlError("target qualification failure is not bound to this exact run")
    classifier = None
    if (
        document["operation"] == "qualification-harness"
        and document["reason"] == "representation-invalid"
    ):
        classifier = load_target_failure_classifier()
        replay_required = (
            document["target_sha"] == classifier.EXPECTED_TARGET_SHA
            and document["harness_sha256"] == classifier.EXPECTED_HARNESS_SHA256
            and document["trusted_control_sha"]
            != classifier.LEGACY_REPLAY_OPTIONAL_CONTROL_SHA
        )
        if replay_required and document["schema_version"] != 2:
            raise ControlError(
                "current representation failure lacks its replay witness"
            )
    if document["schema_version"] == 2:
        if classifier is None:
            classifier = load_target_failure_classifier()
        verifier = load_target_replay_verifier()
        try:
            getattr(verifier, TARGET_REPLAY_VERIFIER_SYMBOL)(document, classifier)
        except (AttributeError, ValueError) as error:
            raise ControlError(
                "target qualification replay witness contradicts its inputs"
            ) from error
    avc_diagnostic = document.get("avc_correlation_diagnostic")
    if document["schema_version"] in {3, 4} and avc_diagnostic is None:
        raise ControlError("target AVC-correlation failure lacks its diagnostic")
    if avc_diagnostic is not None:
        if (
            document["schema_version"] not in {3, 4}
            or avc_diagnostic.get("schema_version")
            != document["schema_version"] - 2
            or document["operation"] != "qualify-avc-correlation"
            or document["reason"] != "command-failed"
            or document["exit_status"] != 3
            or not isinstance(avc_diagnostic, dict)
        ):
            raise ControlError("target AVC-correlation diagnostic is inappropriate")
        binding_names = (
            "target_sha",
            "trusted_control_sha",
            "qualification_run_id",
            "qualification_run_attempt",
            "harness_sha256",
        )
        if any(
            avc_diagnostic.get(name) != document[name] for name in binding_names
        ):
            raise ControlError("target AVC-correlation diagnostic binding disagrees")
        projection = avc_diagnostic.get("projection")
        try:
            projection_bytes = (
                json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
        except (TypeError, UnicodeEncodeError, ValueError) as error:
            raise ControlError(
                "target AVC-correlation projection is not closed JSON"
            ) from error
        if (
            len(projection_bytes) != avc_diagnostic.get("projection_bytes")
            or hashlib.sha256(projection_bytes).hexdigest()
            != avc_diagnostic.get("projection_sha256")
            or len(projection_bytes) != document["diagnostic_input_bytes"]
            or hashlib.sha256(projection_bytes).hexdigest()
            != document["diagnostic_input_sha256"]
        ):
            raise ControlError("target AVC-correlation diagnostic hash closure fails")
        contract = load_selinux_isolation_contract()
        try:
            contract.validate_avc_correlation_diagnostic(projection)
        except contract.IsolationError as error:
            raise ControlError(
                "target AVC-correlation diagnostic contradicts its facts"
            ) from error
        if projection.get("correlation_outcome") == "admitted":
            raise ControlError(
                "target AVC-correlation failure contradicts an admitted candidate"
            )
    adjacency = document.get("daemon_reload_adjacency")
    if adjacency is not None:
        classifier = load_target_failure_classifier()
        try:
            getattr(classifier, TARGET_FAILURE_CLASSIFIER_SYMBOL)(adjacency)
        except (AttributeError, ValueError) as error:
            raise ControlError(
                "target qualification daemon-reload adjacency contradicts its facts"
            ) from error
    start_diagnostic = document.get("quadlet_start_diagnostic")
    start_operations = {
        "qualify-quadlet-start",
        "qualify-quadlet-start-runuser",
        "qualify-quadlet-start-env",
        "qualify-quadlet-start-systemctl",
        "qualify-quadlet-start-service-job",
    }
    current_start_diagnostic = (
        document["operation"] in start_operations - {"qualify-quadlet-start"}
        or (
            document["operation"] == "qualify-quadlet-start"
            and document["reason"] == "diagnostic-unavailable"
        )
    )
    if start_diagnostic is None and current_start_diagnostic:
        raise ControlError("target qualification Quadlet start diagnostic is missing")
    if start_diagnostic is not None:
        if document["operation"] not in start_operations:
            raise ControlError("target qualification start diagnostic is inappropriate")
        classifier = load_target_failure_classifier()
        try:
            getattr(classifier, TARGET_START_CLASSIFIER_SYMBOL)(
                start_diagnostic,
                document["operation"],
                document["reason"],
                document["exit_status"],
            )
        except (AttributeError, ValueError) as error:
            raise ControlError(
                "target qualification Quadlet start diagnostic contradicts its facts"
            ) from error
    active_diagnostic = document.get("quadlet_active_state_diagnostic")
    active_operations = {
        "qualify-quadlet-active-state",
        "qualify-quadlet-active-state-runuser",
        "qualify-quadlet-active-state-env",
        "qualify-quadlet-active-state-systemctl",
    }
    current_active_diagnostic = (
        document["operation"]
        in active_operations - {"qualify-quadlet-active-state"}
        or (
            document["operation"] == "qualify-quadlet-active-state"
            and document["reason"] == "diagnostic-unavailable"
        )
    )
    if active_diagnostic is None and current_active_diagnostic:
        raise ControlError("target qualification Quadlet active-state diagnostic is missing")
    if active_diagnostic is not None:
        if document["operation"] not in active_operations:
            raise ControlError(
                "target qualification active-state diagnostic is inappropriate"
            )
        classifier = load_target_failure_classifier()
        try:
            getattr(classifier, TARGET_ACTIVE_CLASSIFIER_SYMBOL)(
                active_diagnostic,
                document["operation"],
                document["reason"],
                document["exit_status"],
            )
        except (AttributeError, ValueError) as error:
            raise ControlError(
                "target qualification Quadlet active-state diagnostic contradicts its facts"
            ) from error
    primary_diagnostic = document.get("primary_workload_diagnostic")
    primary_operations = {
        "qualify-workload-primary",
        "qualify-workload-primary-runuser",
        "qualify-workload-primary-env",
        "qualify-workload-primary-podman",
        "qualify-workload-primary-podman-oci",
    }
    current_primary_diagnostic = (
        document["operation"] in primary_operations - {"qualify-workload-primary"}
        or (
            document["operation"] == "qualify-workload-primary"
            and document["reason"] == "diagnostic-unavailable"
        )
    )
    if primary_diagnostic is None and current_primary_diagnostic:
        raise ControlError("target qualification primary-workload diagnostic is missing")
    if primary_diagnostic is not None:
        if document["operation"] not in primary_operations:
            raise ControlError(
                "target qualification primary-workload diagnostic is inappropriate"
            )
        classifier = load_target_failure_classifier()
        try:
            getattr(classifier, TARGET_PRIMARY_CLASSIFIER_SYMBOL)(
                primary_diagnostic,
                document["operation"],
                document["reason"],
                document["exit_status"],
            )
        except (AttributeError, ValueError) as error:
            raise ControlError(
                "target qualification primary-workload diagnostic contradicts its facts"
            ) from error


def validate_preparation_failure_semantics(document: dict[str, Any]) -> None:
    phase = document.get("phase")
    if phase == "evidence-collection":
        diagnostic = document.get("collection_diagnostic")
        if not isinstance(diagnostic, dict):
            raise ControlError("collection failure diagnostic must be an object")
        validate_collection_diagnostic_semantics(diagnostic)
        return
    if phase == "fixture":
        diagnostic = document.get("fixture_diagnostic")
        if not isinstance(diagnostic, dict):
            raise ControlError("fixture failure diagnostic must be an object")
        operation = diagnostic.get("operation")
        reason = diagnostic.get("reason")
        if (
            operation not in FIXTURE_DIAGNOSTIC_REASONS
            or reason not in FIXTURE_DIAGNOSTIC_REASONS[operation]
        ):
            raise ControlError(
                "fixture failure diagnostic contradicts the closed operation contract"
            )
        return
    if phase != "repositories":
        return
    profile_repositories = canonical_profile().get("repositories")
    if not isinstance(profile_repositories, dict):
        raise ControlError("reviewed repository profile is malformed")
    final = profile_repositories.get("final_enabled_repositories")
    provider = profile_repositories.get("pre_admission_provider_repositories")
    if not isinstance(final, list) or not isinstance(provider, list):
        raise ControlError("reviewed repository profile is malformed")
    diagnostic = document.get("repository_diagnostic")
    if diagnostic is not None:
        if not isinstance(diagnostic, dict):
            raise ControlError("repository failure diagnostic must be an object")
        operation = diagnostic.get("operation")
        reason = diagnostic.get("reason")
        if operation not in REPOSITORY_DIAGNOSTIC_REASONS or reason not in REPOSITORY_DIAGNOSTIC_REASONS[operation]:
            raise ControlError("repository failure diagnostic contradicts the closed operation contract")
        repository_id = diagnostic.get("repository_id")
        repository_id_domain = REPOSITORY_ID_OPERATION_DOMAINS.get(operation)
        if repository_id_domain is not None:
            expected_ids = final if repository_id_domain == "final" else provider
            if repository_id not in expected_ids:
                raise ControlError("repository failure diagnostic names an unreviewed repository")
        elif repository_id is not None:
            raise ControlError("repository failure diagnostic includes an inappropriate repository ID")
    if "repositories" not in document:
        return
    observation = document["repositories"]
    if not isinstance(observation, dict):
        raise ControlError("repository failure observation must be an object")
    stage = observation.get("stage")
    enabled = observation.get("enabled")
    supplied_unexpected = observation.get("unexpected_enabled")
    supplied_missing = observation.get("missing_required")
    if not isinstance(stage, str) or not all(
        isinstance(value, list)
        for value in (enabled, supplied_unexpected, supplied_missing)
    ):
        raise ControlError("repository failure observation is malformed")
    allowed = set(final)
    if stage == "pre-admission":
        allowed.update(provider)
    elif stage != "final-admission":
        raise ControlError("repository failure stage is outside the closed contract")
    if enabled != sorted(set(enabled)):
        raise ControlError("enabled repository IDs are not canonical")
    expected_unexpected = sorted(set(enabled) - allowed)
    expected_missing = sorted(set(final) - set(enabled))
    if supplied_unexpected != expected_unexpected or supplied_missing != expected_missing:
        raise ControlError("repository failure classification contradicts trusted profile")


def validate_collection_diagnostic(path: Path) -> None:
    diagnostic = load_object(path)
    document = {
        "schema_version": 1,
        "target_sha": "a" * 40,
        "trusted_control_sha": "b" * 40,
        "run_id": "1",
        "run_attempt": "1",
        "phase": "evidence-collection",
        "exit_status": 1,
        "guest": {"id": "rocky", "version_id": "10.2", "uname_machine": "aarch64"},
        "collection_diagnostic": diagnostic,
    }
    schema = load_object(SCHEMAS["preparation-failure"])
    errors = list(Draft202012Validator(schema).iter_errors(document))
    if errors:
        raise ControlError("collection diagnostic is outside the closed failure schema")
    validate_collection_diagnostic_semantics(diagnostic)


def validate_collection_diagnostic_semantics(diagnostic: dict[str, Any]) -> None:
    operation = diagnostic.get("operation")
    reason = diagnostic.get("reason")
    subject = diagnostic.get("subject")
    schema = load_object(SCHEMAS["preparation-failure"])
    reason_groups = schema["properties"]["collection_diagnostic"].get(
        "x-secpal-operation-reason-groups"
    )
    if not isinstance(reason_groups, list):
        raise ControlError("collection diagnostic reason contract is unavailable")
    matching_groups = [
        group
        for group in reason_groups
        if isinstance(group, dict)
        and isinstance(group.get("operations"), list)
        and operation in group["operations"]
    ]
    if len(matching_groups) != 1 or reason not in matching_groups[0].get(
        "reasons", []
    ):
        raise ControlError("collection diagnostic reason contradicts its operation")
    if operation in PACKAGE_COLLECTION_OPERATIONS:
        preparation_schema = load_object(SCHEMAS["preparation"])
        package_branches = preparation_schema["properties"]["packages"]["allOf"]
        allowed = {
            branch["contains"]["properties"]["name"]["const"]
            for branch in package_branches
        }
        if subject not in allowed:
            raise ControlError("package diagnostic does not name a reviewed package")
    elif operation in UNIT_COLLECTION_OPERATIONS:
        if subject not in {
            "dnf-automatic.timer",
            "dnf-automatic-install.timer",
            "dnf-automatic-download.timer",
            "dnf-automatic-notifyonly.timer",
            "podman.socket",
        }:
            raise ControlError("unit diagnostic does not name a reviewed unit")
    elif subject is not None:
        raise ControlError("collection diagnostic has an inappropriate subject")


def discover_image(profile_name: str, control_sha: str, output: Path) -> None:
    if SHA.fullmatch(control_sha) is None:
        raise ControlError("trusted control SHA must be a lowercase full commit SHA")
    validate_profile(profile_name)
    profile = canonical_profile(profile_name)
    profile_architecture = profile["architecture"]
    family = profile["image"]["discovery_family"]
    token = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "")
    if not token or any(character.isspace() for character in token):
        raise ControlError("bounded WIF access token is required for discovery")
    request = urllib.request.Request(
        f"{DISCOVERY_ROOT}{family}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "SecPal-Rocky-Image-Discovery/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read(1_000_001)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        raise ControlError("official Rocky image discovery failed") from error
    if len(payload) > 1_000_000:
        raise ControlError("image discovery response exceeded the size bound")
    try:
        image = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("image discovery returned invalid JSON") from error
    if not isinstance(image, dict):
        raise ControlError("image discovery response must be an object")
    name = image.get("name")
    self_link = image.get("selfLink")
    image_architecture = image.get("architecture")
    creation = image.get("creationTimestamp")
    expected_name = re.compile(
        r"^rocky-linux-10-[a-z0-9-]*arm64[a-z0-9-]*$"
        if profile_architecture == "aarch64"
        else r"^rocky-linux-10-v[0-9]{8}$"
    )
    if (
        not isinstance(name, str)
        or expected_name.fullmatch(name) is None
        or self_link != f"{IMAGE_PREFIX}{name}"
        or image_architecture != PROVIDER_ARCHITECTURES[profile_architecture]
        or not isinstance(creation, str)
        or image.get("status") != "READY"
        or image.get("deprecated") is not None
    ):
        raise ControlError("resolved image is outside the reviewed official profile shape")
    evidence = {
        "schema_version": 1,
        "trusted_control_sha": control_sha,
        "provider": "google",
        "profile": profile_name,
        "image_project": profile["image"]["project"],
        "discovery_family": family,
        "exact_image_name": name,
        "exact_image_self_link": self_link,
        "architecture": image_architecture,
        "image_creation_timestamp": creation,
        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
    }
    write_object(output, evidence)
    validate_evidence("discovery", output)


def validate_continuation(
    path: Path,
    profile_name: str,
    control_sha: str,
    target_sha: str,
    source_run_id: str,
    source_run_attempt: str,
    now: int,
    allow_expired: bool,
    allow_control_mismatch: bool,
) -> None:
    document = validate_evidence("continuation", path)
    expected = {
        "profile": profile_name,
        "target_sha": target_sha,
        "run_id": source_run_id,
        "run_attempt": source_run_attempt,
        "state_artifact": f"rocky-cloud-state-{source_run_id}-{source_run_attempt}",
    }
    if not allow_control_mismatch:
        expected["trusted_control_sha"] = control_sha
    if any(document.get(key) != value for key, value in expected.items()):
        raise ControlError("continuation does not exactly match this trusted resume")
    expires_at = document.get("expires_at")
    if allow_control_mismatch and not allow_expired:
        raise ControlError("control mismatch is allowed only for exact destroy")
    if type(expires_at) is not int or (
        now + 3600 >= expires_at and not allow_expired
    ):
        raise ControlError("continuation has expired")


def create_continuation(options: argparse.Namespace) -> None:
    validate_profile(options.profile)
    profile = canonical_profile(options.profile)
    fields = (
        options.control_sha,
        options.target_sha,
        options.run_id,
        options.run_attempt,
        options.instance_id,
    )
    patterns = (SHA, SHA, RUN_ID, RUN_ATTEMPT, re.compile(r"^[1-9][0-9]{0,29}$"))
    if any(pattern.fullmatch(value) is None for pattern, value in zip(patterns, fields, strict=True)):
        raise ControlError("continuation input is outside the closed format")
    if not options.instance_name == f"sprk-{options.run_id}-{options.run_attempt}-instance":
        raise ControlError("instance name is not derived from exact run ownership")
    if not image_matches_profile(profile, options.image):
        raise ControlError("continuation image is not an exact official Rocky identity")
    if (
        options.created_at < 1_600_000_000
        or options.expires_at <= options.created_at
        or options.expires_at - options.created_at > 10800
    ):
        raise ControlError("continuation TTL is outside the three-hour bound")
    document = {
        "schema_version": 1,
        "repository": "SecPal/deployment",
        "trusted_control_sha": options.control_sha,
        "target_sha": options.target_sha,
        "provider": "google",
        "profile": options.profile,
        "exact_image_self_link": options.image,
        "instance_id": options.instance_id,
        "instance_name": options.instance_name,
        "zone": profile["zone"],
        "run_id": options.run_id,
        "run_attempt": options.run_attempt,
        "created_at": options.created_at,
        "expires_at": options.expires_at,
        "state_artifact": f"rocky-cloud-state-{options.run_id}-{options.run_attempt}",
        "ssh_authority": "rotate-per-operation-before-identity-detach",
    }
    write_object(options.output, document)
    validate_evidence("continuation", options.output)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    profile = subparsers.add_parser("validate-profile")
    profile.add_argument("profile", choices=tuple(PROFILE_PATHS))
    evidence = subparsers.add_parser("validate-evidence")
    evidence.add_argument("kind", choices=sorted(SCHEMAS))
    evidence.add_argument("path", type=Path)
    native_qualification = subparsers.add_parser("validate-native-qualification")
    native_qualification.add_argument("path", type=Path)
    native_qualification.add_argument("--stdout", required=True, type=Path)
    native_qualification.add_argument(
        "--native-observation", required=True, type=Path
    )
    native_qualification.add_argument("--target-sha", required=True)
    native_qualification.add_argument("--control-sha", required=True)
    native_qualification.add_argument("--run-id", required=True)
    native_qualification.add_argument("--run-attempt", required=True)
    native_observation = subparsers.add_parser("validate-native-observation")
    native_observation.add_argument("path", type=Path)
    native_observation.add_argument("--target-sha", required=True)
    native_observation.add_argument("--control-sha", required=True)
    native_observation.add_argument("--run-id", required=True)
    native_observation.add_argument("--run-attempt", required=True)
    target_source_failure = subparsers.add_parser("validate-target-source-failure")
    target_source_failure.add_argument("path", type=Path)
    target_source_failure.add_argument("--target-sha", required=True)
    target_source_failure.add_argument("--control-sha", required=True)
    target_source_failure.add_argument("--run-id", required=True)
    target_source_failure.add_argument("--run-attempt", required=True)
    target_qualification_failure = subparsers.add_parser(
        "validate-target-qualification-failure"
    )
    target_qualification_failure.add_argument("path", type=Path)
    target_qualification_failure.add_argument("--target-sha", required=True)
    target_qualification_failure.add_argument("--control-sha", required=True)
    target_qualification_failure.add_argument("--run-id", required=True)
    target_qualification_failure.add_argument("--run-attempt", required=True)
    collection = subparsers.add_parser("validate-collection-diagnostic")
    collection.add_argument("path", type=Path)
    access_request = subparsers.add_parser("validate-access-request")
    access_request.add_argument("path", type=Path)
    access_request.add_argument("--target-sha", required=True)
    access_request.add_argument("--run-id", required=True)
    access_request.add_argument("--run-attempt", required=True)
    discovery = subparsers.add_parser("discover-image")
    discovery.add_argument("--profile", required=True, choices=tuple(PROFILE_PATHS))
    discovery.add_argument("--control-sha", required=True)
    discovery.add_argument("--output", required=True, type=Path)
    continuation = subparsers.add_parser("validate-continuation")
    continuation.add_argument("path", type=Path)
    continuation.add_argument("--profile", required=True, choices=tuple(PROFILE_PATHS))
    continuation.add_argument("--control-sha", required=True)
    continuation.add_argument("--target-sha", required=True)
    continuation.add_argument("--source-run-id", required=True)
    continuation.add_argument("--source-run-attempt", required=True)
    continuation.add_argument("--now", required=True, type=int)
    continuation.add_argument("--allow-expired-for-destroy", action="store_true")
    continuation.add_argument(
        "--allow-control-sha-mismatch-for-destroy", action="store_true"
    )
    create = subparsers.add_parser("create-continuation")
    create.add_argument("--profile", required=True, choices=tuple(PROFILE_PATHS))
    create.add_argument("--control-sha", required=True)
    create.add_argument("--target-sha", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--run-attempt", required=True)
    create.add_argument("--image", required=True)
    create.add_argument("--instance-id", required=True)
    create.add_argument("--instance-name", required=True)
    create.add_argument("--created-at", required=True, type=int)
    create.add_argument("--expires-at", required=True, type=int)
    create.add_argument("--output", required=True, type=Path)
    return result


def main(arguments: list[str]) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "validate-profile":
            validate_profile(options.profile)
        elif options.command == "validate-evidence":
            validate_evidence(options.kind, options.path)
        elif options.command == "validate-native-qualification":
            validate_native_qualification(
                options.path,
                options.stdout,
                options.native_observation,
                options.target_sha,
                options.control_sha,
                options.run_id,
                options.run_attempt,
            )
        elif options.command == "validate-native-observation":
            validate_native_observation(
                options.path,
                options.target_sha,
                options.control_sha,
                options.run_id,
                options.run_attempt,
            )
        elif options.command == "validate-target-source-failure":
            validate_target_source_failure(
                options.path,
                options.target_sha,
                options.control_sha,
                options.run_id,
                options.run_attempt,
            )
        elif options.command == "validate-target-qualification-failure":
            validate_target_qualification_failure(
                options.path,
                options.target_sha,
                options.control_sha,
                options.run_id,
                options.run_attempt,
            )
        elif options.command == "validate-collection-diagnostic":
            validate_collection_diagnostic(options.path)
        elif options.command == "validate-access-request":
            validate_access_request(
                options.path,
                options.target_sha,
                options.run_id,
                options.run_attempt,
            )
        elif options.command == "discover-image":
            discover_image(options.profile, options.control_sha, options.output)
        elif options.command == "validate-continuation":
            validate_continuation(
                options.path,
                options.profile,
                options.control_sha,
                options.target_sha,
                options.source_run_id,
                options.source_run_attempt,
                options.now,
                options.allow_expired_for_destroy,
                options.allow_control_sha_mismatch_for_destroy,
            )
        elif options.command == "create-continuation":
            create_continuation(options)
    except (ControlError, OSError, ValueError) as error:
        print(f"ERROR: Rocky cloud control rejected input: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
