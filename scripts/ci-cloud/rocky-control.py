#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Closed admission and discovery utility for the Rocky GCP control plane."""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "config/ci-cloud/gcp-rocky-10-2-arm64.json"
SCHEMAS = {
    "discovery": ROOT / "schemas/rocky-cloud-discovery-evidence.schema.json",
    "continuation": ROOT / "schemas/rocky-cloud-continuation.schema.json",
    "preparation": ROOT / "schemas/rocky-cloud-preparation-evidence.schema.json",
    "preparation-failure": ROOT
    / "schemas/rocky-cloud-preparation-failure-evidence.schema.json",
    "qualification": ROOT / "schemas/rocky-cloud-qualification-evidence.schema.json",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
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
IMAGE_NAME = re.compile(r"^rocky-linux-10-[a-z0-9-]{1,50}$")
IMAGE_PREFIX = (
    "https://www.googleapis.com/compute/v1/projects/rocky-linux-cloud/"
    "global/images/"
)
DISCOVERY_URL = (
    "https://compute.googleapis.com/compute/v1/projects/rocky-linux-cloud/"
    "global/images/family/rocky-linux-10-arm64"
)
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
        document = json.loads(payload)
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


def canonical_profile() -> dict[str, Any]:
    return load_object(PROFILE_PATH)


def validate_profile(path: Path) -> None:
    if load_object(path) != canonical_profile():
        raise ControlError("profile differs from the one reviewed Rocky contract")


def validate_evidence(kind: str, path: Path) -> dict[str, Any]:
    schema = load_object(SCHEMAS[kind])
    document = load_object(path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "<root>"
        raise ControlError(f"{kind} evidence rejected at {location}: {first.message}")
    if kind == "preparation-failure":
        validate_preparation_failure_semantics(document)
    return document


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


def discover_image(control_sha: str, output: Path) -> None:
    if SHA.fullmatch(control_sha) is None:
        raise ControlError("trusted control SHA must be a lowercase full commit SHA")
    token = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "")
    if not token or any(character.isspace() for character in token):
        raise ControlError("bounded WIF access token is required for discovery")
    request = urllib.request.Request(
        DISCOVERY_URL,
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
    architecture = image.get("architecture")
    creation = image.get("creationTimestamp")
    if (
        not isinstance(name, str)
        or IMAGE_NAME.fullmatch(name) is None
        or self_link != f"{IMAGE_PREFIX}{name}"
        or architecture != "ARM64"
        or not isinstance(creation, str)
        or image.get("status") != "READY"
        or image.get("deprecated") is not None
    ):
        raise ControlError("resolved image is outside the reviewed official ARM64 shape")
    evidence = {
        "schema_version": 1,
        "trusted_control_sha": control_sha,
        "provider": "google",
        "profile": "gcp-rocky-10-2-arm64",
        "image_project": "rocky-linux-cloud",
        "discovery_family": "rocky-linux-10-arm64",
        "exact_image_name": name,
        "exact_image_self_link": self_link,
        "architecture": architecture,
        "image_creation_timestamp": creation,
        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
    }
    write_object(output, evidence)
    validate_evidence("discovery", output)


def validate_continuation(
    path: Path,
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
    if not options.image.startswith(IMAGE_PREFIX) or IMAGE_NAME.fullmatch(
        options.image.removeprefix(IMAGE_PREFIX)
    ) is None:
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
        "profile": "gcp-rocky-10-2-arm64",
        "exact_image_self_link": options.image,
        "instance_id": options.instance_id,
        "instance_name": options.instance_name,
        "zone": "europe-west3-a",
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
    profile.add_argument("path", type=Path)
    evidence = subparsers.add_parser("validate-evidence")
    evidence.add_argument("kind", choices=sorted(SCHEMAS))
    evidence.add_argument("path", type=Path)
    collection = subparsers.add_parser("validate-collection-diagnostic")
    collection.add_argument("path", type=Path)
    access_request = subparsers.add_parser("validate-access-request")
    access_request.add_argument("path", type=Path)
    access_request.add_argument("--target-sha", required=True)
    access_request.add_argument("--run-id", required=True)
    access_request.add_argument("--run-attempt", required=True)
    discovery = subparsers.add_parser("discover-image")
    discovery.add_argument("--control-sha", required=True)
    discovery.add_argument("--output", required=True, type=Path)
    continuation = subparsers.add_parser("validate-continuation")
    continuation.add_argument("path", type=Path)
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
            validate_profile(options.path)
        elif options.command == "validate-evidence":
            validate_evidence(options.kind, options.path)
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
            discover_image(options.control_sha, options.output)
        elif options.command == "validate-continuation":
            validate_continuation(
                options.path,
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
