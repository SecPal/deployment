#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Positive, negative-mutation, and synthetic host-fact tests for D.1."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate-production-contract.py"
SCHEMA = ROOT / "schemas/production-inventory.schema.json"
HOST_FACTS_SCHEMA = ROOT / "schemas/production-host-facts.schema.json"
EXAMPLE = ROOT / "config/production/inventory.example.yaml"
INVENTORY_FIXTURES = ROOT / "tests/fixtures/production-inventory"
HOST_FIXTURES = ROOT / "tests/fixtures/production-host"


def load_yaml(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(f"fixture must be a mapping: {path}")
    return loaded


def write_yaml(path: Path, document: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def run_validator(inventory: Path, host_facts: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--inventory",
            str(inventory),
            "--host-facts",
            str(host_facts),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def set_nested(document: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    target: dict[str, Any] = document
    for segment in path[:-1]:
        child = target[segment]
        if not isinstance(child, dict):
            raise AssertionError(f"mutation path is not a mapping: {path}")
        target = child
    target[path[-1]] = value


def remove_nested(document: dict[str, Any], path: tuple[str, ...]) -> None:
    target: dict[str, Any] = document
    for segment in path[:-1]:
        child = target[segment]
        if not isinstance(child, dict):
            raise AssertionError(f"mutation path is not a mapping: {path}")
        target = child
    del target[path[-1]]


def assert_schema_objects_are_closed(value: Any, path: tuple[str, ...] = ()) -> int:
    if isinstance(value, dict):
        count = 0
        if value.get("type") == "object":
            if value.get("additionalProperties") is not False:
                location = ".".join(path) or "schema root"
                raise AssertionError(f"schema object is not fail-closed: {location}")
            count += 1
        return count + sum(
            assert_schema_objects_are_closed(child, (*path, str(key)))
            for key, child in value.items()
        )
    if isinstance(value, list):
        return sum(
            assert_schema_objects_are_closed(child, (*path, str(index)))
            for index, child in enumerate(value)
        )
    return 0


def main() -> int:
    for required in (VALIDATOR, SCHEMA, HOST_FACTS_SCHEMA, EXAMPLE):
        if not required.is_file():
            raise AssertionError(f"required D.1 artifact is missing: {required.relative_to(ROOT)}")

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    closed_object_count = assert_schema_objects_are_closed(schema)
    host_facts_schema = json.loads(HOST_FACTS_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(host_facts_schema)
    closed_object_count += assert_schema_objects_are_closed(host_facts_schema)
    schema_validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )

    positive_pairs = (
        (
            INVENTORY_FIXTURES / "valid-amd64.yaml",
            HOST_FIXTURES / "valid-amd64.yaml",
        ),
        (
            INVENTORY_FIXTURES / "valid-arm64.yaml",
            HOST_FIXTURES / "valid-arm64.yaml",
        ),
    )
    for inventory_path, host_path in positive_pairs:
        schema_validator.validate(load_yaml(inventory_path))
        result = run_validator(inventory_path, host_path)
        if result.returncode != 0:
            raise AssertionError(
                f"positive contract failed for {inventory_path.name}: {result.stderr}"
            )

    example = load_yaml(EXAMPLE)
    schema_validator.validate(example)

    synthetic_github_token = "gh" + "p_" + ("0" * 36)
    synthetic_private_key = "-----BEGIN OPENSSH " + "PRIVATE KEY----- synthetic"

    mutations: list[
        tuple[str, Callable[[dict[str, Any]], None], str | None]
    ] = [
        ("unknown-field", lambda d: d.update({"unexpected": True}), None),
        ("missing-schema-version", lambda d: d.pop("schema_version"), None),
        ("future-schema-version", lambda d: d.update({"schema_version": 2}), None),
        (
            "relative-postgresql-path",
            lambda d: set_nested(d, ("paths", "postgresql_data", "path"), "data/postgres"),
            None,
        ),
        (
            "relative-private-storage-path",
            lambda d: set_nested(
                d, ("paths", "private_application_storage", "path"), "data/private"
            ),
            None,
        ),
        (
            "duplicate-persistent-path",
            lambda d: set_nested(
                d,
                ("paths", "private_application_storage", "path"),
                d["paths"]["postgresql_data"]["path"],
            ),
            None,
        ),
        (
            "service-home-conflicts-with-postgresql",
            lambda d: set_nested(
                d,
                ("service_account", "home"),
                d["paths"]["postgresql_data"]["path"],
            ),
            None,
        ),
        (
            "world-writable-secret-mode",
            lambda d: set_nested(d, ("paths", "runtime_secrets", "mode"), "0777"),
            None,
        ),
        (
            "embedded-password-field",
            lambda d: d["backup"].update({"password": "synthetic-password-marker"}),
            "synthetic-password-marker",
        ),
        (
            "embedded-github-token",
            lambda d: set_nested(
                d,
                ("backup", "credential_reference"),
                synthetic_github_token,
            ),
            synthetic_github_token,
        ),
        (
            "embedded-ssh-private-key",
            lambda d: set_nested(
                d,
                ("backup", "credential_reference"),
                synthetic_private_key,
            ),
            "BEGIN OPENSSH " + "PRIVATE KEY",
        ),
        ("registry-override", lambda d: d.update({"api_registry": "example.invalid"}), None),
        (
            "frontend-registry-override",
            lambda d: d.update({"frontend_registry": "example.invalid"}),
            None,
        ),
        ("repository-override", lambda d: d.update({"api_repository": "other/api"}), None),
        (
            "frontend-repository-override",
            lambda d: d.update({"frontend_repository": "other/frontend"}),
            None,
        ),
        ("api-image-override", lambda d: d.update({"api_image": "example/api:latest"}), None),
        (
            "frontend-image-override",
            lambda d: d.update({"frontend_image": "example/frontend:latest"}),
            None,
        ),
        ("api-digest-override", lambda d: d.update({"api_digest": "sha256:" + "0" * 64}), None),
        (
            "frontend-digest-override",
            lambda d: d.update({"frontend_digest": "sha256:" + "0" * 64}),
            None,
        ),
        ("latest-tag", lambda d: d.update({"image_tag": "latest"}), None),
        ("registry-fallback", lambda d: d.update({"registry_fallback": "docker.io"}), None),
        (
            "same-origins",
            lambda d: set_nested(d, ("origins", "api"), d["origins"]["frontend"]),
            None,
        ),
        (
            "localhost-frontend-origin",
            lambda d: set_nested(d, ("origins", "frontend"), "https://localhost"),
            None,
        ),
        (
            "loopback-api-origin",
            lambda d: set_nested(d, ("origins", "api"), "https://127.0.0.1"),
            None,
        ),
        (
            "frontend-origin-with-path",
            lambda d: set_nested(d, ("origins", "frontend"), "https://app.example.invalid/ui"),
            None,
        ),
        (
            "api-origin-with-query",
            lambda d: set_nested(d, ("origins", "api"), "https://api.example.invalid?x=1"),
            None,
        ),
        (
            "frontend-origin-with-userinfo",
            lambda d: set_nested(
                d, ("origins", "frontend"), "https://operator@app.example.invalid"
            ),
            None,
        ),
        (
            "api-origin-ip-literal",
            lambda d: set_nested(d, ("origins", "api"), "https://192.0.2.10"),
            None,
        ),
        (
            "frontend-origin-with-http",
            lambda d: set_nested(d, ("origins", "frontend"), "http://app.example.invalid"),
            None,
        ),
        (
            "hostname-collides-with-frontend-origin",
            lambda d: set_nested(d, ("host", "hostname"), "app.example.invalid"),
            None,
        ),
        (
            "loopback-public-address",
            lambda d: set_nested(d, ("host", "public_address"), "127.0.0.1"),
            None,
        ),
        (
            "loopback-private-address",
            lambda d: set_nested(d, ("host", "private_addresses"), ["127.0.0.1"]),
            None,
        ),
        (
            "unsupported-architecture",
            lambda d: set_nested(d, ("host", "architecture"), "riscv64"),
            None,
        ),
        ("unsupported-topology", lambda d: d.update({"topology": "multi-host"}), None),
        (
            "invalid-uid",
            lambda d: set_nested(d, ("service_account", "uid"), -1),
            None,
        ),
        (
            "invalid-gid",
            lambda d: set_nested(d, ("service_account", "gid"), 70000),
            None,
        ),
        (
            "reserved-runtime-uid",
            lambda d: set_nested(d, ("service_account", "uid"), 10001),
            None,
        ),
        (
            "invalid-filesystem-mode",
            lambda d: set_nested(d, ("paths", "logs", "mode"), "0890"),
            None,
        ),
        (
            "empty-hostname",
            lambda d: set_nested(d, ("host", "hostname"), ""),
            None,
        ),
        (
            "clock-sync-disabled",
            lambda d: set_nested(d, ("host", "require_clock_synchronized"), False),
            None,
        ),
        (
            "image-verification-disabled",
            lambda d: set_nested(d, ("features", "image_verification"), False),
            None,
        ),
        (
            "contradictory-opentimestamps-feature",
            lambda d: set_nested(d, ("features", "bitcoin_quorum"), True),
            None,
        ),
        (
            "mail-feature-before-runtime-contract",
            lambda d: set_nested(d, ("features", "mail_delivery"), True),
            None,
        ),
        (
            "opentimestamps-features-before-runtime-contract",
            lambda d: d["features"].update(opentimestamps=True, bitcoin_quorum=True),
            None,
        ),
        (
            "address-import-feature-before-runtime-contract",
            lambda d: set_nested(d, ("features", "address_data_imports"), True),
            None,
        ),
        (
            "android-push-feature-before-runtime-contract",
            lambda d: set_nested(d, ("features", "android_push"), True),
            None,
        ),
        (
            "web-push-feature-before-runtime-contract",
            lambda d: set_nested(d, ("features", "web_push"), True),
            None,
        ),
        (
            "object-storage-feature-before-runtime-contract",
            lambda d: (
                set_nested(d, ("features", "object_storage"), True),
                set_nested(d, ("backup", "target_type"), "object-storage"),
            ),
            None,
        ),
        (
            "object-storage-feature-with-filesystem-target",
            lambda d: set_nested(d, ("features", "object_storage"), True),
            None,
        ),
        (
            "object-storage-target-with-disabled-feature",
            lambda d: set_nested(d, ("backup", "target_type"), "object-storage"),
            None,
        ),
        (
            "missing-required-paths",
            lambda d: remove_nested(d, ("paths",)),
            None,
        ),
        (
            "path-traversal",
            lambda d: set_nested(
                d, ("paths", "deployment_state", "path"), "/srv/secpal/../root"
            ),
            None,
        ),
        (
            "reconstructable-logs",
            lambda d: set_nested(d, ("paths", "logs", "lifecycle"), "reconstructable"),
            None,
        ),
        (
            "private-key-field",
            lambda d: d["features"].update({"private_key": "synthetic"}),
            "synthetic",
        ),
        (
            "token-field",
            lambda d: d["features"].update({"token": "synthetic"}),
            "synthetic",
        ),
        (
            "secret-field",
            lambda d: d["features"].update({"secret": "synthetic"}),
            "synthetic",
        ),
        (
            "ssh-key-field",
            lambda d: d["features"].update({"ssh_key": "synthetic"}),
            "synthetic",
        ),
        (
            "api-key-field",
            lambda d: d["features"].update({"api_key": "synthetic"}),
            "synthetic",
        ),
        (
            "github-token-field",
            lambda d: d["features"].update({"github_token": "synthetic"}),
            "synthetic",
        ),
        (
            "registry-password-field",
            lambda d: d["features"].update({"registry_password": "synthetic"}),
            "synthetic",
        ),
        (
            "app-key-field",
            lambda d: d["features"].update({"app_key": "synthetic"}),
            "synthetic",
        ),
        (
            "tenant-kek-field",
            lambda d: d["features"].update({"tenant_kek": "synthetic"}),
            "synthetic",
        ),
        (
            "conflicting-public-private-address",
            lambda d: set_nested(
                d,
                ("host", "private_addresses"),
                [d["host"]["public_address"]],
            ),
            None,
        ),
    ]

    negative_host_fixtures = (
        "invalid-architecture.yaml",
        "insufficient-disk.yaml",
        "clock-unsynchronized.yaml",
        "kernel-too-old.yaml",
        "malformed-kernel-release.yaml",
        "cgroup-v1.yaml",
        "unsupported-os.yaml",
        "docker-too-old.yaml",
        "compose-v1.yaml",
        "rootless-engine.yaml",
        "contradictory-filesystem.yaml",
        "malformed-architecture.yaml",
    )

    with tempfile.TemporaryDirectory(prefix="secpal-production-contract-") as directory:
        temp_root = Path(directory)
        valid_host = HOST_FIXTURES / "valid-amd64.yaml"
        valid_host_document = load_yaml(valid_host)
        for name, mutate, sensitive_marker in mutations:
            candidate = copy.deepcopy(example)
            mutate(candidate)
            inventory_path = temp_root / f"{name}.yaml"
            write_yaml(inventory_path, candidate)
            with inventory_path.open("a", encoding="utf-8") as stream:
                stream.write("# ignored decoy: schema_version=1 path=/srv/secpal/postgresql\n")
            result = run_validator(inventory_path, valid_host)
            if result.returncode == 0:
                raise AssertionError(f"controlled inventory mutation was accepted: {name}")
            combined_output = result.stdout + result.stderr
            if "Traceback" in combined_output or not result.stderr.startswith("ERROR: "):
                raise AssertionError(f"inventory failure was not deterministic: {name}")
            if sensitive_marker and sensitive_marker in combined_output:
                raise AssertionError(f"validator leaked a sensitive value for mutation: {name}")

        duplicate_version_path = temp_root / "duplicate-schema-version.yaml"
        duplicate_version_path.write_text(
            EXAMPLE.read_text(encoding="utf-8").replace(
                "schema_version: 1",
                "schema_version: 2\nschema_version: 1",
                1,
            ),
            encoding="utf-8",
        )
        duplicate_result = run_validator(duplicate_version_path, valid_host)
        if duplicate_result.returncode == 0:
            raise AssertionError("duplicate inventory mapping key was accepted")
        if "Traceback" in duplicate_result.stderr or not duplicate_result.stderr.startswith(
            "ERROR: "
        ):
            raise AssertionError("duplicate inventory key failure was not deterministic")

        nested_inventory = copy.deepcopy(example)
        nested_path = f'{nested_inventory["paths"]["postgresql_data"]["path"]}/private'
        set_nested(
            nested_inventory,
            ("paths", "private_application_storage", "path"),
            nested_path,
        )
        nested_inventory_path = temp_root / "nested-private-storage-path.yaml"
        write_yaml(nested_inventory_path, nested_inventory)
        nested_host = copy.deepcopy(valid_host_document)
        set_nested(
            nested_host,
            ("resources", "storage", "private_application_storage", "path"),
            nested_path,
        )
        nested_host_path = temp_root / "nested-private-storage-host.yaml"
        write_yaml(nested_host_path, nested_host)
        nested_result = run_validator(nested_inventory_path, nested_host_path)
        if nested_result.returncode == 0:
            raise AssertionError("nested persistent inventory path was accepted")
        if "Traceback" in nested_result.stderr or not nested_result.stderr.startswith("ERROR: "):
            raise AssertionError("nested persistent path failure was not deterministic")

        for fixture_name in negative_host_fixtures:
            mutation = load_yaml(HOST_FIXTURES / fixture_name)
            path = mutation.get("path")
            if not isinstance(path, list) or not all(
                isinstance(segment, str) for segment in path
            ):
                raise AssertionError(f"invalid host mutation path: {fixture_name}")
            candidate_host = copy.deepcopy(valid_host_document)
            set_nested(candidate_host, tuple(path), mutation.get("value"))
            host_path = temp_root / fixture_name
            write_yaml(host_path, candidate_host)
            result = run_validator(EXAMPLE, host_path)
            if result.returncode == 0:
                raise AssertionError(f"controlled host-fact mutation was accepted: {fixture_name}")
            if "Traceback" in result.stderr or not result.stderr.startswith("ERROR: "):
                raise AssertionError(
                    f"host-fact failure was not deterministic: {fixture_name}"
                )

    total_negative = len(mutations) + len(negative_host_fixtures) + 2
    print(
        "Production inventory contract passed "
        f"({closed_object_count} closed schema objects, 3 positive schema documents, "
        f"2 positive host pairs, {total_negative} negative cases)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
