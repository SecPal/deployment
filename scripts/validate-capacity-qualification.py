#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Strict independent admission for provider-neutral SecPal capacity evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/capacity-qualification.schema.json"
PROBE_PATH = ROOT / "config/capacity-probes-v1.json"
MAX_JSON_BYTES = 262_144
HEADROOM_PERCENT = 30
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)


class QualificationError(ValueError):
    """A bounded capacity-qualification rejection."""


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError("JSON input contains a duplicate object key")
        result[key] = value
    return result


def load_bounded_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        with path.open("rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise QualificationError(f"{label} must be a regular file")
            if metadata.st_size > MAX_JSON_BYTES:
                raise QualificationError(f"{label} is too large")
            payload = stream.read(MAX_JSON_BYTES + 1)
    except OSError as error:
        raise QualificationError(f"cannot read {label}") from error
    if len(payload) > MAX_JSON_BYTES:
        raise QualificationError(f"{label} is too large")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise QualificationError(f"{label} is not strict UTF-8") from error
    try:
        document = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise QualificationError(f"{label} contains malformed JSON") from error
    if not isinstance(document, dict):
        raise QualificationError(f"{label} must be one JSON object")
    return document, payload


def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    try:
        schema, _ = load_bounded_json(path, "capacity qualification schema")
        jsonschema.Draft202012Validator.check_schema(schema)
    except (jsonschema.SchemaError, QualificationError) as error:
        raise QualificationError("capacity qualification schema is invalid") from error
    return schema


def exact_keys(value: object, expected: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise QualificationError(f"{path} has an invalid closed shape")
    return value


def positive_integer(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise QualificationError(f"{path} must be a positive integer")
    return value


def load_probe_contract(path: Path = PROBE_PATH) -> tuple[dict[str, Any], str, str]:
    manifest, _ = load_bounded_json(path, "capacity probe contract")
    exact_keys(manifest, {"schema_version", "workload", "storage"}, "probe contract")
    if manifest["schema_version"] != 1:
        raise QualificationError("capacity probe contract version is unsupported")
    workload = exact_keys(
        manifest["workload"],
        {
            "probe_id",
            "collector_authority",
            "target_result_authority",
            "iteration",
            "cpu",
            "memory",
            "storage_cycles_per_iteration",
        },
        "workload probe",
    )
    if (
        workload["probe_id"] != "secpal-capacity-workload-v1"
        or workload["collector_authority"] != "trusted-controller"
        or workload["target_result_authority"] != "non-authoritative"
    ):
        raise QualificationError("workload probe authority or identity is invalid")
    iteration = exact_keys(
        workload["iteration"],
        {
            "description",
            "minimum_duration_seconds",
            "deadline_seconds",
            "minimum_completed_iterations",
            "failed_iterations_allowed",
            "deadline_misses_allowed",
            "oom_events_allowed",
        },
        "workload iteration",
    )
    for key in ("minimum_duration_seconds", "deadline_seconds", "minimum_completed_iterations"):
        positive_integer(iteration[key], f"workload iteration {key}")
    if any(
        iteration[key] != 0
        for key in ("failed_iterations_allowed", "deadline_misses_allowed", "oom_events_allowed")
    ):
        raise QualificationError("workload probe must fail closed on failures")
    for resource in ("cpu", "memory"):
        definition = exact_keys(
            workload[resource],
            {
                "entitlement_observation" if resource == "cpu" else "usable_observation",
                "peak_observation",
                "headroom_reservation_percent",
                "reservation_observation",
            },
            f"workload {resource}",
        )
        if definition["headroom_reservation_percent"] != HEADROOM_PERCENT:
            raise QualificationError("probe headroom does not match admission contract")
    positive_integer(workload["storage_cycles_per_iteration"], "storage cycle count")

    storage = exact_keys(
        manifest["storage"],
        {"probe_id", "collector_authority", "cycle", "raw_performance_observations"},
        "storage probe",
    )
    if (
        storage["probe_id"] != "secpal-capacity-storage-v1"
        or storage["collector_authority"] != "trusted-controller"
    ):
        raise QualificationError("storage probe authority or identity is invalid")
    cycle = exact_keys(
        storage["cycle"],
        {
            "description",
            "deadline_seconds",
            "postgresql_synchronous_transactions",
            "postgresql_payload_bytes_per_transaction",
            "private_file_bytes",
            "minimum_cycles_per_workload_iteration",
        },
        "storage cycle",
    )
    for key in set(cycle) - {"description"}:
        positive_integer(cycle[key], f"storage cycle {key}")
    if (
        workload["storage_cycles_per_iteration"]
        != cycle["minimum_cycles_per_workload_iteration"]
    ):
        raise QualificationError("workload and storage probe cycle counts disagree")
    raw = exact_keys(
        storage["raw_performance_observations"],
        {"required", "named_performance_tier", "same_persistent_filesystem"},
        "storage raw observations",
    )
    if raw != {
        "required": True,
        "named_performance_tier": False,
        "same_persistent_filesystem": True,
    }:
        raise QualificationError("storage raw-observation semantics are invalid")
    canonical = lambda value: json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return manifest, hashlib.sha256(canonical(workload)).hexdigest(), hashlib.sha256(
        canonical(storage)
    ).hexdigest()


def parse_timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        raise QualificationError(f"{field} is not an exact RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError(f"{field} is not an exact RFC 3339 timestamp") from error
    if parsed.utcoffset() is None:
        raise QualificationError(f"{field} must include a UTC offset")
    return parsed


def validate_hash(value: str, pattern: re.Pattern[str], field: str) -> None:
    if pattern.fullmatch(value) is None:
        raise QualificationError(f"trusted expected {field} is malformed")


def schema_validate(schema: dict[str, Any], document: object, reference: str | None = None) -> None:
    validation_schema = schema
    if reference is not None:
        validation_schema = {
            "$schema": schema.get("$schema"),
            "$defs": schema.get("$defs"),
            "$ref": reference,
        }
    jsonschema.Draft202012Validator(
        validation_schema, format_checker=jsonschema.FormatChecker()
    ).validate(document)


def maximum_freshness(schema: dict[str, Any]) -> int:
    try:
        value = schema["$defs"]["qualification"]["properties"]["freshness_seconds"]["const"]
    except (KeyError, TypeError) as error:
        raise QualificationError(
            "capacity qualification schema freshness is unavailable"
        ) from error
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise QualificationError("capacity qualification schema freshness is invalid")
    return value


def require_equal(actual: object, expected: object, field: str) -> None:
    if actual != expected:
        raise QualificationError(f"{field} does not match trusted expected value")


def require_headroom(capacity: int, peak: int, resource: str) -> None:
    if peak * 100 > capacity * (100 - HEADROOM_PERCENT):
        raise QualificationError(f"{resource} operational headroom is below 30%")


def admit(
    evidence: dict[str, Any],
    source: dict[str, Any],
    source_payload: bytes,
    evaluation_time: datetime,
    schema: dict[str, Any],
    probes: dict[str, Any],
    workload_revision: str,
    storage_revision: str,
    expected_target_sha: str,
    expected_control_sha: str,
    expected_target_identity: str,
    expected_workload_revision: str,
    expected_storage_revision: str,
) -> None:
    schema_validate(schema, evidence)
    schema_validate(schema, source, "#/$defs/capacitySourceEvidence")
    qualification = evidence["qualification"]
    if qualification["result"] != "PASS":
        raise QualificationError(f"qualification result is {qualification['result']}, not PASS")

    require_equal(qualification["target_sha"], expected_target_sha, "target SHA")
    require_equal(qualification["trusted_control_sha"], expected_control_sha, "control SHA")
    require_equal(
        evidence["subject"]["target_identity_sha256"],
        expected_target_identity,
        "target identity",
    )
    require_equal(workload_revision, expected_workload_revision, "workload probe")
    require_equal(storage_revision, expected_storage_revision, "storage probe")
    require_equal(
        qualification["workload_probe_revision_sha256"], workload_revision, "workload probe"
    )
    require_equal(
        qualification["storage_probe_revision_sha256"], storage_revision, "storage probe"
    )
    source_digest = hashlib.sha256(source_payload).hexdigest()
    if qualification["source_evidence_sha256"] != source_digest:
        raise QualificationError("source evidence digest does not match supplied bytes")

    authority = source["authority"]
    for field, expected in (
        ("target_sha", expected_target_sha),
        ("trusted_control_sha", expected_control_sha),
        ("target_identity_sha256", expected_target_identity),
        ("workload_probe_revision_sha256", workload_revision),
        ("storage_probe_revision_sha256", storage_revision),
    ):
        require_equal(authority[field], expected, f"source {field}")
    for field in ("capability", "subject", "observations"):
        if source[field] != evidence[field]:
            raise QualificationError(f"{field} does not match trusted source evidence")

    observed_at = parse_timestamp(qualification["observed_at"], "observed_at")
    require_equal(authority["observed_at"], qualification["observed_at"], "source observed_at")
    valid_until = parse_timestamp(qualification["valid_until"], "valid_until")
    freshness = maximum_freshness(schema)
    if evaluation_time < observed_at:
        raise QualificationError("qualification evidence is from the future")
    if evaluation_time >= valid_until:
        raise QualificationError("qualification evidence is stale")
    if valid_until <= observed_at or valid_until - observed_at > timedelta(seconds=freshness):
        raise QualificationError("qualification freshness window is invalid")
    subject = evidence["subject"]
    if subject["kind"] == "provider-product":
        catalog_time = parse_timestamp(
            subject["provider_product"]["catalog_observed_at"], "catalog_observed_at"
        )
        if catalog_time > observed_at:
            raise QualificationError(
                "provider catalog observation is newer than qualification evidence"
            )
        if evaluation_time - catalog_time > timedelta(seconds=freshness):
            raise QualificationError("provider catalog evidence is stale at decision time")

    cleanup = qualification["cleanup"]
    require_equal(source["cleanup"], cleanup, "source cleanup")
    if cleanup["required"] and cleanup["status"] != "complete":
        raise QualificationError("required qualification cleanup is not complete")
    capability, observations = evidence["capability"], evidence["observations"]
    if capability["compute_isolation"] != observations["compute_isolation"]["classification"]:
        raise QualificationError("claimed compute isolation does not match effective observation")
    if capability["cpu_architecture"] != observations["cpu"]["architecture"]:
        raise QualificationError("claimed CPU architecture does not match effective observation")

    resources, workload = observations["resources"], observations["workload"]
    if resources["usable_cpu_millicores"] > resources["online_logical_cpus"] * 1000:
        raise QualificationError("usable CPU millicores exceed online logical CPUs")
    if resources["free_storage_bytes"] > resources["total_storage_bytes"]:
        raise QualificationError("free storage exceeds total storage")
    if resources["free_inodes"] > resources["total_inodes"]:
        raise QualificationError("free inodes exceeds total inodes")
    if resources["free_storage_bytes"] * 100 < resources["total_storage_bytes"] * 20:
        raise QualificationError("storage operational headroom is below 20%")
    if resources["free_inodes"] * 100 < resources["total_inodes"] * 20:
        raise QualificationError("inode operational headroom is below 20%")
    require_equal(workload["probe_revision_sha256"], workload_revision, "workload probe")
    performance = observations["storage"]["performance"]
    require_equal(performance["probe_revision_sha256"], storage_revision, "storage probe")

    collected_workload = source["collection"]["workload"]
    workload_contract = probes["workload"]["iteration"]
    for observation, collected in (
        ("duration_seconds", "controller_observed_duration_seconds"),
        ("completed_iterations", "controller_observed_completed_iterations"),
        ("failed_iterations", "controller_observed_failed_iterations"),
        ("deadline_misses", "controller_observed_deadline_misses"),
        ("oom_events", "controller_observed_oom_events"),
    ):
        require_equal(
            workload[observation],
            collected_workload[collected],
            f"workload {observation}",
        )
    if collected_workload["controller_observed_deadline_misses"] != 0:
        raise QualificationError("trusted workload observation contains a deadline miss")
    if (
        workload["duration_seconds"] < workload_contract["minimum_duration_seconds"]
        or collected_workload["maximum_iteration_duration_seconds"]
        > workload_contract["deadline_seconds"]
    ):
        raise QualificationError("trusted workload did not satisfy its reviewed duration")
    required_cpu_reservation = (
        resources["usable_cpu_millicores"] * HEADROOM_PERCENT + 99
    ) // 100
    if (
        collected_workload["cpu_reservation_requested_millicores"] < required_cpu_reservation
        or collected_workload["cpu_reservation_delivered_millicores"]
        < collected_workload["cpu_reservation_requested_millicores"]
        or collected_workload["cpu_reservation_observed_seconds"]
        < workload["duration_seconds"]
    ):
        raise QualificationError("trusted CPU reservation was not demonstrably delivered")
    if (
        workload["peak_cpu_millicores"]
        + collected_workload["cpu_reservation_delivered_millicores"]
        > resources["usable_cpu_millicores"]
    ):
        raise QualificationError("CPU operational headroom is below 30%")
    required_memory_reservation = (
        resources["usable_memory_bytes"] * HEADROOM_PERCENT + 99
    ) // 100
    if (
        collected_workload["memory_reservation_bytes"] < required_memory_reservation
        or collected_workload["memory_reservation_held_seconds"] < workload["duration_seconds"]
    ):
        raise QualificationError("trusted memory reservation was not held for the workload")
    if (
        workload["peak_memory_bytes"] + collected_workload["memory_reservation_bytes"]
        > resources["usable_memory_bytes"]
    ):
        raise QualificationError("memory operational headroom is below 30%")
    require_headroom(resources["usable_cpu_millicores"], workload["peak_cpu_millicores"], "CPU")
    require_headroom(resources["usable_memory_bytes"], workload["peak_memory_bytes"], "memory")

    collected_storage = source["collection"]["storage"]
    storage_contract = probes["storage"]["cycle"]
    required_cycles = (
        workload["completed_iterations"]
        * storage_contract["minimum_cycles_per_workload_iteration"]
    )
    if (
        collected_storage["controller_observed_cycles_completed"] < required_cycles
        or collected_storage["controller_observed_deadline_misses"] != 0
        or not collected_storage["same_persistent_filesystem_observed"]
        or collected_storage["maximum_cycle_duration_microseconds"]
        > storage_contract["deadline_seconds"] * 1_000_000
    ):
        raise QualificationError("trusted storage probe did not complete its reviewed workload")
    deadline = storage_contract["deadline_seconds"]
    transactions = storage_contract["postgresql_synchronous_transactions"]
    file_bytes = storage_contract["private_file_bytes"]
    if (
        performance["random_read_iops"] * deadline < transactions
        or performance["random_write_iops"] * deadline < transactions
        or performance["sequential_read_bytes_per_second"] * deadline < file_bytes
        or performance["sequential_write_bytes_per_second"] * deadline < file_bytes
        or performance["fsync_p95_microseconds"] * transactions > deadline * 1_000_000
    ):
        raise QualificationError("storage probe observations cannot satisfy reviewed storage cycle")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strictly admit one trusted SecPal capacity qualification artifact."
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--evaluation-time", required=True)
    parser.add_argument("--expected-target-sha", required=True)
    parser.add_argument("--expected-control-sha", required=True)
    parser.add_argument("--expected-target-identity-sha256", required=True)
    parser.add_argument("--expected-workload-probe-revision", required=True)
    parser.add_argument("--expected-storage-probe-revision", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        validate_hash(arguments.expected_target_sha, SHA, "target SHA")
        validate_hash(arguments.expected_control_sha, SHA, "control SHA")
        validate_hash(arguments.expected_target_identity_sha256, SHA256, "target identity")
        validate_hash(arguments.expected_workload_probe_revision, SHA256, "workload probe")
        validate_hash(arguments.expected_storage_probe_revision, SHA256, "storage probe")
        schema = load_schema()
        probes, workload_revision, storage_revision = load_probe_contract()
        evidence, _ = load_bounded_json(arguments.evidence, "qualification evidence")
        source, source_payload = load_bounded_json(arguments.source_evidence, "source evidence")
        evaluation_time = parse_timestamp(arguments.evaluation_time, "evaluation_time")
        admit(
            evidence,
            source,
            source_payload,
            evaluation_time,
            schema,
            probes,
            workload_revision,
            storage_revision,
            arguments.expected_target_sha,
            arguments.expected_control_sha,
            arguments.expected_target_identity_sha256,
            arguments.expected_workload_probe_revision,
            arguments.expected_storage_probe_revision,
        )
    except jsonschema.ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        print(f"NOT QUALIFIED: schema validation failed at {location}", file=sys.stderr)
        return 1
    except QualificationError as error:
        print(f"NOT QUALIFIED: {error}", file=sys.stderr)
        return 1
    print("QUALIFIED: trusted provider-neutral capacity evidence is current and admitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
