#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure admission for provider-neutral SecPal capacity evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/capacity-qualification.schema.json"
HEADROOM_PERCENT = 30


class QualificationError(ValueError):
    """A bounded capacity-qualification rejection."""


def parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError(f"{field} is not a valid timestamp") from error
    if parsed.utcoffset() is None:
        raise QualificationError(f"{field} must include a UTC offset")
    return parsed


def require_headroom(capacity: int, peak: int, resource: str) -> None:
    usable_percent = 100 - HEADROOM_PERCENT
    if peak * 100 > capacity * usable_percent:
        raise QualificationError(
            f"{resource} operational headroom is below {HEADROOM_PERCENT}%"
        )


def admit(
    evidence: dict[str, Any], evaluation_time: datetime, schema: dict[str, Any]
) -> None:
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(evidence)

    qualification = evidence["qualification"]
    result = qualification["result"]
    if result != "PASS":
        raise QualificationError(f"qualification result is {result}, not PASS")

    observed_at = parse_timestamp(qualification["observed_at"], "observed_at")
    valid_until = parse_timestamp(qualification["valid_until"], "valid_until")
    maximum_freshness = schema["$defs"]["qualification"]["properties"][
        "freshness_seconds"
    ]["const"]
    if evaluation_time < observed_at:
        raise QualificationError("qualification evidence is from the future")
    if evaluation_time >= valid_until:
        raise QualificationError("qualification evidence is stale")
    if valid_until <= observed_at or valid_until - observed_at > timedelta(
        seconds=maximum_freshness
    ):
        raise QualificationError("qualification freshness window is invalid")

    subject = evidence["subject"]
    if subject["kind"] == "provider-product":
        catalog_observed_at = parse_timestamp(
            subject["provider_product"]["catalog_observed_at"],
            "catalog_observed_at",
        )
        if catalog_observed_at > observed_at:
            raise QualificationError(
                "provider catalog observation is newer than qualification evidence"
            )
        if observed_at - catalog_observed_at > timedelta(
            seconds=maximum_freshness
        ):
            raise QualificationError("provider catalog evidence is stale")

    cleanup = qualification["cleanup"]
    if cleanup["required"] and cleanup["status"] != "complete":
        raise QualificationError("required qualification cleanup is not complete")

    capability = evidence["capability"]
    observations = evidence["observations"]
    if capability["compute_isolation"] != observations["compute_isolation"][
        "classification"
    ]:
        raise QualificationError(
            "claimed compute isolation does not match effective observation"
        )
    if capability["cpu_architecture"] != observations["cpu"]["architecture"]:
        raise QualificationError(
            "claimed CPU architecture does not match effective observation"
        )

    resources = observations["resources"]
    if resources["free_storage_bytes"] > resources["total_storage_bytes"]:
        raise QualificationError("free storage exceeds total storage")
    if resources["free_inodes"] > resources["total_inodes"]:
        raise QualificationError("free inodes exceed total inodes")
    if resources["free_storage_bytes"] * 100 < resources["total_storage_bytes"] * 20:
        raise QualificationError("storage operational headroom is below 20%")
    if resources["free_inodes"] * 100 < resources["total_inodes"] * 20:
        raise QualificationError("inode operational headroom is below 20%")

    workload = observations["workload"]
    target_sha = qualification["target_sha"]
    if workload["probe_revision"] != target_sha:
        raise QualificationError("workload probe is not bound to target revision")
    if observations["storage"]["performance"]["probe_revision"] != target_sha:
        raise QualificationError("storage probe is not bound to target revision")
    require_headroom(
        resources["usable_cpu_millicores"],
        workload["peak_cpu_millicores"],
        "CPU",
    )
    require_headroom(
        resources["usable_memory_bytes"],
        workload["peak_memory_bytes"],
        "memory",
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Admit one closed SecPal capacity qualification artifact."
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument(
        "--evaluation-time",
        required=True,
        help="Explicit RFC 3339 decision time; the validator never reads the clock.",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        evidence = json.loads(arguments.evidence.read_text(encoding="utf-8"))
        evaluation_time = parse_timestamp(arguments.evaluation_time, "evaluation_time")
        if not isinstance(evidence, dict):
            raise QualificationError("qualification evidence must be an object")
        admit(evidence, evaluation_time, schema)
    except jsonschema.ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        print(f"NOT QUALIFIED: schema validation failed at {location}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError, QualificationError) as error:
        print(f"NOT QUALIFIED: {error}", file=sys.stderr)
        return 1
    print("QUALIFIED: provider-neutral capacity evidence is current and admitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
