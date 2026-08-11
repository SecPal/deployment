#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Write closed, non-secret evidence for an early remote orchestration failure."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "ci-cloud-bootstrap-failure.schema.json"
)
FAILURE_STAGES = (
    "host-key",
    "cloud-init",
    "root-ssh",
    "target",
    "collector",
    "validation",
)
OUTPUT_NAMES = frozenset(("bootstrap-failure.json", "summary.md"))


def fail(message: str) -> None:
    raise ValueError(message)


def parse_timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail("orchestration start time is invalid")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        fail("orchestration start time must include a timezone")
    return timestamp


def validate_declared_schema(document: object) -> None:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = list(
            Draft202012Validator(
                schema,
                format_checker=FormatChecker(),
            ).iter_errors(document)
        )
    except (OSError, UnicodeError, json.JSONDecodeError, SchemaError):
        fail("declared bootstrap failure schema is unavailable or invalid")
    if errors:
        first = min(errors, key=lambda error: tuple(str(item) for item in error.path))
        location = "$" + "".join(f"[{item!r}]" for item in first.path)
        fail(f"document violates declared bootstrap failure schema at {location}")


def stage_file(output_dir: Path, name: str, content: str) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_dir,
        prefix=f".{name}.",
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        output = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = -1
        with output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


def write_bundle(output_dir: Path, contents: dict[str, str]) -> None:
    if set(contents) != OUTPUT_NAMES:
        fail("bootstrap failure bundle has unexpected files")

    staged: dict[str, Path] = {}
    published: list[Path] = []
    try:
        for name in sorted(contents):
            staged[name] = stage_file(output_dir, name, contents[name])
        for name in sorted(contents):
            destination = output_dir / name
            os.link(staged[name], destination, follow_symlinks=False)
            published.append(destination)
    except BaseException:
        for path in published:
            path.unlink(missing_ok=True)
        raise
    finally:
        for path in staged.values():
            path.unlink(missing_ok=True)


def validate_output_dir(output_dir: Path) -> None:
    if not output_dir.is_dir() or output_dir.is_symlink():
        fail("output directory must be an existing regular directory")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("provider")
    parser.add_argument("region")
    parser.add_argument("profile")
    parser.add_argument("target_sha")
    parser.add_argument("run_id")
    parser.add_argument("run_attempt")
    parser.add_argument("provider_image_slug")
    parser.add_argument("provider_image_id")
    parser.add_argument("machine_type")
    parser.add_argument("started_at")
    parser.add_argument("failure_stage", choices=FAILURE_STAGES)
    parser.add_argument("exit_status", type=int)
    parser.add_argument("host_setup_failure_json")
    parser.add_argument("host_key_observations_json")
    arguments = parser.parse_args()
    try:
        validate_output_dir(arguments.output_dir)
        started_at = parse_timestamp(arguments.started_at)
        ended_at = datetime.now(timezone.utc).replace(microsecond=0)
        if started_at > ended_at:
            fail("orchestration start time is after the end time")
        ended_at_text = ended_at.isoformat().replace("+00:00", "Z")
        try:
            host_setup_failure = json.loads(arguments.host_setup_failure_json)
            host_key_observations = json.loads(
                arguments.host_key_observations_json
            )
        except json.JSONDecodeError:
            fail("closed bootstrap diagnostic is invalid JSON")
        document = {
            "schema_version": 2,
            "workflow": {
                "repository": "SecPal/deployment",
                "run_id": arguments.run_id,
                "run_attempt": arguments.run_attempt,
                "target_sha": arguments.target_sha,
            },
            "test": {
                "provider": arguments.provider,
                "region": arguments.region,
                "profile": arguments.profile,
                "machine_type": arguments.machine_type,
                "provider_image": {
                    "slug": arguments.provider_image_slug,
                    "id": arguments.provider_image_id,
                },
                "started_at": arguments.started_at,
                "ended_at": ended_at_text,
                "failure_stage": arguments.failure_stage,
                "orchestration_exit_status": arguments.exit_status,
                "host_setup_failure": host_setup_failure,
                "host_key_observations": host_key_observations,
                "result": "failed",
                "failed_admission_invariants": ["CI_CLOUD_REMOTE_ORCHESTRATION"],
            },
        }
        validate_declared_schema(document)
        summary_lines = [
            "# Debian 13 cloud bootstrap failure",
            "",
            "- Result: `failed`",
            f"- Target SHA: `{arguments.target_sha}`",
            f"- Provider/profile: `{arguments.provider}/{arguments.profile}` in `{arguments.region}`",
            f"- Started at: `{arguments.started_at}`",
            f"- Ended at: `{ended_at_text}`",
            f"- Failure stage: `{arguments.failure_stage}`",
            f"- Orchestration exit status: `{arguments.exit_status}`",
        ]
        if isinstance(host_setup_failure, dict):
            summary_lines.append(
                "- Host setup failure: "
                f"`{host_setup_failure.get('stage')}` "
                f"(exit `{host_setup_failure.get('exit_status')}`)"
            )
        if isinstance(host_key_observations, dict):
            summary_lines.append(
                "- Host-key observations: `"
                + ", ".join(
                    f"{name}={host_key_observations[name]}"
                    for name in (
                        "connection_refused",
                        "connection_timeout",
                        "no_key",
                        "multiple_keys",
                        "changed_key",
                        "other",
                    )
                )
                + "`"
            )
        summary_lines.extend(
            (
                "- Failed admission invariant: `CI_CLOUD_REMOTE_ORCHESTRATION`",
                "",
            )
        )
        summary = "\n".join(summary_lines)
        write_bundle(
            arguments.output_dir,
            {
                "bootstrap-failure.json": (
                    json.dumps(document, indent=2, sort_keys=True) + "\n"
                ),
                "summary.md": summary,
            },
        )
    except (OSError, UnicodeError, ValueError) as error:
        print(
            f"ERROR: unable to write bootstrap failure evidence: {error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
