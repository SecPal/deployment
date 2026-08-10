#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Write closed, non-secret evidence for an early remote orchestration failure."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,2}$")
DIGITALOCEAN_IMAGE_ID = re.compile(r"^[1-9][0-9]{0,19}$")
GCP_IMAGE_ID = re.compile(
    r"^https://www\.googleapis\.com/compute/v1/projects/debian-cloud/"
    r"global/images/debian-13-trixie-arm64-v[0-9]{8}$"
)
ALLOWED_IDENTITIES = {
    (
        "digitalocean",
        "fra1",
        "intel",
        "debian-13-x64",
        "s-4vcpu-8gb-intel",
    ),
    (
        "digitalocean",
        "fra1",
        "amd",
        "debian-13-x64",
        "s-4vcpu-8gb-amd",
    ),
    (
        "gcp",
        "europe-west3-a",
        "axion",
        "debian-cloud/debian-13-arm64",
        "c4a-standard-4",
    ),
}
FAILURE_STAGES = (
    "host-key",
    "cloud-init",
    "root-ssh",
    "target",
    "collector",
    "validation",
)


def fail(message: str) -> None:
    raise ValueError(message)


def write_new(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


def validate(arguments: argparse.Namespace) -> None:
    identity = (
        arguments.provider,
        arguments.region,
        arguments.profile,
        arguments.provider_image_slug,
        arguments.machine_type,
    )
    if identity not in ALLOWED_IDENTITIES:
        fail("provider identity is outside the closed allowlist")
    if SHA.fullmatch(arguments.target_sha) is None:
        fail("target SHA is invalid")
    if RUN_ID.fullmatch(arguments.run_id) is None:
        fail("run ID is invalid")
    if RUN_ATTEMPT.fullmatch(arguments.run_attempt) is None:
        fail("run attempt is invalid")
    if not 1 <= arguments.exit_status <= 255:
        fail("orchestration exit status is invalid")
    if (
        arguments.provider == "digitalocean"
        and DIGITALOCEAN_IMAGE_ID.fullmatch(arguments.provider_image_id) is None
    ) or (
        arguments.provider == "gcp"
        and GCP_IMAGE_ID.fullmatch(arguments.provider_image_id) is None
    ):
        fail("provider image identity is invalid")
    if (
        not arguments.output_dir.is_dir()
        or arguments.output_dir.is_symlink()
    ):
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
    parser.add_argument("failure_stage", choices=FAILURE_STAGES)
    parser.add_argument("exit_status", type=int)
    arguments = parser.parse_args()
    try:
        validate(arguments)
        document = {
            "schema_version": 1,
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
                "failure_stage": arguments.failure_stage,
                "orchestration_exit_status": arguments.exit_status,
                "result": "failed",
                "failed_admission_invariants": ["CI_CLOUD_REMOTE_ORCHESTRATION"],
            },
        }
        summary = "\n".join(
            (
                "# Debian 13 cloud bootstrap failure",
                "",
                "- Result: `failed`",
                f"- Target SHA: `{arguments.target_sha}`",
                f"- Provider/profile: `{arguments.provider}/{arguments.profile}` in `{arguments.region}`",
                f"- Failure stage: `{arguments.failure_stage}`",
                f"- Orchestration exit status: `{arguments.exit_status}`",
                "- Failed admission invariant: `CI_CLOUD_REMOTE_ORCHESTRATION`",
                "",
            )
        )
        evidence_path = arguments.output_dir / "bootstrap-failure.json"
        summary_path = arguments.output_dir / "summary.md"
        created: list[Path] = []
        try:
            write_new(
                evidence_path,
                json.dumps(document, indent=2, sort_keys=True) + "\n",
            )
            created.append(evidence_path)
            write_new(summary_path, summary)
            created.append(summary_path)
        except OSError:
            for path in created:
                path.unlink(missing_ok=True)
            raise
    except (OSError, UnicodeError, ValueError) as error:
        print(
            f"ERROR: unable to write bootstrap failure evidence: {error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
