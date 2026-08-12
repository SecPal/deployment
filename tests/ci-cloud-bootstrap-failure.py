#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Regression tests for bounded early cloud-bootstrap failure evidence."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
WRITER = ROOT / "scripts" / "ci-cloud" / "write-bootstrap-failure.py"
SCHEMA = ROOT / "schemas" / "ci-cloud-bootstrap-failure.schema.json"
TARGET_SHA = "a" * 40


def load_writer():
    spec = importlib.util.spec_from_file_location("ci_cloud_bootstrap_failure", WRITER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load bootstrap failure writer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BootstrapFailureEvidenceTests(unittest.TestCase):
    def invoke(
        self,
        output_dir: Path,
        *,
        provider: str = "digitalocean",
        region: str = "fra1",
        profile: str = "intel",
        image_slug: str = "debian-13-x64",
        image_id: str = "234194767",
        machine_type: str = "s-4vcpu-8gb-intel",
        stage: str = "bootstrap",
        host_setup_failure: str = "null",
        host_key_observations: str = "null",
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            "python3",
            str(WRITER),
            str(output_dir),
            provider,
            region,
            profile,
            TARGET_SHA,
            "12345",
            "1",
            image_slug,
            image_id,
            machine_type,
            "2026-08-10T22:48:58Z",
            stage,
            "1",
            host_setup_failure,
            host_key_observations,
        ]
        return subprocess.run(arguments, check=False, capture_output=True, text=True)

    def test_writes_closed_structured_failure_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(output_dir)
            self.assertEqual(0, completed.returncode, completed.stderr)
            document = json.loads(
                (output_dir / "bootstrap-failure.json").read_text(encoding="utf-8")
            )
            self.assertEqual(4, document["schema_version"])
            self.assertEqual(
                {"schema_version", "workflow", "test"}, set(document)
            )
            self.assertEqual(
                {
                    "provider",
                    "region",
                    "profile",
                    "machine_type",
                    "provider_image",
                    "started_at",
                    "ended_at",
                    "failure_stage",
                    "orchestration_exit_status",
                    "host_setup_failure",
                    "host_key_observations",
                    "result",
                    "failed_admission_invariants",
                },
                set(document["test"]),
            )
            self.assertEqual("failed", document["test"]["result"])
            self.assertIsNone(document["test"]["host_setup_failure"])
            self.assertIsNone(document["test"]["host_key_observations"])
            self.assertEqual(
                "CI_CLOUD_REMOTE_ORCHESTRATION",
                document["test"]["failed_admission_invariants"][0],
            )
            datetime.fromisoformat(document["test"]["started_at"].replace("Z", "+00:00"))
            datetime.fromisoformat(document["test"]["ended_at"].replace("Z", "+00:00"))
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            self.assertEqual(
                [],
                list(
                    Draft202012Validator(
                        schema, format_checker=FormatChecker()
                    ).iter_errors(document)
                ),
            )
            summary = (output_dir / "summary.md").read_text(encoding="utf-8")
            self.assertIn("bootstrap", summary)
            self.assertIn(TARGET_SHA, summary)
            self.assertEqual(
                0o600,
                (output_dir / "bootstrap-failure.json").stat().st_mode & 0o777,
            )
            self.assertEqual(
                0o600,
                (output_dir / "summary.md").stat().st_mode & 0o777,
            )

    def test_rejects_arbitrary_failure_stage_without_writing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(output_dir, stage="arbitrary-shell-text")
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_rejects_existing_output_to_prevent_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            first = self.invoke(output_dir)
            second = self.invoke(output_dir)
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertNotEqual(0, second.returncode)

    def test_accepts_closed_gcp_axion_failure_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.invoke(
                Path(temporary),
                provider="gcp",
                region="europe-west3-a",
                profile="axion",
                image_slug="debian-cloud/debian-13-arm64",
                image_id=(
                    "https://www.googleapis.com/compute/v1/projects/debian-cloud/"
                    "global/images/debian-13-trixie-arm64-v20260810"
                ),
                machine_type="c4a-standard-4",
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_records_closed_host_setup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                host_setup_failure='{"exit_status":7,"stage":"apparmor"}',
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            document = json.loads(
                (output_dir / "bootstrap-failure.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                {"exit_status": 7, "stage": "apparmor"},
                document["test"]["host_setup_failure"],
            )
            self.assertIn(
                "Host setup failure: `apparmor` (exit `7`)",
                (output_dir / "summary.md").read_text(encoding="utf-8"),
            )

    def test_rejects_unclosed_host_setup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                host_setup_failure=(
                    '{"exit_status":1,"secret":"forbidden","stage":"ssh"}'
                ),
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_records_kernel_reboot_host_setup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                host_setup_failure=(
                    '{"exit_status":1,"stage":"kernel-reboot"}'
                ),
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            document = json.loads(
                (output_dir / "bootstrap-failure.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                {"exit_status": 1, "stage": "kernel-reboot"},
                document["test"]["host_setup_failure"],
            )

    def test_identifies_invalid_host_setup_failure_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(output_dir, host_setup_failure="{")
            self.assertNotEqual(0, completed.returncode)
            self.assertIn(
                "host-setup failure diagnostic is invalid JSON",
                completed.stderr,
            )
            self.assertNotIn("host-key observations", completed.stderr)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_rejects_host_setup_detail_outside_bootstrap_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                stage="host-key",
                host_setup_failure='{"exit_status":1,"stage":"initialize"}',
                host_key_observations=(
                    '{"changed_key":0,"connection_refused":1,'
                    '"connection_timeout":0,"multiple_keys":0,'
                    '"no_key":0,"other":0}'
                ),
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_records_closed_host_key_observations(self) -> None:
        observations = {
            "changed_key": 0,
            "connection_refused": 3,
            "connection_timeout": 1,
            "multiple_keys": 0,
            "no_key": 2,
            "other": 0,
        }
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                stage="host-key",
                host_key_observations=json.dumps(observations),
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            document = json.loads(
                (output_dir / "bootstrap-failure.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                observations,
                document["test"]["host_key_observations"],
            )
            self.assertIn(
                "Host-key observations: `connection_refused=3, "
                "connection_timeout=1, no_key=2, multiple_keys=0, "
                "changed_key=0, other=0`",
                (output_dir / "summary.md").read_text(encoding="utf-8"),
            )

    def test_rejects_host_key_observations_outside_host_key_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                host_key_observations=(
                    '{"changed_key":0,"connection_refused":1,'
                    '"connection_timeout":0,"multiple_keys":0,'
                    '"no_key":0,"other":0}'
                ),
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_rejects_unclosed_host_key_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                stage="host-key",
                host_key_observations=(
                    '{"changed_key":0,"connection_refused":1,'
                    '"connection_timeout":0,"multiple_keys":0,'
                    '"no_key":0,"other":0,"authorization":"forbidden"}'
                ),
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_identifies_invalid_host_key_observations_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            completed = self.invoke(
                output_dir,
                host_key_observations="{",
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn(
                "host-key observations diagnostic is invalid JSON",
                completed.stderr,
            )
            self.assertNotIn("host-setup failure", completed.stderr)
            self.assertEqual([], list(output_dir.iterdir()))

    def test_staging_failure_leaves_no_partial_evidence(self) -> None:
        writer = load_writer()
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            real_stage_file = writer.stage_file
            calls = 0

            def fail_second_stage(
                target_dir: Path, name: str, content: str
            ) -> Path:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("fixture write failure")
                return real_stage_file(target_dir, name, content)

            with mock.patch.object(
                writer,
                "stage_file",
                side_effect=fail_second_stage,
            ):
                with self.assertRaises(OSError):
                    writer.write_bundle(
                        output_dir,
                        {"bootstrap-failure.json": "{}\n", "summary.md": "failed\n"},
                    )
            self.assertEqual([], list(output_dir.iterdir()))

    def test_publication_collision_rolls_back_new_artifact(self) -> None:
        writer = load_writer()
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            existing_summary = output_dir / "summary.md"
            existing_summary.write_text("existing\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                writer.write_bundle(
                    output_dir,
                    {"bootstrap-failure.json": "{}\n", "summary.md": "failed\n"},
                )
            self.assertFalse((output_dir / "bootstrap-failure.json").exists())
            self.assertEqual(
                "existing\n", existing_summary.read_text(encoding="utf-8")
            )
            self.assertEqual([existing_summary], list(output_dir.iterdir()))


if __name__ == "__main__":
    unittest.main()
