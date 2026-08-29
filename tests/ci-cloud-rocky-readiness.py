#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavioral contract for Rocky qualification guest readiness."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
WAITER = ROOT / "scripts/ci-cloud/wait-rocky-qualification-readiness.py"
WORKFLOW = ROOT / ".github/workflows/rocky-cloud-qualification.yml"
BOOTSTRAP = ROOT / "scripts/ci-cloud/bootstrap-rocky-host.tftpl"
TRANSITION = ROOT / "scripts/ci-cloud/rocky-gcp-transition.py"
PUBLISHER = ROOT / "scripts/ci-cloud/publish-rocky-qualification-readiness.py"
READINESS_SCHEMA = ROOT / "schemas/rocky-cloud-qualification-readiness.schema.json"


def load_waiter():
    specification = importlib.util.spec_from_file_location("rocky_readiness", WAITER)
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load Rocky readiness waiter")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class RockyQualificationReadinessTests(unittest.TestCase):
    target = "293977ae93408a7bb812619de58649ab8a92d438"
    control = "5" * 40
    boot = "22222222-2222-4222-8222-222222222222"
    key_digest = "a" * 64

    def setUp(self) -> None:
        self.module = load_waiter()
        self.expected = self.module.Expectation(
            target_sha=self.target,
            trusted_control_sha=self.control,
            access_run_id="33146182082",
            access_run_attempt="1",
            ssh_public_key_sha256=self.key_digest,
        )

    def marker(self, **changes: object) -> dict[str, object]:
        marker: dict[str, object] = {
            "schema_version": 1,
            "target_sha": self.target,
            "trusted_control_sha": self.control,
            "access_run_id": "33146182082",
            "access_run_attempt": "1",
            "boot_id": self.boot,
            "ssh_public_key_sha256": self.key_digest,
            "cloud_identity_absent": True,
            "guest_startup_complete": True,
            "runtime_user_manager_active": True,
            "runtime_user_bus_available": True,
            "runtime_user_control_reachable": True,
        }
        marker.update(changes)
        return marker

    def run_sequence(self, outcomes: list[object]):
        calls = 0

        def probe():
            nonlocal calls
            outcome = outcomes[min(calls, len(outcomes) - 1)]
            calls += 1
            return outcome

        result = self.module.wait_for_readiness(
            probe,
            self.expected,
            deadline=4,
            interval=1,
            monotonic=self.module.StepClock(),
            sleep=lambda _: None,
        )
        return result, calls

    def test_delayed_transport_does_not_execute_target_early(self) -> None:
        ready = self.module.ProbeResult.ready(self.boot, self.marker())
        result, calls = self.run_sequence(
            [self.module.ProbeResult.transport(), self.module.ProbeResult.transport(), ready]
        )
        self.assertEqual(self.boot, result["boot_id"])
        self.assertEqual(3, calls)

    def test_permanent_transport_refusal_is_bounded_and_closed(self) -> None:
        with self.assertRaises(self.module.ReadinessFailure) as failure:
            self.run_sequence([self.module.ProbeResult.transport()])
        self.assertEqual(
            ("ssh-transport", "not-ready-timeout"),
            (failure.exception.operation, failure.exception.reason),
        )

    def test_delayed_authentication_waits_for_exact_rotated_authority(self) -> None:
        ready = self.module.ProbeResult.ready(self.boot, self.marker())
        result, calls = self.run_sequence(
            [self.module.ProbeResult.authentication(), ready]
        )
        self.assertTrue(result["guest_startup_complete"])
        self.assertEqual(2, calls)

    def test_missing_marker_never_admits_target_execution(self) -> None:
        with self.assertRaises(self.module.ReadinessFailure) as failure:
            self.run_sequence([self.module.ProbeResult.missing(self.boot)])
        self.assertEqual(
            ("guest-state", "missing-or-stale"),
            (failure.exception.operation, failure.exception.reason),
        )

    def test_stale_or_mismatched_marker_fails_closed(self) -> None:
        cases = (
            {"boot_id": "11111111-1111-4111-8111-111111111111"},
            {"target_sha": "f" * 40},
            {"trusted_control_sha": "e" * 40},
            {"access_run_id": "33145864214"},
            {"access_run_attempt": "2"},
            {"ssh_public_key_sha256": "b" * 64},
            {"cloud_identity_absent": False},
            {"guest_startup_complete": False},
        )
        for mutation in cases:
            with self.subTest(mutation=mutation), self.assertRaises(
                self.module.ReadinessFailure
            ) as failure:
                self.run_sequence(
                    [self.module.ProbeResult.ready(self.boot, self.marker(**mutation))]
                )
            self.assertEqual(
                ("guest-state", "binding-mismatch"),
                (failure.exception.operation, failure.exception.reason),
            )

    def test_runtime_user_readiness_failures_remain_independently_actionable(self) -> None:
        cases = (
            (
                {"guest_startup_complete": False, "runtime_user_manager_active": False},
                "runtime-user-manager",
            ),
            (
                {"guest_startup_complete": False, "runtime_user_bus_available": False},
                "runtime-user-bus",
            ),
            (
                {"guest_startup_complete": False, "runtime_user_control_reachable": False},
                "runtime-user-control",
            ),
        )
        for mutation, operation in cases:
            with self.subTest(operation=operation), self.assertRaises(
                self.module.ReadinessFailure
            ) as failure:
                self.run_sequence(
                    [self.module.ProbeResult.ready(self.boot, self.marker(**mutation))]
                )
            self.assertEqual(
                (operation, "not-ready-timeout"),
                (failure.exception.operation, failure.exception.reason),
            )

    def test_legacy_missing_mistyped_and_extra_runtime_facts_fail_closed(self) -> None:
        for mutation in (
            {"runtime_user_manager_active": None},
            {"runtime_user_bus_available": "true"},
            {"runtime_user_control_reachable": 1},
            {"unexpected": True},
        ):
            marker = self.marker(**mutation)
            if mutation == {"runtime_user_manager_active": None}:
                marker.pop("runtime_user_manager_active")
            with self.subTest(mutation=mutation), self.assertRaises(
                self.module.ReadinessFailure
            ) as failure:
                self.run_sequence([self.module.ProbeResult.ready(self.boot, marker)])
            self.assertEqual(
                ("guest-state", "binding-mismatch"),
                (failure.exception.operation, failure.exception.reason),
            )

    def test_current_marker_is_exact_and_order_independent(self) -> None:
        reversed_marker = dict(reversed(list(self.marker().items())))
        result, calls = self.run_sequence(
            [self.module.ProbeResult.ready(self.boot, reversed_marker)]
        )
        self.assertEqual(self.marker(), result)
        self.assertEqual(1, calls)

    def test_startup_and_workflow_enforce_the_new_lifecycle_boundary(self) -> None:
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        publisher = PUBLISHER.read_text(encoding="utf-8")
        transition = TRANSITION.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("qualification-readiness.json", bootstrap)
        self.assertLess(
            bootstrap.index('rm -f -- "$qualification_readiness"'),
            bootstrap.index('printf \'%s\\n\' "$public_key"'),
        )
        self.assertLess(
            bootstrap.index("/usr/local/sbin/secpal-prepare-rocky-host"),
            bootstrap.index("/usr/local/sbin/secpal-publish-rocky-qualification-readiness"),
        )
        self.assertIn("runtime_user_manager_active", publisher)
        self.assertIn("runtime_user_bus_available", publisher)
        self.assertIn("runtime_user_control_reachable", publisher)
        self.assertNotIn("daemon-reload", publisher)
        self.assertNotRegex(publisher, r"(?m)^\s*(?:time\.)?sleep\(60\)")
        self.assertIn("secpal-rocky-access-run-id", transition)
        waiter = "scripts/ci-cloud/wait-rocky-qualification-readiness.py"
        target = "sudo /usr/local/sbin/secpal-run-rocky-target-qualification"
        self.assertIn(waiter, workflow)
        self.assertLess(workflow.index(waiter), workflow.index(target))
        self.assertEqual(1, workflow.count(target))
        target_job = workflow.split("  qualify_target:", 1)[1].split("\n  cleanup:", 1)[0]
        self.assertNotIn("id-token: write", target_job)
        self.assertNotIn("google-github-actions/auth", target_job)
        self.assertNotRegex(target_job, r"(?m)^\s*-\s+run:\s+sleep\s+[0-9]+")

    def test_failure_diagnostic_is_bounded_and_contains_no_transport_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failure.json"
            failure = self.module.ReadinessFailure(
                "ssh-authentication", "not-ready-timeout"
            )
            self.module.write_failure(
                output,
                failure,
                self.expected,
                probe_count=90,
                elapsed_seconds=450,
            )
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertLessEqual(output.stat().st_size, 2048)
            self.assertEqual("qualification-readiness", document["phase"])
            self.assertNotIn("stdout", document)
            self.assertNotIn("stderr", document)
            self.assertNotIn("command", document)

    def test_success_schema_requires_exact_true_runtime_user_facts(self) -> None:
        schema = json.loads(READINESS_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        self.assertEqual([], list(validator.iter_errors(self.marker())))
        for mutation in (
            {"runtime_user_manager_active": False},
            {"runtime_user_bus_available": False},
            {"runtime_user_control_reachable": False},
            {"runtime_user_manager_active": "true"},
            {"unexpected": True},
        ):
            with self.subTest(mutation=mutation):
                self.assertTrue(list(validator.iter_errors(self.marker(**mutation))))
        missing = self.marker()
        missing.pop("runtime_user_manager_active")
        self.assertTrue(list(validator.iter_errors(missing)))

    def test_unreviewed_probe_cadence_is_rejected_before_network_access(self) -> None:
        result = subprocess.run(
            [
                WAITER,
                "--ipv4",
                "8.8.8.8",
                "--identity",
                "/does/not/exist",
                "--public-key",
                "/does/not/exist",
                "--known-hosts",
                "/does/not/exist",
                "--target-sha",
                self.target,
                "--control-sha",
                self.control,
                "--run-id",
                "33146182082",
                "--run-attempt",
                "1",
                "--diagnostic-output",
                "/does/not/exist",
                "--interval-seconds",
                "1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(64, result.returncode)
        self.assertIn(b"readiness budget is outside the reviewed bound", result.stderr)


if __name__ == "__main__":
    unittest.main()
