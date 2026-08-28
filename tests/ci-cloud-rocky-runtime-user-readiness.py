#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Behavioral contract for current-boot runtime-user readiness."""

from __future__ import annotations

import importlib.util
import stat
import subprocess
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "scripts/ci-cloud/publish-rocky-qualification-readiness.py"


def load_publisher():
    specification = importlib.util.spec_from_file_location(
        "rocky_runtime_user_readiness", PUBLISHER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("unable to load runtime-user readiness publisher")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class StepClock:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class RockyRuntimeUserReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_publisher()

    def wait(self, observations):
        calls = 0

        def probe(_deadline):
            nonlocal calls
            observation = observations[min(calls, len(observations) - 1)]
            calls += 1
            return observation

        clock = StepClock()
        result = self.module.wait_for_runtime_user(
            probe,
            deadline=4,
            interval=1,
            monotonic=clock,
            sleep=clock.sleep,
        )
        return result, calls

    def test_manager_inactive_never_becomes_readiness(self) -> None:
        observation = self.module.RuntimeUserObservation(False, False, False)
        result, calls = self.wait([observation])
        self.assertFalse(result.ready)
        self.assertEqual(observation, result.observation)
        self.assertEqual(4, calls)

    def test_active_manager_without_bus_never_becomes_readiness(self) -> None:
        observation = self.module.RuntimeUserObservation(True, False, False)
        result, _ = self.wait([observation])
        self.assertFalse(result.ready)

    def test_manager_and_bus_without_cross_user_control_never_become_readiness(self) -> None:
        observation = self.module.RuntimeUserObservation(True, True, False)
        result, _ = self.wait([observation])
        self.assertFalse(result.ready)

    def test_all_three_current_boot_facts_admit_readiness(self) -> None:
        unavailable = self.module.RuntimeUserObservation(False, False, False)
        ready = self.module.RuntimeUserObservation(True, True, True)
        result, calls = self.wait([unavailable, ready])
        self.assertTrue(result.ready)
        self.assertEqual(ready, result.observation)
        self.assertEqual(2, calls)

    def test_linger_does_not_replace_bounded_manager_reachability_wait(self) -> None:
        unavailable = self.module.RuntimeUserObservation(False, True, False)
        ready = self.module.RuntimeUserObservation(True, True, True)
        result, calls = self.wait([unavailable, unavailable, ready])
        self.assertTrue(result.ready)
        self.assertEqual(3, calls)

    def test_probe_count_remains_bounded_if_the_clock_does_not_advance(self) -> None:
        observation = self.module.RuntimeUserObservation(False, False, False)
        probes = 0

        def probe(_deadline):
            nonlocal probes
            probes += 1
            return observation

        result = self.module.wait_for_runtime_user(
            probe,
            deadline=60,
            interval=5,
            monotonic=lambda: 0,
            sleep=lambda _: None,
        )
        self.assertFalse(result.ready)
        self.assertEqual(13, probes)

    def test_assembly_preserves_bindings_and_never_promotes_failure(self) -> None:
        observation = self.module.RuntimeUserObservation(True, True, False)
        document = self.module.assemble_readiness(
            target_sha="d" * 40,
            trusted_control_sha="c" * 40,
            access_run_id="33189464175",
            access_run_attempt="1",
            boot_id="22222222-2222-4222-8222-222222222222",
            ssh_public_key_sha256="a" * 64,
            result=self.module.RuntimeUserResult(False, observation),
        )
        self.assertFalse(document["guest_startup_complete"])
        self.assertTrue(document["runtime_user_manager_active"])
        self.assertTrue(document["runtime_user_bus_available"])
        self.assertFalse(document["runtime_user_control_reachable"])
        self.assertEqual("33189464175", document["access_run_id"])
        self.assertEqual("22222222-2222-4222-8222-222222222222", document["boot_id"])

    def test_observer_uses_exact_non_mutating_cross_user_control_seam(self) -> None:
        completed = subprocess.CompletedProcess([], 0)
        socket_metadata = mock.Mock(st_mode=stat.S_IFSOCK | 0o600)
        with mock.patch.object(
            self.module.pwd, "getpwnam", return_value=mock.Mock(pw_uid=994)
        ), mock.patch.object(
            self.module.os, "stat", return_value=socket_metadata
        ), mock.patch.object(
            self.module.subprocess, "run", side_effect=(completed, completed)
        ) as run:
            observed = self.module.observe_runtime_user(deadline=10, monotonic=lambda: 0)
        self.assertEqual(self.module.RuntimeUserObservation(True, True, True), observed)
        self.assertEqual(
            ["systemctl", "is-active", "--quiet", "user@994.service"],
            run.call_args_list[0].args[0],
        )
        self.assertEqual(
            [
                "systemctl",
                "--machine=secpal-runtime@.host",
                "--user",
                "show-environment",
            ],
            run.call_args_list[1].args[0],
        )
        for call in run.call_args_list:
            self.assertIs(subprocess.DEVNULL, call.kwargs["stdout"])
            self.assertIs(subprocess.DEVNULL, call.kwargs["stderr"])

    def test_bus_must_be_a_socket_and_control_is_not_guessed(self) -> None:
        completed = subprocess.CompletedProcess([], 0)
        regular_metadata = mock.Mock(st_mode=stat.S_IFREG | 0o600)
        with mock.patch.object(
            self.module.pwd, "getpwnam", return_value=mock.Mock(pw_uid=994)
        ), mock.patch.object(
            self.module.os, "stat", return_value=regular_metadata
        ), mock.patch.object(
            self.module.subprocess, "run", return_value=completed
        ) as run:
            observed = self.module.observe_runtime_user(deadline=10, monotonic=lambda: 0)
        self.assertEqual(self.module.RuntimeUserObservation(True, False, False), observed)
        self.assertEqual(1, run.call_count)

    def test_sleep_and_each_command_timeout_use_only_the_remaining_budget(self) -> None:
        clock = mock.Mock(side_effect=(0.0, 0.75, 1.0))
        sleeps = []
        observation = self.module.RuntimeUserObservation(False, False, False)
        result = self.module.wait_for_runtime_user(
            lambda _deadline: observation,
            deadline=1.0,
            interval=5.0,
            monotonic=clock,
            sleep=sleeps.append,
        )
        self.assertFalse(result.ready)
        self.assertEqual([0.25], sleeps)

        completed = subprocess.CompletedProcess([], 0)
        socket_metadata = mock.Mock(st_mode=stat.S_IFSOCK | 0o600)
        with mock.patch.object(
            self.module.pwd, "getpwnam", return_value=mock.Mock(pw_uid=994)
        ), mock.patch.object(
            self.module.os, "stat", return_value=socket_metadata
        ), mock.patch.object(
            self.module.subprocess, "run", side_effect=(completed, completed)
        ) as run:
            self.module.observe_runtime_user(
                deadline=60.0,
                monotonic=mock.Mock(side_effect=(59.0, 59.6)),
            )
        self.assertEqual(1.0, run.call_args_list[0].kwargs["timeout"])
        self.assertAlmostEqual(0.4, run.call_args_list[1].kwargs["timeout"])

    def test_publisher_owns_no_target_or_mutating_systemd_operation(self) -> None:
        source = PUBLISHER.read_text(encoding="utf-8")
        for forbidden in (
            "daemon-reload",
            " start ",
            " restart ",
            " stop ",
            "reset-failed",
            "qualify-production-host",
            "Quadlet",
            "pty",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
