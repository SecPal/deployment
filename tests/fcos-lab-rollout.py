#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Exercise fleet sequencing using an adapter that only models lab operations."""

from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fcos_lab_rollout import (
    AcceptanceRejected, HOSTS, RELEASE_PATHS, Release, RolloutError,
    command_adapter, recover, run_rollout, source_release,
)


BASE = Release("1" * 40, "2" * 64)
NEXT = Release("3" * 40, "4" * 64)
LATER = Release("5" * 40, "6" * 64)


class Adapter:
    def __init__(self):
        self.current = {host: BASE.fingerprint for host in HOSTS}
        self.calls = []
        self.fail = None
        self.interrupt = None

    def __call__(self, operation, host, release, previous):
        self.calls.append((operation, host, release.fingerprint))
        if operation == "prepare" and (operation, host) == self.fail:
            raise RolloutError("preparation failed")
        if operation == "observe":
            return self.current[host]
        if operation == "activate":
            if (operation, host) == self.fail:
                raise RolloutError("activation failed")
            self.current[host] = release.fingerprint
            if host == self.interrupt:
                raise KeyboardInterrupt
        if operation == "accept" and (operation, host) == self.fail:
            raise AcceptanceRejected("acceptance failed")
        if operation == "rollback":
            self.current[host] = previous.fingerprint
        return None


class RolloutTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name) / "rollout.json"
        self.adapter = Adapter()
        run_rollout(BASE, self.state, self.adapter, BASE)

    def test_stages_entire_fleet_then_updates_one_host_at_a_time(self):
        self.adapter.calls.clear()
        run_rollout(NEXT, self.state, self.adapter, BASE)
        calls = [(op, host) for op, host, _ in self.adapter.calls]
        self.assertEqual([host for op, host in calls if op == "prepare"], list(HOSTS))
        self.assertLess(calls.index(("prepare", "cax21")), calls.index(("activate", "cx23")))
        for host, successor in zip(HOSTS, tuple(HOSTS)[1:]):
            self.assertLess(calls.index(("accept", host)), calls.index(("activate", successor)))
        self.adapter.calls.clear()
        run_rollout(Release("7" * 40, NEXT.fingerprint), self.state, self.adapter, BASE)
        self.assertEqual(self.adapter.calls, [])

    def test_arm_preparation_failure_does_not_activate_any_host(self):
        self.adapter.fail = "prepare", "cax21"
        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        self.assertFalse(any(op == "activate" for op, _, _ in self.adapter.calls))
        self.assertEqual(set(self.adapter.current.values()), {BASE.fingerprint})

    def test_failed_acceptance_rolls_back_and_blocks_later_revisions(self):
        self.adapter.fail = "accept", "cx33"
        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        self.assertEqual(self.adapter.current["cx23"], NEXT.fingerprint)
        self.assertEqual(self.adapter.current["cx33"], BASE.fingerprint)
        self.assertEqual(self.adapter.current["cax21"], BASE.fingerprint)
        self.assertIn(("rollback", "cx33", NEXT.fingerprint), self.adapter.calls)
        self.assertTrue(json.loads(self.state.read_text())["blocked"])
        self.adapter.calls.clear()
        with self.assertRaises(RolloutError):
            run_rollout(LATER, self.state, self.adapter, BASE)
        self.assertEqual(self.adapter.calls, [])

    def test_recovery_requires_reconciled_baseline_and_preserves_blocked_journal(self):
        self.adapter.fail = "accept", "cx33"
        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        original = self.state.read_bytes()
        with self.assertRaises(RolloutError):
            recover(self.state, BASE, self.adapter)
        self.assertEqual(self.state.read_bytes(), original)
        self.adapter.current["cx23"] = BASE.fingerprint
        recover(self.state, BASE, self.adapter)
        archives = list(self.state.parent.glob("blocked-*/rollout.json"))
        self.assertEqual([archive.read_bytes() for archive in archives], [original])
        self.assertFalse(json.loads(self.state.read_text())["blocked"])

    def test_interrupt_after_activation_resumes_original_release_from_readback(self):
        self.adapter.interrupt = "cx33"
        with self.assertRaises(KeyboardInterrupt):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        self.adapter.interrupt = None
        self.adapter.calls.clear()
        run_rollout(LATER, self.state, self.adapter, BASE)
        self.assertNotIn(("activate", "cx33", NEXT.fingerprint), self.adapter.calls)
        self.assertIn(("accept", "cx33", NEXT.fingerprint), self.adapter.calls)
        self.assertEqual(set(self.adapter.current.values()), {NEXT.fingerprint})
        run_rollout(LATER, self.state, self.adapter, BASE)
        self.assertEqual(set(self.adapter.current.values()), {LATER.fingerprint})

    def test_malformed_state_never_reaches_adapter(self):
        state = json.loads(self.state.read_text())
        state["next"] = 400
        self.state.write_text(json.dumps(state))
        self.adapter.calls.clear()
        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        self.assertEqual(self.adapter.calls, [])

    def test_ambiguous_interruption_requires_operator_reconciliation(self):
        self.adapter.fail = "activate", "cx23"
        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        self.assertNotIn(("rollback", "cx23", NEXT.fingerprint), self.adapter.calls)
        self.assertEqual(self.adapter.current["cx33"], BASE.fingerprint)

    def test_completed_checkpoint_needs_readback_before_accepting(self):
        state = json.loads(self.state.read_text())
        state.update(pending=asdict(NEXT), next=len(HOSTS))
        self.state.write_text(json.dumps(state))
        self.adapter.calls.clear()
        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        self.assertEqual(json.loads(self.state.read_text())["accepted"], asdict(BASE))
        self.adapter.current = dict.fromkeys(HOSTS, NEXT.fingerprint)
        self.adapter.calls.clear()
        run_rollout(NEXT, self.state, self.adapter, BASE)
        self.assertEqual(
            self.adapter.calls,
            [("observe", host, NEXT.fingerprint) for host in HOSTS],
        )
        self.assertEqual(json.loads(self.state.read_text())["accepted"], asdict(NEXT))

    def test_initial_admission_does_not_install_on_a_mismatched_host(self):
        self.state.unlink()
        self.adapter.calls.clear()
        self.adapter.current["cx23"] = LATER.fingerprint
        with self.assertRaises(RolloutError):
            run_rollout(BASE, self.state, self.adapter, BASE)
        self.assertFalse(self.state.exists())
        self.assertTrue(all(op == "observe" for op, _, _ in self.adapter.calls))


class SourceAndProtocolTest(unittest.TestCase):
    def test_only_release_input_changes_change_the_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args])

            def commit():
                git("add", "--all")
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                    "commit", "--quiet", "-m", "Fixture")
                return git("rev-parse", "HEAD").decode().strip()

            git("init", "--quiet")
            for source in RELEASE_PATHS:
                path = repo / source
                if source.endswith("fcos-security"):
                    path /= "config.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("base")
            first = source_release(repo, commit())
            (repo / "README.md").write_text("documentation")
            self.assertEqual(source_release(repo, commit()).fingerprint, first.fingerprint)
            (repo / "scripts/integration_runtime_contract.py").write_text("updated image")
            image_update = source_release(repo, commit())
            self.assertNotEqual(image_update.fingerprint, first.fingerprint)
            (repo / "config/quadlet/fcos-security/config.yaml").write_text("changed")
            self.assertNotEqual(source_release(repo, commit()).fingerprint, image_update.fingerprint)
            (repo / "scripts/integration_runtime_contract.py").unlink()
            with self.assertRaises(RolloutError):
                source_release(repo, commit())

    def test_adapter_receives_literal_arguments_and_bounded_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            adapter = Path(directory) / "adapter"
            adapter.write_text(
                "#!/bin/sh\n"
                '[ "$2:$3" = "cax21:linux/arm64" ] || exit 1\n'
                'case "$1" in\n'
                'observe) printf "%s\\n" "$7";;\n'
                'accept) exit 10;;\n'
                'prepare) printf "unexpected output";;\n'
                'esac\n'
            )
            adapter.chmod(0o700)
            call = command_adapter(adapter)
            self.assertEqual(call("observe", "cax21", NEXT, BASE), BASE.fingerprint)
            with self.assertRaises(AcceptanceRejected):
                call("accept", "cax21", NEXT, BASE)
            with self.assertRaises(RolloutError):
                call("prepare", "cax21", NEXT, BASE)
            adapter.write_text('#!/bin/sh\nprintf "%s\\nextra" "$7"\n')
            with self.assertRaises(RolloutError):
                call("observe", "cax21", NEXT, BASE)


if __name__ == "__main__":
    unittest.main()
