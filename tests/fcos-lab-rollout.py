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
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fcos_lab_rollout import (
    LAB_API_PINS,
    AcceptanceRejected, HOSTS, RELEASE_PATHS, Release, RolloutError, SupersededRelease,
    admit_archived_api_only, admit_frontend_only, command_adapter, propose_after_reconciliation, recover, run_rollout, source_release,
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

    def test_discovery_uses_read_back_of_all_hosts_and_never_uses_a_pending_baseline(self):
        repo, archives = Path("/protected/main"), Path("/protected/scanners")
        with patch("fcos_lab_rollout_adapter.admit_proposal_dispatch") as preflight, patch(
            "fcos_lab_proposal.propose_archives"
        ) as propose:
            self.adapter.calls.clear()
            propose_after_reconciliation(repo, NEXT, self.state, self.adapter, archives)
            preflight.assert_not_called()
            propose.assert_not_called()
            propose_after_reconciliation(repo, BASE, self.state, self.adapter, archives)
            preflight.assert_called_once_with(repo, BASE)
            propose.assert_called_once()
            self.assertEqual(self.adapter.calls, [("observe", host, BASE.fingerprint) for host in HOSTS])
            propose.reset_mock()
            self.adapter.current["cx33"] = NEXT.fingerprint
            with self.assertRaisesRegex(RolloutError, "cx33"):
                propose_after_reconciliation(repo, BASE, self.state, self.adapter, archives)
            propose.assert_not_called()

    def test_supersession_prevents_the_first_activation(self):
        def verify(candidate, previous):
            self.assertEqual((candidate, previous), (NEXT, BASE))
            raise RolloutError("protected main advanced")

        with self.assertRaisesRegex(RolloutError, "advanced"):
            run_rollout(NEXT, self.state, self.adapter, BASE, begin=verify)
        self.assertFalse(any(call[0] == "activate" for call in self.adapter.calls))
        self.assertFalse(json.loads(self.state.read_text())["in_flight"])

    def test_clean_superseded_pending_reconciles_and_accepts_a_replacement(self):
        def deferred(*args):
            raise ValueError("wait for fresh evidence")

        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE, component_evidence=deferred)

        def current(candidate, previous):
            if candidate == NEXT:
                raise SupersededRelease("protected main advanced")

        self.adapter.calls.clear()
        self.assertTrue(run_rollout(LATER, self.state, self.adapter, BASE, begin=current))
        status = json.loads(self.state.read_bytes())
        self.assertIsNone(status["pending"])
        self.assertEqual(status["accepted"], asdict(BASE))
        self.assertEqual(self.adapter.calls, [("observe", host, NEXT.fingerprint) for host in HOSTS])
        run_rollout(LATER, self.state, self.adapter, BASE, begin=current)
        self.assertEqual(json.loads(self.state.read_bytes())["accepted"], asdict(LATER))

    def test_arm_preparation_failure_does_not_activate_any_host(self):
        self.adapter.fail = "prepare", "cax21"
        with self.assertRaises(RolloutError):
            run_rollout(NEXT, self.state, self.adapter, BASE)
        self.assertFalse(any(op == "activate" for op, _, _ in self.adapter.calls))
        self.assertEqual(set(self.adapter.current.values()), {BASE.fingerprint})

    def test_missing_publisher_evidence_cannot_prepare_or_change_the_journal(self):
        before = self.state.read_bytes()
        self.adapter.calls.clear()

        def require_evidence(release, previous):
            self.assertEqual((release, previous), (NEXT, BASE))
            raise RolloutError("publisher acceptance unavailable")

        with self.assertRaisesRegex(RolloutError, "acceptance unavailable"):
            run_rollout(NEXT, self.state, self.adapter, BASE, admit=require_evidence)
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.state.read_bytes(), before)

    def test_candidate_guard_rechecks_fresh_predecessor_before_each_switch(self):
        self.adapter.calls.clear()
        guarded = []

        def evidence(host, release, previous):
            self.assertEqual((release, previous), (NEXT, BASE))
            self.assertEqual(self.adapter.calls[-1], ("observe", host, NEXT.fingerprint))
            self.assertEqual(self.adapter.current[host], BASE.fingerprint)
            self.assertFalse(json.loads(self.state.read_text())["in_flight"])
            guarded.append(host)
            return {"installed": {}, "proposed": {}, "previous": {}, "candidate": {},
                    "exposure_unchanged": True}

        with patch("fcos_lab_rollout_adapter.admit_component_update",
                   side_effect=[{}, ValueError("comparison evidence expired")]) as policy:
            with self.assertRaisesRegex(RolloutError, "comparison evidence expired"):
                run_rollout(NEXT, self.state, self.adapter, BASE, component_evidence=evidence)
        self.assertEqual(policy.call_count, 2)
        self.assertIn("observed_at", policy.call_args.kwargs)
        self.assertEqual(guarded, ["cx23", "cx33"])
        self.assertEqual(self.adapter.current, {
            "cx23": NEXT.fingerprint, "cx33": BASE.fingerprint, "cax21": BASE.fingerprint,
        })
        state = json.loads(self.state.read_text())
        self.assertEqual(state["next"], 1)
        self.assertFalse(state["blocked"])
        self.assertFalse(state["in_flight"])

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
        admitted = []
        run_rollout(LATER, self.state, self.adapter, BASE,
                    admit=lambda release, previous: admitted.append((release, previous)))
        self.assertEqual(admitted, [(NEXT, BASE)])
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
    def test_timer_admits_only_the_two_lab_frontend_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args])

            def record():
                git("add", "--all")
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                    "commit", "--quiet", "-m", "Fixture")
                return source_release(repo, git("rev-parse", "HEAD").decode().strip())

            git("init", "--quiet")
            root = Path(__file__).resolve().parents[1]
            for input_path in RELEASE_PATHS:
                files = (root / input_path).glob("*") if (root / input_path).is_dir() else (root / input_path,)
                for source in files:
                    if source.is_file():
                        path = repo / source.relative_to(root)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(source.read_bytes())
            pin = repo / "scripts/integration_runtime_contract.py"
            original = LAB_API_PINS.sub(b"", pin.read_bytes()).decode()
            pin.write_text(original)
            base = record()
            lines = dict(line.split(" = ", 1) for line in original.splitlines()
                         if line.startswith(("LAB_FRONTEND_", "API_DIGEST = ")))
            updated = original.replace(
                f'LAB_FRONTEND_DIGEST = {lines["LAB_FRONTEND_DIGEST"]}',
                f'LAB_FRONTEND_DIGEST = "sha256:{"b" * 64}"',
            ).replace(
                f'LAB_FRONTEND_SOURCE_COMMIT = {lines["LAB_FRONTEND_SOURCE_COMMIT"]}',
                f'LAB_FRONTEND_SOURCE_COMMIT = "{"a" * 40}"',
            )
            pin.write_text(updated)
            frontend = record()
            admit_frontend_only(repo, frontend, base, frontend)
            pin.write_text(updated + 'LAB_FRONTEND_TRANSPORT = "oci-archive-v1"\n')
            archived = record()
            admit_frontend_only(repo, archived, base, archived)
            api = (
                f'LAB_API_SOURCE_COMMIT = "{"a" * 40}"\n'
                f'LAB_API_DIGEST = "sha256:{"b" * 64}"\n'
                f'LAB_PHP_FPM_DIGEST = "sha256:{"c" * 64}"\n'
                f'LAB_API_PAIR_DIGEST = "sha256:{"d" * 64}"\n'
                'LAB_API_VEX_EXPIRES_AT = "2040-01-01T00:00:00Z"\n'
                f'LAB_API_COMPATIBILITY_SHA256 = "{"e" * 64}"\n'
                'LAB_API_TRANSPORT = "oci-archive-v1"\n'
            )
            pin.write_text(original + api)
            archived_api = record()
            admit_archived_api_only(repo, archived_api, base, archived_api)
            pin.write_text(updated + api)
            mixed = record()
            with self.assertRaisesRegex(RolloutError, "unrelated runtime"):
                admit_archived_api_only(repo, mixed, base, mixed)
            for label, changed, extra in (
                ("mixed", updated.replace(lines["API_DIGEST"], f'"sha256:{"c" * 64}"'), None),
                ("backend-only", original.replace(lines["API_DIGEST"], f'"sha256:{"c" * 64}"'), None),
                ("migration", updated, "scripts/production-migrate.php"),
                ("fixture", updated, "scripts/init-local-secrets.sh"),
                ("infrastructure", updated, "config/quadlet/fcos-security/spoe.cfg"),
                ("frontend pin unchanged", updated.replace(
                    f'LAB_FRONTEND_DIGEST = "sha256:{"b" * 64}"',
                    f'LAB_FRONTEND_DIGEST = {lines["LAB_FRONTEND_DIGEST"]}',
                ), None),
            ):
                with self.subTest(label=label):
                    git("checkout", "--quiet", "--detach", frontend.revision)
                    pin.write_text(changed)
                    if extra:
                        with (repo / extra).open("ab") as target:
                            target.write(b"\n# changed\n")
                    rejected = record()
                    with self.assertRaisesRegex(RolloutError, "frontend-only"):
                        admit_frontend_only(repo, rejected, base, rejected)

    def test_denied_pending_candidate_is_not_replaced_or_dispatched(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rollout.json"
            adapter = Adapter()
            run_rollout(BASE, path, adapter, BASE)
            adapter.interrupt = "cx23"
            with self.assertRaises(KeyboardInterrupt):
                run_rollout(NEXT, path, adapter, BASE)
            before = path.read_bytes()
            adapter.calls.clear()

            def admit(release, previous):
                self.assertEqual((release, previous), (NEXT, BASE))
                raise RolloutError("denied pending release")

            with self.assertRaisesRegex(RolloutError, "denied pending"):
                run_rollout(LATER, path, adapter, BASE, admit=admit)
            self.assertEqual(adapter.calls, [])
            self.assertEqual(path.read_bytes(), before)

    def test_timer_service_selects_independent_component_updates(self):
        root = Path(__file__).resolve().parents[1]
        service = root / "config/quadlet/fcos-lab-rollout/secpal-fcos-lab-rollout.service"
        start, = [line for line in service.read_text().splitlines() if line.startswith("ExecStart=")]
        self.assertIn("--component-updates", start.split())

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
