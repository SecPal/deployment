#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""#170 conformance: synthetic provider, real disposable SQLite CAS/processes."""
from dataclasses import asdict, replace
import json
import multiprocessing
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import endpoint_switch as contract


def connection(path):
    return sqlite3.connect(path, timeout=5)


class Owner:
    """Synthetic #131 authority; this is not GREEN/writer qualification."""
    def __init__(self, path, approved, *, writes=False):
        self.path, self.approved, self.writes = path, approved, writes

    def authorize(self, plan):
        if (plan not in self.approved or
                (plan.intent is contract.Intent.PRE_WRITE_REVERSAL and self.writes)):
            raise PermissionError("synthetic admission denied")

    def claim_dispatch(self, plan):
        self.authorize(plan)
        binding = json.dumps(asdict(plan), sort_keys=True)
        with connection(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT binding FROM attempts WHERE operation = ?",
                             (plan.operation_id,)).fetchone()
            if row:
                if row[0] != binding:
                    raise PermissionError("operation identity reused")
                return False
            db.execute("INSERT INTO attempts VALUES (?, ?)", (plan.operation_id, binding))
            return True


class SQLiteAdapter:
    """Test-only native conditional routing register, not a cloud/DNS adapter."""
    def __init__(self, path, endpoint, *, mode="normal", barrier=None):
        self.path, self.endpoint = path, endpoint
        self.mode, self.barrier, self.calls = mode, barrier, 0

    def observe(self, endpoint):
        with connection(self.path) as db:
            row = db.execute("SELECT generation, target, exposure, operation FROM routing").fetchone()
        return contract.RoutingState(self.endpoint, str(row[0]), row[1], row[2], row[3])

    def validate(self, plan):
        if plan.before.endpoint != self.endpoint or plan.target not in {"blue", "green", "green-alt"}:
            raise PermissionError("not an admitted provider target")

    def compare_and_switch(self, plan):
        self.calls += 1
        if self.barrier:
            self.barrier.wait(timeout=10)
        if self.mode == "ambiguous":
            return contract.Mutation.UNKNOWN
        with connection(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE routing SET generation=generation+1,target=?,operation=? "
                "WHERE generation=? AND target=? AND exposure=?",
                (plan.target, plan.operation_id, int(plan.before.generation),
                 plan.before.target, plan.before.exposure_sha256),
            ).rowcount
            if self.mode == "interrupted":
                db.rollback()
                raise TimeoutError("private transport detail must not enter evidence")
        if self.mode == "lost-ack":
            raise TimeoutError("private transport detail must not enter evidence")
        if self.mode == "bad-response":
            return {"success": True}
        if self.mode == "readback-mismatch":
            with connection(self.path) as db:
                db.execute("UPDATE routing SET target='green-alt',generation=generation+1,operation='other'")
        return contract.Mutation.APPLIED if changed else contract.Mutation.REJECTED


def concurrent_switch(path, endpoint, plan, barrier, outcomes):
    adapter = SQLiteAdapter(path, endpoint, barrier=barrier)
    owner = Owner(path, [plan])
    result = contract.execute(plan, adapter, adapter, owner)
    outcomes.put((result.outcome.value, adapter.calls))


class EndpointSwitchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="secpal-endpoint-")
        self.addCleanup(self.temporary.cleanup)
        self.path = str(Path(self.temporary.name) / "routing.sqlite")
        self.endpoint = contract.Endpoint(
            "deployment-fixture",
            contract.ResourceTarget("provider-fixture", "project-fixture", "viewer", "endpoint-1"),
        )
        with connection(self.path) as db:
            db.executescript(
                "CREATE TABLE routing (generation INTEGER, target TEXT, exposure TEXT, operation TEXT);"
                "CREATE TABLE attempts (operation TEXT PRIMARY KEY, binding TEXT NOT NULL);"
                "CREATE TABLE writer (authority TEXT); INSERT INTO writer VALUES ('none');"
            )
            db.execute("INSERT INTO routing VALUES (1,'blue',?,NULL)", ("a" * 64,))
        self.adapter = SQLiteAdapter(self.path, self.endpoint)
        self.before = self.adapter.observe(self.endpoint)
        self.plan = contract.plan("operation-1", self.before, "green")
        self.owner = Owner(self.path, [self.plan])

    def execute(self, plan=None, adapter=None, owner=None, observer=None):
        return contract.execute(
            plan or self.plan, adapter or self.adapter, observer or adapter or self.adapter,
            owner or self.owner,
        )

    def test_current_observation_plan_apply_and_independent_readback(self):
        self.assertEqual(1, contract.CONTRACT_VERSION)
        self.assertEqual(self.before, contract.inspect(self.endpoint, self.adapter))
        result = self.execute()
        self.assertEqual(contract.Outcome.APPLIED, result.outcome)
        self.assertEqual("green", result.observed.target)
        self.assertEqual(self.before.exposure_sha256, result.observed.exposure_sha256)
        self.assertNotEqual(self.before.generation, result.observed.generation)
        self.assertEqual(1, self.adapter.calls)

    def test_wrong_deployment_resource_generation_and_target_never_mutate(self):
        wrong_endpoint = replace(self.endpoint, deployment_id="another-deployment")
        wrong_resource = replace(self.endpoint, resource=replace(
            self.endpoint.resource, provider_resource_id="unrelated-endpoint"))
        cases = [
            replace(self.plan, before=replace(self.before, endpoint=wrong_endpoint)),
            replace(self.plan, before=replace(self.before, endpoint=wrong_resource)),
            replace(self.plan, before=replace(self.before, generation="stale")),
            replace(self.plan, target="unadmitted"),
        ]
        for plan in cases:
            with self.subTest(plan=plan):
                result = self.execute(plan=plan, owner=Owner(self.path, [plan]))
                self.assertEqual(contract.Outcome.REJECTED, result.outcome)
        self.assertEqual(0, self.adapter.calls)
        self.assertEqual(self.before, self.adapter.observe(self.endpoint))
        class PermissiveOwner:
            def authorize(self, request):
                return None
        self.assertEqual(contract.Outcome.REJECTED,
                         contract.reconcile(None, self.adapter, PermissiveOwner()).outcome)
        self.assertEqual(contract.Outcome.REJECTED,
                         contract.assess(None, contract.Mutation.UNKNOWN, self.before).outcome)

    def test_reachable_target_does_not_replace_cutover_admission(self):
        result = self.execute(owner=Owner(self.path, []))
        self.assertEqual(contract.Outcome.REJECTED, result.outcome)
        self.assertEqual("endpoint-cutover-admission", result.diagnostic)
        self.assertEqual(0, self.adapter.calls)

    def test_lost_ack_is_reconciled_and_committed_repeat_never_dispatches(self):
        adapter = SQLiteAdapter(self.path, self.endpoint, mode="lost-ack")
        self.assertEqual(contract.Outcome.APPLIED, self.execute(adapter=adapter).outcome)
        restarted = SQLiteAdapter(self.path, self.endpoint)
        result = self.execute(adapter=restarted)
        self.assertEqual(contract.Outcome.ALREADY_SATISFIED, result.outcome)
        self.assertEqual(0, restarted.calls)
        self.assertEqual(contract.Outcome.ALREADY_SATISFIED,
                         contract.reconcile(self.plan, restarted, self.owner).outcome)

    def test_interruption_and_ambiguous_response_never_allow_blind_redispatch(self):
        for mode in ("interrupted", "ambiguous"):
            with self.subTest(mode=mode):
                adapter = SQLiteAdapter(self.path, self.endpoint, mode=mode)
                request = replace(self.plan, operation_id="operation-" + mode)
                owner = Owner(self.path, [request])
                result = self.execute(plan=request, adapter=adapter, owner=owner)
                self.assertEqual(1, adapter.calls)
                self.assertEqual(contract.Outcome.UNCERTAIN, result.outcome)
                self.assertNotIn("private transport", result.diagnostic)
                self.assertEqual(self.before, adapter.observe(self.endpoint))
                restarted = SQLiteAdapter(self.path, self.endpoint)
                self.assertEqual(contract.Outcome.UNCERTAIN, self.execute(plan=request, adapter=restarted, owner=owner).outcome)
                self.assertEqual(0, restarted.calls)
                self.assertEqual(contract.Outcome.UNCERTAIN,
                                 contract.reconcile(request, restarted, owner).outcome)

    def test_malformed_ack_uses_readback_but_mismatch_never_becomes_success(self):
        self.assertEqual(contract.Outcome.APPLIED,
                         self.execute(adapter=SQLiteAdapter(
                             self.path, self.endpoint, mode="bad-response")).outcome)
        reverse = contract.plan("operation-2", self.adapter.observe(self.endpoint), "blue",
                                intent=contract.Intent.PRE_WRITE_REVERSAL)
        result = self.execute(plan=reverse, owner=Owner(self.path, [reverse]),
                              adapter=SQLiteAdapter(self.path, self.endpoint, mode="readback-mismatch"))
        self.assertEqual(contract.Outcome.RECOVERY_REQUIRED, result.outcome)

    def test_observation_failure_does_not_publish_or_disclose_provider_errors(self):
        class Broken:
            def observe(self, endpoint):
                raise OSError("PRIVATE_PROVIDER_SECRET")
        result = self.execute(observer=Broken())
        self.assertEqual(contract.Outcome.UNCERTAIN, result.outcome)
        self.assertNotIn("PRIVATE_PROVIDER_SECRET", repr(result))
        self.assertEqual(0, self.adapter.calls)
        adapter = self.adapter
        class LostReadback:
            calls = 0
            def observe(self, endpoint):
                self.calls += 1
                if self.calls > 1:
                    raise OSError("PRIVATE_PROVIDER_SECRET")
                return adapter.observe(endpoint)
        result = self.execute(observer=LostReadback())
        self.assertEqual(contract.Outcome.UNCERTAIN, result.outcome)
        self.assertEqual(1, self.adapter.calls)
        self.assertEqual(contract.Outcome.ALREADY_SATISFIED,
                         contract.reconcile(self.plan, self.adapter, self.owner).outcome)

    def test_changed_exposure_and_uncorrelated_routes_require_recovery(self):
        for changes in (
            {"exposure_sha256": "b" * 64},
            {"operation_id": None},
            {"generation": self.before.generation},
        ):
            with self.subTest(changes=changes):
                state = replace(self.before, target="green", generation="2", operation_id="operation-1")
                state = replace(state, **changes)
                class Readback:
                    def observe(self, endpoint):
                        return state
                self.assertEqual(contract.Outcome.RECOVERY_REQUIRED,
                                 contract.reconcile(self.plan, Readback(), self.owner).outcome)

    def test_pre_write_reversal_requires_fresh_owner_and_post_write_denies_it(self):
        self.execute()
        reverse = contract.plan("reverse-1", self.adapter.observe(self.endpoint), "blue",
                                intent=contract.Intent.PRE_WRITE_REVERSAL)
        owner = Owner(self.path, [reverse], writes=True)
        self.assertEqual(contract.Outcome.REJECTED, self.execute(plan=reverse, owner=owner).outcome)
        disguised = replace(reverse, intent=contract.Intent.SWITCH)
        self.assertEqual(contract.Outcome.REJECTED, self.execute(plan=disguised, owner=owner).outcome)
        owner.writes = False
        self.assertEqual(contract.Outcome.APPLIED, self.execute(plan=reverse, owner=owner).outcome)
        self.assertEqual("blue", self.adapter.observe(self.endpoint).target)
        calls = self.adapter.calls
        self.assertEqual(contract.Outcome.REJECTED, self.execute().outcome)
        self.assertEqual(calls, self.adapter.calls)

    def test_endpoint_switch_never_creates_writer_authority(self):
        self.execute()
        with connection(self.path) as db:
            self.assertEqual("none", db.execute("SELECT authority FROM writer").fetchone()[0])

    def test_two_independent_publishers_cannot_commit_competing_targets(self):
        context = multiprocessing.get_context("fork")
        barrier, outcomes = context.Barrier(2), context.Queue()
        other = replace(self.plan, operation_id="operation-2", target="green-alt")
        workers = [context.Process(target=concurrent_switch,
                                   args=(self.path, self.endpoint, plan, barrier, outcomes))
                   for plan in (self.plan, other)]
        try:
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=15)
                self.assertEqual(0, worker.exitcode)
            results = [outcomes.get(timeout=3)[0] for _ in workers]
            self.assertCountEqual(["applied", "rejected"], results)
            self.assertEqual("2", self.adapter.observe(self.endpoint).generation)
        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=3)
            outcomes.close()

    def test_operation_id_cannot_be_rebound_and_adapter_rejection_is_terminal(self):
        self.owner.claim_dispatch(self.plan)
        altered = replace(self.plan, target="green-alt")
        result = self.execute(plan=altered, owner=Owner(self.path, [altered]))
        self.assertEqual(contract.Outcome.UNCERTAIN, result.outcome)
        self.assertEqual(0, self.adapter.calls)
        result = contract.assess(self.plan, contract.Mutation.REJECTED, self.before)
        self.assertEqual(contract.Outcome.REJECTED, result.outcome)


if __name__ == "__main__":
    unittest.main()
