#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Exercise delivery with source records and a transport that never reaches GitHub."""

import base64
import runpy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import opentofu_delivery as delivery
from opentofu_delivery import (APP, REQUIRED, Rejected, candidate_ref, merge_ready,
                               render_intent, read_intent, require_installation)

RECONCILIATION_FIXTURES = runpy.run_path(str(Path(__file__).with_name("opentofu-reconciliation.py")))
SourceGitHub = RECONCILIATION_FIXTURES["GitHub"]
lock = RECONCILIATION_FIXTURES["lock"]
hashes = RECONCILIATION_FIXTURES["hashes"]
BASE = RECONCILIATION_FIXTURES["BASE"]
DO = RECONCILIATION_FIXTURES["DO"]
ACTOR = {"login": f"{APP}[bot]", "id": 198000000, "type": "Bot"}
REPAIR = "d" * 40
TREE = "e" * 40


class Writer(SourceGitHub):
    def __init__(self):
        super().__init__()
        self.writes = []
        self.head = self.add(463, "digitalocean", DO, "2.107.0", "2.108.0")
        self.report, self.files = delivery.RECONCILE.reconcile(
            self.get, 463, self.head, BASE,
            lambda source, version: lock(source, version, version, hashes(source, 30)),
        )
        self.intent = {key: self.report[key] for key in delivery.FIELDS}
        self.ref = candidate_ref(self.intent)
        self.routes[f"git/matching-refs/heads/{self.ref}"] = []
        self.fail_signature = False

    def write(self, action, payload):
        self.writes.append((action, payload))
        if action == "ref":
            self.routes[f"git/matching-refs/heads/{self.ref}"] = [
                {"ref": payload["ref"], "object": {"sha": payload["sha"]}},
            ]
            return payload["sha"]
        if action == "commit":
            assert payload["branch"]["repositoryNameWithOwner"] == delivery.REPO
            assert payload["branch"]["branchName"] == self.ref
            assert payload["expectedHeadOid"] == BASE
            assert set(payload["message"]) == {"headline", "body"}
            self.routes[f"git/trees/{TREE}?recursive=1"] = {"truncated": False, "tree": []}
            paths = []
            for item in payload["fileChanges"]["additions"]:
                self.set_file(TREE, item["path"], base64.b64decode(item["contents"]).decode())
                paths.append({"filename": item["path"], "status": "modified"})
            message = payload["message"]["headline"] + "\n\n" + payload["message"]["body"]
            author = f'{ACTOR["id"]}+{ACTOR["login"]}@users.noreply.github.com'
            signed_payload = (f"tree {TREE}\nparent {BASE}\nauthor {ACTOR['login']} <{author}> 1795340656 +0000\n"
                              f"committer GitHub <noreply@github.com> 1795340656 +0000\n\n{message}\n")
            verification = {"verified": not self.fail_signature, "reason": "valid", "payload": signed_payload}
            self.routes[f"commits/{REPAIR}"] = {
                "sha": REPAIR, "parents": [{"sha": BASE}], "author": ACTOR, "files": paths,
                "commit": {"message": message, "tree": {"sha": TREE}, "verification": verification},
            }
            self.routes[f"commit-signature/{REPAIR}"] = {
                "oid": REPAIR, "signature": {"isValid": True, "state": "VALID", "wasSignedByGitHub": True},
            }
            self.routes[f"git/matching-refs/heads/{self.ref}"][0]["object"]["sha"] = REPAIR
            return REPAIR
        assert action == "pull"
        repository = {"full_name": delivery.REPO}
        pr = {"number": 484, "user": ACTOR, "state": "open", "commits": 1, "draft": False,
              "head": {"ref": payload["head"], "sha": REPAIR, "repo": repository},
              "base": {"ref": payload["base"], "repo": repository}}
        self.open.append(pr)
        self.routes["pulls/484"] = pr
        return {"number": 484}

    def deliver(self, files=None):
        return delivery.deliver(self.get, self.write, self.intent, self.files if files is None else files, ACTOR)



class DeliveryContract(unittest.TestCase):
    def setUp(self):
        self.intent = {"base": "a" * 40, "source": "hashicorp/google", "version": "8.12.0",
                       "proposals": [{"number": 461, "head": "b" * 40},
                                     {"number": 462, "head": "c" * 40}]}

    def test_signed_intent_and_dedicated_ref_are_deterministic(self):
        self.assertEqual(read_intent(render_intent(self.intent)), self.intent)
        ref = candidate_ref(self.intent)
        self.assertRegex(ref, r"^automation/opentofu/google/[0-9a-f]{64}$")
        self.assertNotEqual(ref, candidate_ref(dict(self.intent, base="d" * 40)))

    def test_ref_rejects_versions_and_fields_outside_the_contract(self):
        for bad in (dict(self.intent, source="example/other"), dict(self.intent, version="8.12.0-rc.1"),
                    dict(self.intent, base="../main"), dict(self.intent, application=APP)):
            with self.subTest(bad=bad), self.assertRaises(Rejected):
                read_intent(render_intent(bad))

    def test_installation_requires_exact_app_and_single_repository(self):
        approved = {"total_count": 1, "repositories": [{"full_name": "SecPal/deployment"}]}
        require_installation(APP, approved)
        for slug, access in (("secpal-controller", approved),
                             (APP, dict(approved, total_count=2)),
                             (APP, dict(approved, repositories=[{"full_name": "SecPal/api"}]))):
            with self.subTest(slug=slug, access=access), self.assertRaises(Rejected):
                require_installation(slug, access)

    def test_enrollment_requires_exact_head_and_successful_required_checks(self):
        head = "b" * 40
        pr = {"headRefOid": head, "baseRefOid": self.intent["base"], "mergeStateStatus": "CLEAN"}
        checks = [{"name": name, "bucket": "pass"} for name in sorted(REQUIRED)]
        self.assertTrue(merge_ready(pr, head, self.intent["base"], checks))
        for changed, observed in ((dict(pr, headRefOid="c" * 40), checks),
                                  (dict(pr, mergeStateStatus="BLOCKED"), checks),
                                  (pr, checks[:-1]), (pr, checks + [checks[0]]),
                                  (pr, [dict(checks[0], bucket="cancel")] + checks[1:])):
            with self.subTest(changed=changed, observed=observed):
                self.assertFalse(merge_ready(changed, head, self.intent["base"], observed))


class SignedWriterTests(unittest.TestCase):
    def test_signed_read_back_precedes_pr_creation_and_retry_is_idempotent(self):
        github = Writer()
        self.assertEqual(github.deliver(), 484)
        self.assertEqual([kind for kind, _ in github.writes], ["ref", "commit", "pull"])
        self.assertEqual(github.deliver(), 484)
        self.assertEqual(len(github.writes), 3)
        # The verifier compares independently reproduced bytes to the actual
        # signed Git blob, even when GitHub reports a verified App signature.
        file = next(iter(github.files))
        github.set_file(TREE, file, github.files[file] + "unauthorized edit")
        with self.assertRaisesRegex(Rejected, "differ from independent"):
            delivery.repair_commit(github.get, REPAIR, ACTOR, github.files)

    def test_unsigned_write_never_opens_a_pull_request(self):
        github = Writer()
        github.fail_signature = True
        with self.assertRaisesRegex(Rejected, "signature"):
            github.deliver()
        self.assertEqual([kind for kind, _ in github.writes], ["ref", "commit"])

    def test_concurrent_ref_change_blocks_pr_creation(self):
        github = Writer()

        def write(action, payload):
            result = github.write(action, payload)
            if action == "commit":
                github.routes[f"git/matching-refs/heads/{github.ref}"][0]["object"]["sha"] = "f" * 40
            return result

        with self.assertRaisesRegex(Rejected, "branch changed"):
            delivery.deliver(github.get, write, github.intent, github.files, ACTOR)
        self.assertEqual([kind for kind, _ in github.writes], ["ref", "commit"])

    def test_changed_base_or_proposal_and_unexpected_paths_prevent_writes(self):
        for invalid in ("base", "proposal", "paths"):
            github = Writer()
            files = dict(github.files)
            if invalid == "base":
                github.routes["branches/main"]["commit"]["sha"] = "b" * 40
            elif invalid == "proposal":
                github.routes["pulls/463"]["head"]["sha"] = "c" * 40
            else:
                files[".github/workflows/local-integration.yml"] = "unexpected"
            with self.subTest(invalid=invalid), self.assertRaises(Rejected):
                github.deliver(files)
            self.assertEqual(github.writes, [])

    def test_independently_owned_overlapping_repair_defers_all_writes(self):
        github = Writer()
        github.open.append({"number": 480, "user": {"login": "maintainer"}, "head": {"sha": "f" * 40,
                                                                                   "ref": "maintainer/repair"}})
        github.routes["pulls/480/files?per_page=100"] = [{"filename": next(iter(github.files))}]
        with self.assertRaises(delivery.Deferred):
            github.deliver()
        self.assertEqual(github.writes, [])

    def test_app_credential_is_specific_to_the_writer_after_reconciliation(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/opentofu-reconciliation.yml").read_text()
        writer, _, verifier = workflow.partition("  admission:\n")
        secret = "secrets.OPENTOFU_RECONCILER_PRIVATE_KEY"
        self.assertEqual(workflow.count(secret), 1)
        self.assertLess(writer.index("opentofu_delivery.py prepare"), writer.index(secret))
        self.assertIn("GH_TOKEN: ${{ steps.app.outputs.token }}", writer)
        self.assertIn("GH_TOKEN: ${{ github.token }}", verifier)
        self.assertNotIn("steps.app.outputs", verifier)
        self.assertIn("ref: ${{ github.sha }}", writer)
        self.assertIn("pull_request_target:", workflow)

    def test_protected_checks_control_automatic_merge_and_app_cannot_self_admit(self):
        github = Writer()
        github.deliver()
        transport = delivery.GitHub("gh")
        transport.get = github.get
        pr = {"headRefOid": REPAIR, "baseRefOid": BASE, "mergeStateStatus": "CLEAN"}
        checks = [{"name": name, "bucket": "pass"} for name in sorted(REQUIRED)]
        calls = []

        def call(args, stage, **kwargs):
            calls.append(args)
            if args[:2] == ["pr", "view"]:
                return render_intent(pr)
            if args[:2] == ["pr", "checks"]:
                return render_intent(checks)
            self.assertEqual(args[-1], REPAIR)
            self.assertNotIn("--admin", args)
            return ""

        transport.call = call
        transport.merge(484, github.intent, REPAIR, ACTOR)
        self.assertEqual(calls[-1][:2], ["pr", "merge"])
        self.assertIn("--auto", calls[-1])
        checks.pop()
        calls.clear()
        transport.merge(484, github.intent, REPAIR, ACTOR)
        self.assertEqual(len(calls), 2)
        with self.assertRaisesRegex(Rejected, "signature"):
            delivery.repair_commit(github.get, REPAIR, dict(ACTOR, id=12), github.files)


if __name__ == "__main__":
    unittest.main()
