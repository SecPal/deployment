#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

import base64
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import asdict
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fcos_lab_proposal import (
    FILE, Proposal, evidence_agrees, proposed_file, candidate, main, publish, publisher_archive, write,
)
from fcos_lab_rollout_adapter import Frontend

OLD = Frontend("sha256:" + "1" * 64, "2" * 40)
NEW = Frontend("sha256:" + "3" * 64, "4" * 40)
CHILDREN = {"linux/amd64": "sha256:" + "5" * 64, "linux/arm64": "sha256:" + "6" * 64}
PROPOSAL = Proposal(NEW.index, NEW.source, 12, 2, CHILDREN["linux/amd64"],
                    CHILDREN["linux/arm64"], "sha256:" + "7" * 64)
BASE = "8" * 40
WRITE_TOKEN_ENV = "FCOS_FRONTEND_PROPOSAL_WRITE_TOKEN"
WRITE_TOKEN = "dedicated-write"
SOURCE = (f'FRONTEND_DIGEST = "{OLD.index}"\n'
          f'LAB_FRONTEND_DIGEST = "{OLD.index}"\nLAB_FRONTEND_SOURCE_COMMIT = "{OLD.source}"\n')


class ProposalContract(unittest.TestCase):
    def test_only_ahead_and_different_can_be_proposed(self):
        case = {"source_commit": NEW.source, "run_id": 12, "run_attempt": 2}
        for state in ("identical", "behind", "diverged"):
            self.assertIsNone(candidate(dict(case, source_relationship=state), OLD))
        with patch("fcos_lab_proposal.verify_publication", return_value=PROPOSAL):
            self.assertEqual(candidate(dict(case, source_relationship="ahead"), OLD), PROPOSAL)
            self.assertIsNone(candidate(dict(case, source_relationship="ahead"), NEW))
        wrong = Proposal(OLD.index, NEW.source, 12, 2, PROPOSAL.amd64, PROPOSAL.arm64, PROPOSAL.evidence)
        with patch("fcos_lab_proposal.verify_publication", return_value=wrong):
            self.assertIsNone(candidate(dict(case, source_relationship="ahead"), OLD))

    def test_edits_only_the_existing_lab_pair(self):
        text = proposed_file(SOURCE, PROPOSAL)
        self.assertIn(f'FRONTEND_DIGEST = "{OLD.index}"\n', text)
        self.assertIn(f'LAB_FRONTEND_DIGEST = "{NEW.index}"\n', text)
        self.assertNotIn(OLD.source, text)
        with self.assertRaises(ValueError):
            proposed_file(SOURCE + SOURCE, PROPOSAL)

    def test_signed_evidence_requires_exact_both_native_subjects_and_clean_scans(self):
        scan_digest = "sha256:" + "a" * 64
        doc = {"schema_version": "secpal-trivy-repository-scan-v5", "gate_state": "CLEAN",
               "subject": {"repository": "SecPal/frontend", "commit": NEW.source},
               "operation": {"name": "TRIVY_REPOSITORY_SCAN", "status": "SUCCEEDED"},
               "database": {"status": "FRESH"}}
        source = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        evidence = {
            "schema_version": "1.0.0",
            "subject": {"repository": "ghcr.io/secpal/frontend", "index_digest": NEW.index,
                        "platforms": [{"platform": arch, "manifest_digest": digest, "user": "101:101"}
                                      for arch, digest in CHILDREN.items()]},
            "workflow": {"repository": "SecPal/frontend", "path": ".github/workflows/publish-container.yml",
                         "run_id": "12", "run_attempt": "2", "commit": NEW.source},
            "source": {"repository": "https://github.com/SecPal/frontend", "commit": NEW.source},
            "extensions": {"https://github.com/SecPal/frontend": {
                "source_security_sha256": "sha256:" + hashlib.sha256(source).hexdigest()}},
            "sboms": [{"platform": arch, "subject_digest": digest, "spdx_sha256": scan_digest}
                      for arch, digest in CHILDREN.items()],
            "scans": [{"scanner": scanner, "platform": arch, "subject_digest": subject,
                       "status": "SUCCEEDED", "policy_result": "CLEAN"}
                      for arch, digest in CHILDREN.items()
                      for scanner, subject in (("grype", scan_digest), ("trivy", digest))],
            "smoke_tests": [{"platform": arch, "digest": digest, "runner_architecture": arch.split("/")[1],
                             "workflow_run_id": "12", "workflow_run_attempt": "2", "result": "SUCCEEDED"}
                            for arch, digest in CHILDREN.items()],
        }
        evidence_agrees(evidence, doc, PROPOSAL)
        for key, change in (("scans", lambda rows: rows[0].update(policy_result="ACTIONABLE")),
                            ("smoke_tests", lambda rows: rows.pop()),
                            ("subject", lambda row: row["platforms"][0].update(user="root")),
                            ("workflow", lambda row: row.update(run_attempt="3"))):
            with self.subTest(key=key):
                altered = deepcopy(evidence)
                change(altered[key])
                with self.assertRaises(ValueError):
                    evidence_agrees(altered, doc, PROPOSAL)
        for key, value in (("schema_version", "unknown"),
                           ("operation", {"name": "TRIVY_REPOSITORY_SCAN", "status": "FAILED"}),
                           ("database", {"status": "STALE"})):
            with self.subTest(key=key):
                source = dict(doc, **{key: value})
                updated = deepcopy(evidence)
                source_bytes = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
                updated["extensions"]["https://github.com/SecPal/frontend"]["source_security_sha256"] = (
                    "sha256:" + hashlib.sha256(source_bytes).hexdigest()
                )
                with self.assertRaises(ValueError):
                    evidence_agrees(updated, source, PROPOSAL)

    def test_closed_candidate_pr_and_changed_base_cannot_write(self):
        with patch("fcos_lab_proposal.get", return_value={"object": {"sha": "9" * 40}}), \
                patch("fcos_lab_proposal.write") as writer:
            self.assertEqual(publish(PROPOSAL, BASE, SOURCE, token=WRITE_TOKEN), "base changed")
            writer.assert_not_called()
        with patch("fcos_lab_proposal.get", side_effect=[
            {"object": {"sha": BASE}}, [{"number": 33, "state": "closed", "head": {
                "ref": "fcos-lab-frontend-" + NEW.index.removeprefix("sha256:") + "-" + OLD.source,
                "repo": {"full_name": "SecPal/deployment"},
            }}],
        ]) as reader, patch("fcos_lab_proposal.write") as writer:
            self.assertEqual(publish(PROPOSAL, BASE, SOURCE, token=WRITE_TOKEN), "proposal #33 already exists")
            self.assertTrue(reader.call_args.kwargs["paginate"])
            writer.assert_not_called()
        with patch("fcos_lab_proposal.get", side_effect=[
            {"object": {"sha": BASE}}, [{"state": "open", "head": {
                "ref": "fcos-lab-frontend-existing", "repo": {"full_name": "SecPal/deployment"},
            }}],
        ]), patch("fcos_lab_proposal.write") as writer:
            self.assertEqual(publish(PROPOSAL, BASE, SOURCE, token=WRITE_TOKEN), "another frontend proposal is open")
            writer.assert_not_called()

    def test_workflow_token_is_not_reused_for_the_cross_repository_archive(self):
        gh = Path("/verified/gh")
        listing = {"artifacts": [{
            "name": "frontend-accepted-12-2", "expired": False, "size_in_bytes": 20, "id": 22,
            "digest": "sha256:" + "a" * 64,
        }]}
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GH_TOKEN": "local-workflow-token"},
                        clear=True), patch("fcos_lab_proposal.get", return_value=listing), \
                patch("fcos_lab_proposal.subprocess.run") as download:
            with self.assertRaisesRegex(ValueError, "requires scoped frontend Actions read"):
                publisher_archive(gh, 12, 2)
            download.assert_not_called()

        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GH_TOKEN": "local-workflow-token",
                                     "FCOS_FRONTEND_ACTIONS_READ_TOKEN": "scoped-read"}, clear=True), \
                patch("fcos_lab_proposal.get", return_value=listing) as read, \
                patch("fcos_lab_proposal.subprocess.run") as download:
            download.return_value.stdout = b"wrong archive"
            with self.assertRaisesRegex(ValueError, "archive identity differs"):
                publisher_archive(gh, 12, 2)
            self.assertEqual(read.call_args.kwargs["gh"], gh)
            self.assertEqual(download.call_args.args[0][0], gh)
            self.assertEqual(download.call_args.kwargs["env"]["GH_TOKEN"], "scoped-read")

    def test_publish_requires_a_separate_credential_and_removes_it_from_the_read_environment(self):
        def inspect_publish(proposal, base, source, *, token):
            self.assertEqual((proposal, base, source, token), (PROPOSAL, BASE, SOURCE, WRITE_TOKEN))
            self.assertEqual(os.environ["GH_TOKEN"], "workflow-read")
            self.assertNotIn(WRITE_TOKEN_ENV, os.environ)
            return "draft proposal #99 created"

        for token in ("", WRITE_TOKEN):
            with self.subTest(configured=bool(token)), patch.dict(os.environ, {
                "GH_TOKEN": "workflow-read", "GITHUB_SHA": BASE, WRITE_TOKEN_ENV: token,
            }, clear=True), patch.object(sys, "argv", ["proposal", "publish"]), \
                    patch.object(sys, "stdin", StringIO(json.dumps(asdict(PROPOSAL)))), \
                    patch.object(Path, "read_text", return_value=SOURCE), \
                    patch("fcos_lab_proposal.publish", side_effect=inspect_publish) as publisher, \
                    redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(main(), 0 if token else 1)
                self.assertEqual(publisher.call_count, int(bool(token)))

    def test_write_uses_the_dedicated_credential_in_the_subprocess_environment(self):
        with patch.dict(os.environ, {"GH_TOKEN": "workflow-read"}, clear=True), \
                patch("fcos_lab_proposal.subprocess.run") as api:
            api.return_value.stdout = '{"number":99}'
            result = write("POST", "repos/SecPal/deployment/pulls", {}, token=WRITE_TOKEN)
            self.assertEqual(result, {"number": 99})
            self.assertIn("github.com", api.call_args.args[0])
            self.assertNotIn(WRITE_TOKEN, api.call_args.args[0])
            self.assertEqual(api.call_args.kwargs["env"]["GH_TOKEN"], WRITE_TOKEN)
            self.assertEqual(os.environ["GH_TOKEN"], "workflow-read")

    def test_only_a_verified_single_file_commit_can_open_a_draft(self):
        tip = "9" * 40
        base_ref = {"object": {"sha": BASE}}
        run = {"head_branch": "main", "event": "push", "conclusion": "success",
               "head_repository": {"full_name": "SecPal/frontend"}, "head_sha": NEW.source,
               "id": PROPOSAL.run_id, "run_attempt": PROPOSAL.run_attempt}
        snapshot = proposed_file(SOURCE, PROPOSAL)
        branch = "fcos-lab-frontend-" + NEW.index.removeprefix("sha256:") + "-" + BASE
        response = {"data": {"createCommitOnBranch": {"commit": {"oid": tip}}}}
        for signed in (True, False):
            commit = {"parents": [{"sha": BASE}], "files": [{"filename": FILE}],
                      "commit": {"verification": {"verified": signed}}}
            with self.subTest(signed=signed), patch("fcos_lab_proposal.get", side_effect=[
                base_ref, [{"head": {"ref": branch, "repo": {"full_name": "example/deployment"}}}],
                {"workflow_runs": [run]}, {"status": "ahead"}, [{
                    "ref": "refs/heads/" + branch.replace(BASE, OLD.source), "object": {"sha": OLD.source},
                }],
                commit, snapshot, base_ref,
            ]), patch("fcos_lab_proposal.write", side_effect=[base_ref, response, {"number": 99}]) as writer:
                if not signed:
                    with self.assertRaises(ValueError):
                        publish(PROPOSAL, BASE, SOURCE, token=WRITE_TOKEN)
                    self.assertEqual(writer.call_count, 2)
                    continue
                self.assertEqual(publish(PROPOSAL, BASE, SOURCE, token=WRITE_TOKEN), "draft proposal #99 created")
                self.assertEqual([call.kwargs["token"] for call in writer.call_args_list], [WRITE_TOKEN] * 3)
                ref, proposed, pr = [call.args for call in writer.call_args_list]
                self.assertEqual(ref[2], {"ref": f"refs/heads/{branch}", "sha": BASE})
                self.assertEqual(proposed[1], "graphql")
                supplied = proposed[2]["variables"]["input"]
                self.assertEqual(supplied["expectedHeadOid"], BASE)
                change, = supplied["fileChanges"]["additions"]
                self.assertEqual(change["path"], FILE)
                self.assertEqual(base64.b64decode(change["contents"]).decode(), snapshot)
                self.assertEqual((pr[2]["head"], pr[2]["base"], pr[2]["draft"]), (branch, "main", True))
                self.assertIn(PROPOSAL.arm64, pr[2]["body"])


if __name__ == "__main__":
    unittest.main()
