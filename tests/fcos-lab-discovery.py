#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Test the public candidate selectors without GitHub access."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
from subprocess import CompletedProcess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fcos_lab_discovery import (
    discover, main, official_tag, product_candidate, source_relationship, stable_release,
)
from integration_runtime_contract import API_SOURCE_COMMIT, FRONTEND_SOURCE_COMMIT


class CandidateSelectors(unittest.TestCase):
    def test_postgresql_stays_on_major_and_distribution(self):
        catalog = "Tags: 18.7, 18.7-bookworm, 18-bookworm\nTags: 19.1-bookworm, 18.9-alpine"
        self.assertEqual(official_tag(catalog, r"(18)\.([0-9]+)-bookworm"), "18.7-bookworm")

    def test_selects_haproxy_patch_numerically(self):
        catalog = "Tags: 3.2.9-trixie, 3.2.27-trixie, 3.3.1-trixie, 3.2-trixie"
        self.assertEqual(official_tag(catalog, r"(3)\.(2)\.([0-9]+)-trixie"), "3.2.27-trixie")

    def test_security_prerelease_and_draft_are_ineligible(self):
        def release(tag, *, prerelease=False, draft=False):
            return {"tag_name": tag, "prerelease": prerelease, "draft": draft}

        releases = [
            release("v1.9.0", draft=True), release("v1.10.0", prerelease=True),
            release("v2.0.0"), release("v1.8.2"), release("v1.8.11"),
        ]
        self.assertEqual(stable_release(releases, r"v(1)\.([0-9]+)\.([0-9]+)"), "v1.8.11")

    def test_product_requires_successful_main_push_from_the_right_repository(self):
        source = "1" * 40
        run = {"head_branch": "main", "event": "push", "conclusion": "success",
               "head_repository": {"full_name": "SecPal/frontend"}, "head_sha": source, "id": 42}
        result = product_candidate({"workflow_runs": [run]}, "SecPal/frontend")
        self.assertEqual(result, {"source_commit": source, "run_id": 42})
        self.assertEqual(
            product_candidate({"workflow_runs": [dict(run, event="workflow_dispatch")]}, "SecPal/frontend"),
            result,
        )
        with self.assertRaises(ValueError):
            product_candidate({"workflow_runs": [dict(run, event="pull_request")]}, "SecPal/frontend")
        with self.assertRaises(ValueError):
            product_candidate({"workflow_runs": [dict(run, head_branch="feature")]}, "SecPal/frontend")

    def test_out_of_order_or_diverged_publications_are_not_upgrades(self):
        for status in ("identical", "behind", "diverged", "ahead"):
            self.assertEqual(source_relationship({"status": status}), status)
        with self.assertRaises(ValueError):
            source_relationship({"status": "unknown"})

    def test_missing_candidates_fail(self):
        with self.assertRaises(ValueError):
            official_tag("Tags: 19.0-bookworm", r"(18)\.([0-9]+)-bookworm")
        with self.assertRaises(ValueError):
            stable_release([], r"v(4)\.([0-9]+)\.([0-9]+)")


class DiscoveryContract(unittest.TestCase):
    def test_complete_cli_read_contract(self):
        def publication(repo, commit, run_id):
            return json.dumps({"workflow_runs": [{
                "head_branch": "main", "event": "push", "conclusion": "success",
                "head_repository": {"full_name": repo}, "head_sha": commit, "id": run_id,
            }]})

        frontend_revision = "a" * 40
        workflow = "/actions/workflows/publish-container.yml/runs?branch=main&status=success&per_page=1"
        responses = {
            f"repos/SecPal/api{workflow}": publication("SecPal/api", API_SOURCE_COMMIT, 42),
            f"repos/SecPal/frontend{workflow}": publication("SecPal/frontend", frontend_revision, 43),
            f"repos/SecPal/api/compare/{API_SOURCE_COMMIT}...{API_SOURCE_COMMIT}": '{"status":"identical"}',
            f"repos/SecPal/frontend/compare/{FRONTEND_SOURCE_COMMIT}...{frontend_revision}": '{"status":"ahead"}',
            "repos/docker-library/official-images/contents/library/postgres": "Tags: 18.7-bookworm",
            "repos/docker-library/official-images/contents/library/haproxy": "Tags: 3.2.27-trixie",
        }
        for repo, version in {
            "crowdsecurity/crowdsec": "v1.8.2",
            "crowdsecurity/cs-haproxy-spoa-bouncer": "v0.4.0",
            "coreruleset/coreruleset": "v4.30.0",
        }.items():
            responses[f"repos/{repo}/releases?per_page=100"] = json.dumps(
                [{"tag_name": version, "prerelease": False, "draft": False}]
            )

        def get(command, **kwargs):
            self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
            self.assertEqual(kwargs["timeout"], 45)
            path = command[4]
            headers = ["--header", "Accept: application/vnd.github.raw+json"]
            self.assertEqual(command[5:], headers if "/contents/library/" in path else [])
            return CompletedProcess(command, 0, stdout=responses.pop(path))

        with patch("fcos_lab_discovery.subprocess.run", side_effect=get):
            self.assertEqual(discover(), {
                "api": {"source_commit": API_SOURCE_COMMIT, "run_id": 42, "source_relationship": "identical"},
                "frontend": {"source_commit": frontend_revision, "run_id": 43, "source_relationship": "ahead"},
                "postgres": "18.7-bookworm", "haproxy": "3.2.27-trixie",
                "crowdsec": "v1.8.2", "spoa": "v0.4.0", "crs": "v4.30.0",
            })
        self.assertEqual(responses, {})

    def test_incomplete_or_malformed_read_does_not_publish_a_report(self):
        for reply in ('{"workflow_runs":[]}', "invalid response"):
            args = ["gh"]
            with self.subTest(reply=reply), patch(
                "fcos_lab_discovery.subprocess.run", return_value=CompletedProcess(args, 0, stdout=reply)
            ), redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as error:
                self.assertEqual(main(), 1)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("failed to admit a complete upstream report", error.getvalue())
                self.assertNotIn(reply, error.getvalue())


if __name__ == "__main__":
    unittest.main()
