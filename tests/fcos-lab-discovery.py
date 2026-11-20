#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Test the public candidate selectors without GitHub access."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fcos_lab_discovery import official_tag, product_candidate, source_relationship, stable_release


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


if __name__ == "__main__":
    unittest.main()
