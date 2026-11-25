#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract for the bounded public reference transaction."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from reference_update import Pin, planned_change, validate_enrollment
from reference_runtime import lanepaths, render_api_release, render_pin, source_offer


class ReferenceContract(unittest.TestCase):
    def test_current_and_changed_lanes_are_independent(self):
        frontend = Pin("a" * 40, "sha256:" + "1" * 64)
        previous = Pin("b" * 40, "sha256:" + "2" * 64)
        offered = Pin("c" * 40, "sha256:" + "3" * 64)
        self.assertIsNone(planned_change(frontend, frontend))
        self.assertEqual(planned_change(previous, offered), offered)
        with self.assertRaises(ValueError):
            planned_change(previous, Pin(previous.source, offered.identity))

    def test_reference_scope_requires_explicit_synthetic_enrollment(self):
        valid = {"baseline": "a" * 40, "exposure": {}, "data_class": "secpal-owned-synthetic"}
        validate_enrollment(valid)
        for invalid in (
            {"baseline": valid["baseline"], "exposure": {}},
            {**valid, "data_class": "production"},
            {**valid, "data_class": "customer-test"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_enrollment(invalid)

    def test_release_metadata_uses_the_signed_source_and_preserves_the_pool(self):
        original = "[secpal]\nenv[SESSION_DOMAIN]=$SESSION_DOMAIN\n"
        first = "a" * 40
        next_source = "b" * 40
        update = render_api_release(render_api_release(original, first), next_source)
        self.assertEqual(update, render_api_release(original, next_source))
        self.assertTrue(update.startswith(original))
        self.assertIn("BOOTSTRAP_API_RELEASE_VERSION]=git." + next_source, update)
        self.assertIn("https://codeload.github.com/SecPal/api/tar.gz/" + next_source, update)
        with self.assertRaises(ValueError):
            render_api_release(original, "main")
        with self.assertRaises(ValueError):
            render_api_release(original + "[other]\n", first)

    def test_source_offer_binds_the_frontend_commit_and_verified_contracts(self):
        source = "b" * 40
        offer = source_offer(source)
        self.assertEqual(offer["version"], 1)
        repositories = offer["repositories"]
        self.assertEqual(set(repositories), {"frontend", "contracts"})
        self.assertEqual(repositories["frontend"]["sourceUrl"],
                         "https://codeload.github.com/SecPal/frontend/tar.gz/" + source)
        self.assertEqual(repositories["contracts"]["sourceUrl"],
                         "https://codeload.github.com/SecPal/contracts/tar.gz/f8771b74d887b84b84dcc94e2405df7b47222466")
        with self.assertRaises(ValueError):
            source_offer("main")

    def test_only_exact_running_image_is_replaced(self):
        old = "ghcr.io/secpal/api@sha256:" + "a" * 64
        new = "ghcr.io/secpal/api@sha256:" + "b" * 64
        original = f"[Container]\nImage={old}\nPull=never\nPublishPort=127.0.0.1:18081:8080/tcp\n"
        updated = render_pin(original, old, new)
        self.assertEqual(updated.replace(new, old), original)
        for wrong in (original + f"Image={old}\n", original.replace(old, new)):
            with self.assertRaises(ValueError):
                render_pin(wrong, old, new)
        with self.assertRaises(ValueError):
            lanepaths("../api")


if __name__ == "__main__":
    unittest.main()
