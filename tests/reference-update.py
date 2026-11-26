#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract for the bounded public reference transaction."""
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from reference_update import Pin, compatible, planned_change, validate_enrollment
from reference_runtime import Container, apply, lanepaths, render_api_release, render_pin, source_offer


class ReferenceContract(unittest.TestCase):
    def test_qualified_migration_binds_both_database_states_and_backward_evidence(self):
        previous = SimpleNamespace(pair="sha256:" + "a" * 64)
        candidate = SimpleNamespace(pair="sha256:" + "b" * 64)
        database = {"schema": "1" * 64, "ledger": "2" * 64}
        advanced = {"schema": "3" * 64, "ledger": "4" * 64}
        record = {
            "schema_version": 2, "previous_pair": previous.pair, "candidate_pair": candidate.pair,
            **database, "migration": advanced,
            "forward": {"linux/amd64": "sha256:" + "5" * 64, "linux/arm64": "sha256:" + "6" * 64},
            "rollback": {"linux/amd64": "sha256:" + "7" * 64, "linux/arm64": "sha256:" + "8" * 64},
        }
        release = SimpleNamespace(revision="a" * 40)

        def validate(contents, observed=database):
            raw = json.dumps(contents).encode()
            candidate.compatibility = hashlib.sha256(raw).hexdigest()
            with patch("reference_update.git", return_value=raw):
                return compatible(None, release, previous, candidate, observed)

        self.assertEqual(validate(record), advanced)
        self.assertEqual(validate(record, advanced), advanced)
        for invalid in (
            dict(record, rollback=None),
            dict(record, ledger="9" * 64),
            dict(record, migration=dict(advanced, ledger=database["ledger"])),
            dict(record, migration=dict(advanced, extra="unexpected")),
            dict(record, migration={"ledger": advanced["ledger"]}),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate(invalid)

    def test_acceptance_failure_restores_images_without_repeating_the_migration(self):
        old = Container("ghcr.io/secpal/api@sha256:" + "1" * 64, "a" * 40, "sha256:" + "1" * 64)
        new = Container("ghcr.io/secpal/api@sha256:" + "2" * 64, "b" * 40, "sha256:" + "2" * 64)
        events = []
        with TemporaryDirectory() as directory:
            root = Path(directory)
            pool = root / "fpm.conf"
            path = root / "secpal-php-fpm.container"
            state = root / "state"
            state.mkdir()
            pool.write_text("[secpal]\n")
            original = f"[Container]\nImage={old.image}\nPull=never\n"
            path.write_text(original)
            # Only the source fixture path is a Quadlet input.
            units = root / "units"
            units.mkdir()
            path = path.rename(units / path.name)

            def observe(_):
                return {"php-fpm": new if new.image in path.read_text() else old}

            def unit(_, *arguments, **options):
                if "stop" in arguments:
                    events.append("stop")
                if "start" in arguments:
                    events.append("start")

            def migrate():
                self.assertIn(new.image, path.read_text())
                self.assertEqual(events, ["stop"])
                events.append("migrate")

            def reject():
                raise ValueError("candidate health rejected")

            with patch.multiple("reference_runtime", STATE=state, FPM_POOL=pool,
                                lanepaths=lambda _: {"secpal-php-fpm": path}, protected=Path.read_bytes,
                                as_user=lambda *args: [], run=lambda _: new.image.encode(),
                                replace_protected_config=Path.write_bytes, migration_state=dict,
                                unit=unit, observe=observe, public_accept=lambda **options: None):
                with self.assertRaisesRegex(ValueError, "candidate health rejected"):
                    apply("api", {"php-fpm": old}, {"php-fpm": new}, {}, lambda: None, reject,
                          lambda: events.append("backward proof"), migrate=migrate)
            self.assertEqual(path.read_text(), original)
            self.assertEqual(events, ["stop", "migrate", "start", "start", "backward proof", "stop", "start", "start"])
            self.assertFalse((state / "api.blocked").exists())

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
