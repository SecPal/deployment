#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract for the bounded public reference transaction."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from reference_update import Pin, planned_change
from reference_runtime import lanepaths, render_pin


class ReferenceContract(unittest.TestCase):
    def test_current_and_changed_lanes_are_independent(self):
        frontend = Pin("a" * 40, "sha256:" + "1" * 64)
        previous = Pin("b" * 40, "sha256:" + "2" * 64)
        offered = Pin("c" * 40, "sha256:" + "3" * 64)
        self.assertIsNone(planned_change(frontend, frontend))
        self.assertEqual(planned_change(previous, offered), offered)
        with self.assertRaises(ValueError):
            planned_change(previous, Pin(previous.source, offered.identity))

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
