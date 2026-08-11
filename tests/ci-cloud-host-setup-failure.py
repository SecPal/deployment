#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Regression tests for the closed host-setup failure marker."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "ci-cloud" / "host-setup-failure.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("host_setup_failure", HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load host-setup failure helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HostSetupFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    def test_round_trip_is_closed_bounded_and_non_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            path = directory / "host-setup-failure.json"
            self.helper.write_marker(
                path,
                "apparmor",
                7,
                required_uid=os.getuid(),
            )
            document = self.helper.read_marker(path, required_uid=os.getuid())
            self.assertEqual({"stage": "apparmor", "exit_status": 7}, document)
            self.assertEqual(0o644, path.stat().st_mode & 0o777)
            self.assertLessEqual(path.stat().st_size, 128)
            self.assertEqual(
                {"exit_status": 7, "stage": "apparmor"},
                json.loads(path.read_text(encoding="utf-8")),
            )

    def test_rejects_unknown_stage_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            path = directory / "host-setup-failure.json"
            with self.assertRaises(ValueError):
                self.helper.write_marker(
                    path,
                    "arbitrary-shell-text",
                    1,
                    required_uid=os.getuid(),
                )
            self.assertFalse(path.exists())

    def test_rejects_symlink_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            target = directory / "target"
            target.write_text(
                '{"exit_status":1,"secret":"forbidden","stage":"ssh"}\n',
                encoding="utf-8",
            )
            target.chmod(0o644)
            link = directory / "host-setup-failure.json"
            link.symlink_to(target)
            with self.assertRaises((OSError, ValueError)):
                self.helper.read_marker(link, required_uid=os.getuid())
            link.unlink()
            target.rename(link)
            with self.assertRaises(ValueError):
                self.helper.read_marker(link, required_uid=os.getuid())

    def test_rejects_oversized_or_wrong_mode_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            path = directory / "host-setup-failure.json"
            path.write_bytes(b"x" * 129)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.helper.read_marker(path, required_uid=os.getuid())
            path.write_text(
                '{"exit_status":1,"stage":"ssh"}\n', encoding="utf-8"
            )
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                self.helper.read_marker(path, required_uid=os.getuid())


if __name__ == "__main__":
    unittest.main()
