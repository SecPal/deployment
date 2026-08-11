#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Regression tests for the closed host-setup failure marker."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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
                required_gid=os.getgid(),
            )
            document = self.helper.read_marker(
                path,
                required_uid=os.getuid(),
                required_gid=os.getgid(),
            )
            self.assertEqual({"stage": "apparmor", "exit_status": 7}, document)
            self.assertEqual(0o644, path.stat().st_mode & 0o777)
            self.assertLessEqual(path.stat().st_size, 128)
            self.assertEqual(
                {"exit_status": 7, "stage": "apparmor"},
                json.loads(path.read_text(encoding="utf-8")),
            )

    def test_staging_file_remains_restrictive_until_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            path = directory / "host-setup-failure.json"
            staged_modes: list[int] = []
            original_replace = self.helper.os.replace

            def inspect_replace(source: Path, destination: Path) -> None:
                staged_modes.append(stat.S_IMODE(source.stat().st_mode))
                original_replace(source, destination)

            with mock.patch.object(
                self.helper.os,
                "replace",
                side_effect=inspect_replace,
            ):
                self.helper.write_marker(
                    path,
                    "apparmor",
                    7,
                    required_uid=os.getuid(),
                    required_gid=os.getgid(),
                )

            self.assertEqual([0o600], staged_modes)
            self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))

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
                    required_gid=os.getgid(),
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
                self.helper.read_marker(
                    link,
                    required_uid=os.getuid(),
                    required_gid=os.getgid(),
                )
            link.unlink()
            target.rename(link)
            with self.assertRaises(ValueError):
                self.helper.read_marker(
                    link,
                    required_uid=os.getuid(),
                    required_gid=os.getgid(),
                )

    def test_rejects_oversized_or_wrong_mode_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            path = directory / "host-setup-failure.json"
            path.write_bytes(b"x" * 129)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.helper.read_marker(
                    path,
                    required_uid=os.getuid(),
                    required_gid=os.getgid(),
                )
            path.write_text(
                '{"exit_status":1,"stage":"ssh"}\n', encoding="utf-8"
            )
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                self.helper.read_marker(
                    path,
                    required_uid=os.getuid(),
                    required_gid=os.getgid(),
                )

    def test_uid_and_gid_are_validated_independently(self) -> None:
        directory_metadata = os.stat_result(
            (stat.S_IFDIR | 0o755, 0, 0, 1, 1001, 2002, 0, 0, 0, 0)
        )
        marker_metadata = os.stat_result(
            (stat.S_IFREG | 0o644, 0, 0, 1, 1001, 2002, 32, 0, 0, 0)
        )
        directory = mock.Mock(spec=Path)
        directory.stat.return_value = directory_metadata

        self.helper.validate_directory(directory, 1001, 2002)
        self.helper.validate_file_metadata(marker_metadata, 1001, 2002)

        with self.assertRaises(ValueError):
            self.helper.validate_directory(directory, 1001, 1001)
        with self.assertRaises(ValueError):
            self.helper.validate_file_metadata(marker_metadata, 1001, 1001)


if __name__ == "__main__":
    unittest.main()
