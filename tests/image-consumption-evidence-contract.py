#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Compose-independent API/frontend image evidence contract."""

from __future__ import annotations

import os
from pathlib import Path
import re
import runpy
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class EvidenceError(RuntimeError):
    """The immutable image evidence is incomplete or inconsistent."""


def require_text(path: Path, expected: str, failures: list[str]) -> None:
    if not path.is_file() or expected not in path.read_text(encoding="utf-8"):
        failures.append(f"{path} must contain: {expected}")


def validate_evidence(root: Path) -> None:
    runtime_path = root / "scripts" / "integration_runtime_contract.py"
    if not runtime_path.is_file():
        raise EvidenceError(f"missing runtime identity owner: {runtime_path}")

    runtime = runpy.run_path(os.fspath(runtime_path))
    readme = root / "README.md"
    api_doc = root / "docs" / "api-image-consumption.md"
    frontend_doc = root / "docs" / "frontend-image-consumption.md"
    failures: list[str] = []

    for name, repository in (
        ("API", "ghcr.io/secpal/api"),
        ("FRONTEND", "ghcr.io/secpal/frontend"),
    ):
        image = runtime[f"{name}_IMAGE"]
        digest = runtime[f"{name}_DIGEST"]
        source_commit = runtime[f"{name}_SOURCE_COMMIT"]
        if image != f"{repository}@{digest}":
            failures.append(f"{name}_IMAGE must be the canonical repository plus {name}_DIGEST")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            failures.append(f"{name}_DIGEST must be a lowercase SHA-256 digest")
        if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
            failures.append(f"{name}_SOURCE_COMMIT must be a full lowercase Git commit")

    for path, values in (
        (
            readme,
            (
                runtime["API_IMAGE"],
                runtime["FRONTEND_IMAGE"],
                runtime["FRONTEND_SOURCE_COMMIT"],
                "4fc2796409b7c37a541f515ccf29236f143fc132",
                "31264563173",
                "31264562902",
            ),
        ),
        (
            api_doc,
            (
                runtime["API_IMAGE"],
                runtime["API_DIGEST"],
                runtime["API_SOURCE_COMMIT"],
                "Publisher run: `30833321334` (attempt `1`)",
                "4fc2796409b7c37a541f515ccf29236f143fc132",
                "31264562902",
                "python3 scripts/quadlet-integration.py",
            ),
        ),
        (
            frontend_doc,
            (
                runtime["FRONTEND_IMAGE"],
                runtime["FRONTEND_DIGEST"],
                runtime["FRONTEND_SOURCE_COMMIT"],
                runtime["API_DIGEST"],
                "Publisher run: `31247196734` (attempt `1`)",
                "Artifact Attestation ID: `39567451`",
                "4fc2796409b7c37a541f515ccf29236f143fc132",
                "31264563173",
                "31264562902",
                "Compose Contract job: `93120504279`",
            ),
        ),
    ):
        for value in values:
            require_text(path, value, failures)

    for path, stale_text in (
        (api_doc, "the real Compose integration lifecycle"),
        (frontend_doc, "The runner resolves the static Compose contract first."),
    ):
        if path.is_file() and stale_text in path.read_text(encoding="utf-8"):
            failures.append(f"{path} retains obsolete operational text: {stale_text}")

    if failures:
        raise EvidenceError("\n".join(failures))


class ImageConsumptionEvidenceContract(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = runpy.run_path(
            os.fspath(ROOT / "scripts" / "integration_runtime_contract.py")
        )

    def test_current_evidence_is_consistent(self) -> None:
        validate_evidence(ROOT)

    def assert_drift_rejected(self, relative_path: str, old: str, new: str) -> None:
        with tempfile.TemporaryDirectory(prefix="secpal-image-evidence.") as temp:
            fixture = Path(temp)
            (fixture / "scripts").mkdir()
            (fixture / "docs").mkdir()
            for relative in (
                "README.md",
                "scripts/integration_runtime_contract.py",
                "docs/api-image-consumption.md",
                "docs/frontend-image-consumption.md",
            ):
                source = ROOT / relative
                target = fixture / relative
                shutil.copy2(source, target)
            target = fixture / relative_path
            text = target.read_text(encoding="utf-8")
            self.assertIn(old, text)
            target.write_text(text.replace(old, new), encoding="utf-8")
            with self.assertRaises(EvidenceError):
                validate_evidence(fixture)

    def test_api_digest_drift_is_rejected(self) -> None:
        self.assert_drift_rejected(
            "docs/api-image-consumption.md",
            self.runtime["API_DIGEST"],
            "sha256:" + "a" * 64,
        )

    def test_api_source_commit_drift_is_rejected(self) -> None:
        self.assert_drift_rejected(
            "docs/api-image-consumption.md",
            self.runtime["API_SOURCE_COMMIT"],
            "a" * 40,
        )

    def test_frontend_digest_drift_is_rejected(self) -> None:
        self.assert_drift_rejected(
            "docs/frontend-image-consumption.md",
            self.runtime["FRONTEND_DIGEST"],
            "sha256:" + "a" * 64,
        )

    def test_frontend_source_commit_drift_is_rejected(self) -> None:
        self.assert_drift_rejected(
            "docs/frontend-image-consumption.md",
            self.runtime["FRONTEND_SOURCE_COMMIT"],
            "a" * 40,
        )

    def test_publisher_evidence_drift_is_rejected(self) -> None:
        self.assert_drift_rejected(
            "docs/frontend-image-consumption.md",
            "Publisher run: `31247196734` (attempt `1`)",
            "Publisher run: `31247196735` (attempt `1`)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
