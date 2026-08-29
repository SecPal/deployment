#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Bounded classification contract for deployment documentation authority."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Authority(Enum):
    CURRENT_GUIDANCE = "current-guidance"
    CURRENT_TECHNICAL = "current-technical"
    IN_PROGRESS_TECHNICAL = "in-progress-technical"
    HISTORICAL_RECORD = "historical-record"
    IMMUTABLE_HISTORY = "immutable-history"


DOCUMENT_AUTHORITY = {
    Path("AGENTS.md"): Authority.CURRENT_GUIDANCE,
    Path(".github/copilot-instructions.md"): Authority.CURRENT_GUIDANCE,
    Path("README.md"): Authority.CURRENT_GUIDANCE,
    Path("docs/roadmap.md"): Authority.CURRENT_GUIDANCE,
    Path("docs/architecture/scope.md"): Authority.CURRENT_GUIDANCE,
    Path("docs/quadlet-integration.md"): Authority.CURRENT_TECHNICAL,
    Path("docs/api-image-consumption.md"): Authority.CURRENT_TECHNICAL,
    Path("docs/frontend-image-consumption.md"): Authority.CURRENT_TECHNICAL,
    Path("docs/rocky-cloud-qualification.md"): Authority.IN_PROGRESS_TECHNICAL,
    Path("docs/ci-cloud-conformance.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-host.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-inventory.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-secrets.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-state.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/decisions/production-edge.md"): Authority.HISTORICAL_RECORD,
    Path("CHANGELOG.md"): Authority.IMMUTABLE_HISTORY,
}

OBSOLETE_CURRENT_SUPPORT = {
    "Compose execution": re.compile(r"\b(?:run|start|deploy with)\s+docker compose\b", re.I),
    "Valkey startup": re.compile(r"\b(?:run|start|deploy)\s+Valkey\b", re.I),
    "production PostgreSQL container": re.compile(
        r"\bproduction PostgreSQL (?:product )?container\b", re.I
    ),
    "pre-18 PostgreSQL baseline": re.compile(
        r"\bPostgreSQL (?:16|17) is the (?:current|production) baseline\b", re.I
    ),
    "Debian current admission": re.compile(
        r"\bSchema version 1 admits only Debian 13/trixie hosts\b", re.I
    ),
    "Debian current conformance heading": re.compile(
        r"^#{2,3} (?:Ephemeral|Independent) Debian 13 cloud conformance", re.I | re.M
    ),
    "old edge decision": re.compile(r"\bD\.3 selects a pinned Debian NGINX\b", re.I),
    "old build vocabulary": re.compile(r"\b(?:Product|Their) Dockerfiles\b"),
    "edge-only CrowdSec": re.compile(r"\bCrowdSec belongs at the public edge\b", re.I),
    "Valkey future topology": re.compile(
        r"\bValkey never replaces PostgreSQL as the source of truth\b", re.I
    ),
    "old implementation status": re.compile(
        r"\bD\.1 host contract,\s+D\.1a integration-runtime parity, and D\.2"
        r"[^.]{0,100}\bare implemented\b",
        re.I | re.S,
    ),
}

HISTORICAL_STATUS = {
    Path("docs/ci-cloud-conformance.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-host.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-inventory.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-secrets.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-state.md"): "> **Status: Historical.**",
    Path("docs/architecture/decisions/production-edge.md"): "> **Status: Superseded.**",
}


def read(relative: Path) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class DocumentationCurrentGuidance(unittest.TestCase):
    def test_classifier_covers_every_repository_markdown_document(self) -> None:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                "*.md",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        discovered = {
            Path(value.decode("utf-8"))
            for value in result.stdout.split(b"\0")
            if value
        }
        self.assertEqual(discovered, set(DOCUMENT_AUTHORITY))

    def test_obsolete_support_wording_is_absent_from_current_guidance(self) -> None:
        violations = []
        for path, authority in DOCUMENT_AUTHORITY.items():
            if authority is not Authority.CURRENT_GUIDANCE:
                continue
            content = read(path)
            for claim, pattern in OBSOLETE_CURRENT_SUPPORT.items():
                if match := pattern.search(content):
                    line = content.count("\n", 0, match.start()) + 1
                    violations.append(f"{path}:{line}: {claim}")
        self.assertEqual(violations, [])

    def test_current_guidance_names_the_complete_target_vocabulary(self) -> None:
        current = "\n".join(
            read(path)
            for path, authority in DOCUMENT_AUTHORITY.items()
            if authority is Authority.CURRENT_GUIDANCE
        )
        required = (
            "Rocky Linux 10.2+",
            "SELinux",
            "rootless Podman",
            "Quadlet",
            "host-native PostgreSQL 18",
            "no Valkey",
            "HAProxy",
            "Certbot",
            "nftables",
            "CrowdSec",
            "AppSec",
            "Barman",
            "Borg",
            "Recovery Sets",
            "socketless runtime detection",
        )
        for term in required:
            with self.subTest(term=term):
                self.assertIn(term, current)

    def test_superseded_records_have_bounded_status_markers(self) -> None:
        for path, marker in HISTORICAL_STATUS.items():
            with self.subTest(path=path):
                self.assertIn(marker, read(path)[:1_000])

        old_edge = read(Path("docs/architecture/decisions/production-edge.md"))[:1_000]
        self.assertIn("https://github.com/SecPal/deployment/issues/89", old_edge)

    def test_current_integration_states_its_two_implementation_boundaries(self) -> None:
        integration = read(Path("docs/quadlet-integration.md"))
        for current_fact in (
            "PostgreSQL 18.6",
            "/var/lib/postgresql/18/docker",
            "CACHE_STORE=database",
            "QUEUE_CONNECTION=database",
            "SESSION_DRIVER=database",
            "exactly one `activity-hash-chain` worker",
            "one scheduler",
            "not the production edge",
        ):
            with self.subTest(current_fact=current_fact):
                self.assertIn(current_fact, integration)
        self.assertRegex(integration, r"one\s+explicit migration container")
        self.assertIn("https://github.com/SecPal/deployment/issues/119", integration)
        self.assertIn("blocked by #118", integration)


if __name__ == "__main__":
    unittest.main(verbosity=2)
