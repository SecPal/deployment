#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Structural regression evidence for deployment work-graph governance."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT_BASELINE = ROOT / "AGENTS.md"
ROCKY_QUALIFICATION = ROOT / "docs" / "rocky-cloud-qualification.md"


class WorkGraphGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = " ".join(
            AGENT_BASELINE.read_text(encoding="utf-8").split()
        )
        cls.rocky_history = " ".join(
            ROCKY_QUALIFICATION.read_text(encoding="utf-8").split()
        ).lower()

    def require_clauses(self, clauses: tuple[str, ...]) -> None:
        for clause in clauses:
            with self.subTest(clause=clause):
                self.assertIn(clause, self.baseline)

    def test_delegates_generic_governance_to_canonical_contract(self) -> None:
        self.require_clauses(
            (
                "SecPal/.github/docs/work-graph-contract.md",
                "as the single authority for work-graph, delivery, replanning, "
                "and evidence semantics",
                "This repository adds only deployment-specific implementation "
                "and security constraints",
                "SecPal/.github/docs/evidence-architecture-contract.md",
                "authoritative companion for evidence-pipeline and "
                "external-system architecture",
            )
        )

    def test_deployment_external_operations_fail_closed(self) -> None:
        self.require_clauses(
            (
                "Apply the canonical evidence-architecture companion before "
                "dispatching any deployment-owned cloud, host, registry, "
                "migration, or conformance operation",
                "Deployment preflight must fail closed when its reachable "
                "trusted operations cannot produce the required bounded "
                "semantic diagnostics",
            )
        )

    def test_rocky_history_distinguishes_sources_and_current_correction(self) -> None:
        for reference in (
            "#64",
            "#67",
            "#68",
            "#72",
            "#73",
            "#74",
            "#117",
            "#118",
            "#119",
            "#120",
            "#121",
            "#122",
            "#150",
        ):
            with self.subTest(reference=reference):
                self.assertIsNotNone(
                    re.search(
                        rf"(?<![0-9]){re.escape(reference)}(?![0-9])",
                        self.rocky_history,
                    )
                )
        for clause in (
            "#67 elevated one authoritative definition per semantic invariant",
            "#68 owns pure layer-boundary enforcement",
            "current #117 identifies #64/#68 and PRs #73/#74 as reusable design evidence",
            "current #117 requires explicit observation, normalization, admission, and assembly ownership",
            "current #150 is the concrete architecture prerequisite blocking #118",
        ):
            with self.subTest(clause=clause):
                self.assertIn(clause.lower(), self.rocky_history)

    def test_deployment_evidence_boundary_remains_explicit(self) -> None:
        self.require_clauses(
            (
                "repository-authored fixtures cannot replace real-system evidence",
                "Do not require a real-system run when the leaf promises no real-system outcome",
                "closed-schema, bounded, target-SHA-bound, and independently revalidated",
                "only provider/system evidence proves a promised real-system result",
            )
        )

    def test_deployment_validator_design_constraints_remain_explicit(self) -> None:
        self.require_clauses(
            (
                "Python scope analysis uses `symtable`",
                "Custom deployment-domain validation remains legitimate",
                "finite, closed, and known",
            )
        )

    def test_deployment_security_boundaries_remain_explicit(self) -> None:
        self.require_clauses(
            (
                "Docker daemon",
                "container registries",
                "cloud providers",
                "Never print secret values to logs",
                "using `latest` tags or unpinned production images",
                "API and frontend remain separate images",
                "Migrations are explicit and run exactly once",
                "CrowdSec belongs at the public edge",
                "Valkey never replaces PostgreSQL as the source of truth",
            )
        )


if __name__ == "__main__":
    unittest.main()
