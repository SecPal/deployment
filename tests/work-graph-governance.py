#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Structural regression evidence for deployment work-graph governance."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT_BASELINE = ROOT / "AGENTS.md"


class WorkGraphGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = " ".join(
            AGENT_BASELINE.read_text(encoding="utf-8").split()
        )

    def require_clauses(self, clauses: tuple[str, ...]) -> None:
        for clause in clauses:
            with self.subTest(clause=clause):
                self.assertIn(clause, self.baseline)

    def test_canonical_contract_owns_work_graph_and_delivery_semantics(self) -> None:
        self.require_clauses(
            (
                "SecPal/.github/docs/work-graph-contract.md",
                "native GitHub graph state is authoritative",
                "Human-readable diagrams and prose are explanatory only",
                "one reviewable contract",
                "one primary delivery pull request",
                "`Fixes #<leaf>`",
                "`Part of: #<parent>`",
                "sub-epic",
            )
        )

    def test_evidence_is_proportional_to_the_promised_outcome(self) -> None:
        self.require_clauses(
            (
                "Observable behavior or validator-contract changes require failing-first",
                "Behavior-preserving refactors",
                "repository-authored fixtures cannot replace real-system evidence",
                "Do not require a real-system run when the leaf promises no real-system outcome",
                "smallest non-redundant evidence set",
            )
        )

    def test_validator_design_stays_standards_first_and_fail_closed(self) -> None:
        self.require_clauses(
            (
                "exactly one authoritative definition",
                "Independent enforcement remains legitimate at trust boundaries",
                "standard-library, language, runtime, and platform primitives",
                "finite, closed, and known",
                "Do not add a dependency when the standard library or platform suffices",
                "closed-schema, bounded, target-SHA-bound, and independently revalidated",
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
