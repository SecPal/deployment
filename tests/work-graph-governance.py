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
