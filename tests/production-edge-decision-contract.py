#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Historical-preservation evidence for the superseded D.3 edge record."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DECISION = ROOT / "docs" / "architecture" / "decisions" / "production-edge.md"
CONTRACT_START = "<!-- production-edge-contract:start -->"
CONTRACT_END = "<!-- production-edge-contract:end -->"


class HistoricalProductionEdgeDecisionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DECISION.read_text(encoding="utf-8")

    def test_superseded_record_points_to_current_owners(self) -> None:
        for required in (
            "HISTORICAL / SUPERSEDED",
            "20260824-production-edge-layered-security-adr019.md",
            "https://github.com/SecPal/deployment/issues/89",
            "https://github.com/SecPal/deployment/issues/209",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.text)

    def test_embedded_accepted_status_is_explicitly_historical(self) -> None:
        self.assertIn(
            'Its embedded `"status": "accepted"` records that historical state;',
            self.text,
        )
        self.assertIn("it is not the document's current status.", self.text)

        historical_contract = self.text.split(CONTRACT_START, 1)[1].split(
            CONTRACT_END, 1
        )[0]
        self.assertIn('"status": "accepted"', historical_contract)


if __name__ == "__main__":
    unittest.main()
