#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Synthetic fail-closed tests for Rocky GCP TTL cleanup."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "gcp_rocky_janitor", ROOT / "scripts/ci-cloud/gcp-rocky-janitor.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


NOW = 1_800_010_900
LABELS = {
    "secpal_ci_owner": "rocky-host-qualification",
    "repository": "secpal-deployment",
    "github_run_id": "12345",
    "github_run_attempt": "1",
    "target_sha": "a" * 40,
    "control_sha": "b" * 40,
    "provider_profile": "gcp-rocky-10-2-arm64",
    "created_at": "1800000000",
    "expires_at": "1800010800",
}


def resource(component: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"name": f"sprk-12345-1-{component}"}
    effective = LABELS if labels is None else labels
    if component in {"instance", "disk"}:
        item["labels"] = effective
    else:
        import json

        item["description"] = json.dumps(
            {
                "o": effective.get("secpal_ci_owner", ""),
                "r": effective.get("repository", ""),
                "i": effective.get("github_run_id", ""),
                "a": effective.get("github_run_attempt", ""),
                "t": effective.get("target_sha", ""),
                "c": effective.get("control_sha", ""),
                "p": effective.get("provider_profile", ""),
                "n": effective.get("created_at", ""),
                "x": effective.get("expires_at", ""),
            }
        )
    return item


class FakeClient:
    def __init__(self, resources: dict[str, list[dict[str, Any]]]) -> None:
        self.resources = resources
        self.deleted: list[tuple[str, str]] = []

    def list_component(self, component: str) -> list[dict[str, Any]]:
        return self.resources.get(component, [])

    def get_component(self, component: str, name: str) -> dict[str, Any]:
        return next(item for item in self.resources[component] if item["name"] == name)

    def delete_component(self, component: str, name: str) -> None:
        self.deleted.append((component, name))


class RockyJanitorTests(unittest.TestCase):
    def test_exact_expired_bundle_deletes_in_dependency_order(self) -> None:
        resources = {component: [resource(component)] for component in MODULE.DELETE_ORDER}
        client = FakeClient(resources)
        deleted = MODULE.cleanup_expired(client, NOW, True)
        self.assertEqual(list(MODULE.DELETE_ORDER), [component for component, _ in deleted])
        self.assertEqual(deleted, client.deleted)

    def test_name_prefix_without_exact_metadata_never_deletes(self) -> None:
        bad = dict(LABELS)
        bad.pop("control_sha")
        resources = {component: [resource(component, bad)] for component in MODULE.DELETE_ORDER}
        client = FakeClient(resources)
        self.assertEqual([], MODULE.cleanup_expired(client, NOW, True))
        self.assertEqual([], client.deleted)

    def test_mismatched_run_metadata_refuses_the_ambiguous_group(self) -> None:
        resources = {component: [resource(component)] for component in MODULE.DELETE_ORDER}
        bad = dict(LABELS)
        bad["target_sha"] = "c" * 40
        resources["network"] = [resource("network", bad)]
        client = FakeClient(resources)
        deleted = MODULE.cleanup_expired(client, NOW, True)
        self.assertEqual([], deleted)

    def test_unexpired_resource_never_deletes(self) -> None:
        resources = {component: [resource(component)] for component in MODULE.DELETE_ORDER}
        client = FakeClient(resources)
        self.assertEqual([], MODULE.cleanup_expired(client, 1_800_000_100, True))


if __name__ == "__main__":
    unittest.main()
