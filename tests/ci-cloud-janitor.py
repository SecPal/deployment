#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Unit tests for fail-closed DigitalOcean TTL ownership parsing."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JANITOR_PATH = ROOT / "scripts" / "ci-cloud" / "digitalocean-janitor.py"


def load_janitor():
    spec = importlib.util.spec_from_file_location("digitalocean_janitor", JANITOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load janitor module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    def __init__(self, droplets: list[dict[str, object]]) -> None:
        self.droplets = droplets
        self.deleted: list[str] = []

    def list_droplets(self) -> list[dict[str, object]]:
        return self.droplets

    def get_droplet(self, resource_id: int) -> dict[str, object]:
        for droplet in self.droplets:
            if droplet["id"] == resource_id:
                return droplet
        raise AssertionError("unknown droplet")

    def delete(self, path: str) -> None:
        self.deleted.append(path)


class DigitalOceanJanitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.janitor = load_janitor()

    @staticmethod
    def tags(*, expires: int = 1_700_001_800, sha: str = "a" * 40) -> list[str]:
        suffix = "12345-2"
        return [
            f"spci-owner-{suffix}",
            f"spci-repo-secpal-deployment-{suffix}",
            f"spci-sha-{sha}-{suffix}",
            f"spci-created-1700001000-{suffix}",
            f"spci-expires-{expires}-{suffix}",
        ]

    def test_deletes_one_revalidated_expired_owned_droplet_by_id(self) -> None:
        client = FakeClient([{"id": 77, "name": "spci-12345-2", "tags": self.tags()}])
        deleted = self.janitor.cleanup_expired(client, now=1_700_002_000, apply=True)
        self.assertEqual([77], deleted)
        self.assertEqual(["/v2/droplets/77"], client.deleted)

    def test_dry_run_never_deletes(self) -> None:
        client = FakeClient([{"id": 77, "name": "spci-12345-2", "tags": self.tags()}])
        deleted = self.janitor.cleanup_expired(client, now=1_700_002_000, apply=False)
        self.assertEqual([77], deleted)
        self.assertEqual([], client.deleted)

    def test_unexpired_droplet_is_ignored(self) -> None:
        client = FakeClient(
            [{"id": 77, "name": "spci-12345-2", "tags": self.tags(expires=1_700_002_001)}]
        )
        self.assertEqual([], self.janitor.cleanup_expired(client, now=1_700_002_000, apply=True))
        self.assertEqual([], client.deleted)

    def test_missing_ownership_dimension_is_ignored(self) -> None:
        tags = self.tags()
        tags.pop(1)
        client = FakeClient([{"id": 77, "name": "spci-12345-2", "tags": tags}])
        self.assertEqual([], self.janitor.cleanup_expired(client, now=1_700_002_000, apply=True))

    def test_ambiguous_duplicate_metadata_is_ignored(self) -> None:
        tags = self.tags() + ["spci-expires-1700001700-12345-2"]
        client = FakeClient([{"id": 77, "name": "spci-12345-2", "tags": tags}])
        self.assertEqual([], self.janitor.cleanup_expired(client, now=1_700_002_000, apply=True))

    def test_invalid_sha_or_excessive_ttl_is_ignored(self) -> None:
        for tags in (self.tags(sha="main"), self.tags(expires=1_700_020_000)):
            with self.subTest(tags=tags):
                client = FakeClient(
                    [{"id": 77, "name": "spci-12345-2", "tags": tags}]
                )
                self.assertEqual(
                    [], self.janitor.cleanup_expired(client, now=1_700_020_001, apply=True)
                )

    def test_name_must_exactly_match_owned_run(self) -> None:
        client = FakeClient([{"id": 77, "name": "spci-99999-1", "tags": self.tags()}])
        self.assertEqual([], self.janitor.cleanup_expired(client, now=1_700_002_000, apply=True))


if __name__ == "__main__":
    unittest.main()
