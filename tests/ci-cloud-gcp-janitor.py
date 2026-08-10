#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Unit tests for fail-closed GCP TTL ownership parsing."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JANITOR_PATH = ROOT / "scripts" / "ci-cloud" / "gcp-janitor.py"


def load_janitor():
    spec = importlib.util.spec_from_file_location("gcp_janitor", JANITOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load GCP janitor module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    def __init__(self, resources: dict[str, list[dict[str, object]]]) -> None:
        self.resources = resources
        self.deleted: list[tuple[str, str]] = []

    def list_resources(self, kind: str) -> list[dict[str, object]]:
        return self.resources.get(kind, [])

    def get_resource(self, kind: str, name: str) -> dict[str, object]:
        for resource in self.resources.get(kind, []):
            if resource["name"] == name:
                return resource
        raise AssertionError("unknown resource")

    def delete_resource(self, kind: str, name: str) -> None:
        self.deleted.append((kind, name))


class GCPJanitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.janitor = load_janitor()

    @staticmethod
    def labels(*, expires: int = 1_700_001_800, sha: str = "a" * 40) -> dict[str, str]:
        return {
            "secpal_ci_owner": "deployment-conformance",
            "repository": "secpal-deployment",
            "github_run_id": "12345",
            "github_run_attempt": "2",
            "target_sha": sha,
            "created_at": "1700001000",
            "expires_at": str(expires),
        }

    def resource(self, kind: str, **label_overrides: str) -> dict[str, object]:
        labels = self.labels()
        labels.update(label_overrides)
        return {
            "id": "77001",
            "name": f"spci-12345-2-{kind}",
            "labels": labels,
            "zone": "https://www.googleapis.com/compute/v1/projects/example/zones/europe-west3-a",
        }

    def test_deletes_revalidated_expired_instance_then_disk_by_exact_name(self) -> None:
        resources = {
            "instances": [self.resource("instance")],
            "disks": [self.resource("disk")],
        }
        client = FakeClient(resources)
        deleted = self.janitor.cleanup_expired(client, now=1_700_002_000, apply=True)
        self.assertEqual(
            [("instances", "spci-12345-2-instance"), ("disks", "spci-12345-2-disk")],
            deleted,
        )
        self.assertEqual(deleted, client.deleted)

    def test_dry_run_never_deletes(self) -> None:
        client = FakeClient({"instances": [self.resource("instance")]})
        deleted = self.janitor.cleanup_expired(client, now=1_700_002_000, apply=False)
        self.assertEqual([("instances", "spci-12345-2-instance")], deleted)
        self.assertEqual([], client.deleted)

    def test_unexpired_resource_is_ignored(self) -> None:
        resource = self.resource("instance", expires_at="1700002001")
        client = FakeClient({"instances": [resource]})
        self.assertEqual([], self.janitor.cleanup_expired(client, 1_700_002_000, True))

    def test_missing_or_extra_ownership_metadata_is_ignored(self) -> None:
        missing = self.resource("instance")
        del missing["labels"]["repository"]  # type: ignore[index]
        extra = self.resource("instance")
        extra["labels"]["unknown"] = "value"  # type: ignore[index]
        for resource in (missing, extra):
            with self.subTest(resource=resource):
                client = FakeClient({"instances": [resource]})
                self.assertEqual([], self.janitor.cleanup_expired(client, 1_700_002_000, True))

    def test_invalid_sha_or_excessive_ttl_is_ignored(self) -> None:
        for resource in (
            self.resource("instance", target_sha="main"),
            self.resource("instance", expires_at="1700020000"),
        ):
            with self.subTest(resource=resource):
                client = FakeClient({"instances": [resource]})
                self.assertEqual([], self.janitor.cleanup_expired(client, 1_700_020_001, True))

    def test_name_zone_and_numeric_id_must_be_exact(self) -> None:
        bad_name = self.resource("instance")
        bad_name["name"] = "spci-99999-1-instance"
        bad_zone = self.resource("instance")
        bad_zone["zone"] = "projects/example/zones/us-central1-a"
        bad_id = self.resource("instance")
        bad_id["id"] = "not-numeric"
        for resource in (bad_name, bad_zone, bad_id):
            with self.subTest(resource=resource):
                client = FakeClient({"instances": [resource]})
                self.assertEqual([], self.janitor.cleanup_expired(client, 1_700_002_000, True))

    def test_revalidation_difference_aborts_deletion(self) -> None:
        resource = self.resource("instance")

        class ChangedClient(FakeClient):
            def get_resource(self, kind: str, name: str) -> dict[str, object]:
                changed = dict(super().get_resource(kind, name))
                changed["id"] = "77002"
                return changed

        client = ChangedClient({"instances": [resource]})
        with self.assertRaises(self.janitor.JanitorError):
            self.janitor.cleanup_expired(client, 1_700_002_000, True)
        self.assertEqual([], client.deleted)


if __name__ == "__main__":
    unittest.main()
