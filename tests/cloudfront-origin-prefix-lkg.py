#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Offline contract evidence for CloudFront Origin prefix LKG state."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "scripts" / "cloudfront-origin-prefix-lkg.py"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "cloudfront-origin" / "valid-ip-ranges.json"


def load_module():
    spec = importlib.util.spec_from_file_location("cloudfront_origin_prefix_lkg", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load CloudFront Origin LKG utility")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CloudFrontOriginPrefixLkgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lkg = load_module()
        cls.valid_source = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def candidate(self, source: dict | None = None):
        return self.lkg.build_candidate(
            self.valid_source if source is None else source,
            retrieved_at="2026-08-30T12:00:00Z",
        )

    def test_valid_fixture_selects_only_service_and_is_deterministic(self) -> None:
        first = self.candidate()
        reordered = json.loads(json.dumps(self.valid_source))
        reordered["prefixes"].reverse()
        reordered["ipv6_prefixes"].reverse()
        second = self.candidate(reordered)
        self.assertEqual(first, second)
        self.assertEqual(first["ipv4_prefixes"], ["192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual(first["ipv6_prefixes"], ["2001:db8:1::/48", "2001:db8:2::/48"])
        self.assertEqual(first["candidate_sha256"], self.lkg.candidate_digest(first))

    def test_source_rejections_are_fail_closed(self) -> None:
        cases = {
            "missing provenance": lambda source: source.pop("syncToken"),
            "invalid shape": lambda source: source.__setitem__("prefixes", {}),
            "empty selected service": lambda source: [
                entry.__setitem__("service", "AMAZON") for entry in source["prefixes"] + source["ipv6_prefixes"]
            ],
            "malformed IPv4": lambda source: source["prefixes"][0].__setitem__("ip_prefix", "not-a-cidr"),
            "malformed IPv6": lambda source: source["ipv6_prefixes"][0].__setitem__("ipv6_prefix", "not-a-cidr"),
            "default IPv4": lambda source: source["prefixes"][0].__setitem__("ip_prefix", "0.0.0.0/0"),
            "default IPv6": lambda source: source["ipv6_prefixes"][0].__setitem__("ipv6_prefix", "::/0"),
            "noncanonical": lambda source: source["prefixes"][0].__setitem__("ip_prefix", "198.51.100.1/24"),
        }
        for label, change in cases.items():
            with self.subTest(label=label):
                source = json.loads(json.dumps(self.valid_source))
                change(source)
                with self.assertRaises(self.lkg.ContractError):
                    self.candidate(source)

    def test_fetch_rejects_network_tls_and_malformed_json(self) -> None:
        with mock.patch.object(self.lkg.urllib.request, "build_opener", side_effect=OSError("offline")):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.observe_source()
        with mock.patch.object(self.lkg, "read_https_document", return_value=b"not json"):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.acquire_candidate_bytes()

    def test_candidate_never_auto_promotes_and_exact_acceptance_is_required(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, candidate)
            self.assertIsNone(self.lkg.read_lkg(state))
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.accept_candidate(state, "0" * 64)
            self.lkg.accept_candidate(state, candidate["candidate_sha256"])
            self.assertEqual(self.lkg.read_lkg(state), candidate)

    def test_replaced_candidate_rejects_stale_acceptance_and_failed_refresh_preserves_lkg(self) -> None:
        candidate = self.candidate()
        changed = json.loads(json.dumps(self.valid_source))
        changed["prefixes"][0]["ip_prefix"] = "198.51.101.0/24"
        replacement = self.candidate(changed)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, candidate)
            self.lkg.accept_candidate(state, candidate["candidate_sha256"])
            self.lkg.write_candidate(state, replacement)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.accept_candidate(state, candidate["candidate_sha256"])
            self.assertEqual(self.lkg.read_lkg(state), candidate)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.write_candidate(state, {"invalid": "candidate"})
            self.assertEqual(self.lkg.read_lkg(state), candidate)

    def test_failed_source_acquisition_cannot_change_an_accepted_lkg(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, candidate)
            self.lkg.accept_candidate(state, candidate["candidate_sha256"])
            with mock.patch.object(
                self.lkg,
                "acquire_candidate_bytes",
                side_effect=self.lkg.ContractError("TLS validation failed"),
            ):
                with self.assertRaises(self.lkg.ContractError):
                    self.lkg.acquire_candidate_bytes()
            self.assertEqual(self.lkg.read_lkg(state), candidate)


if __name__ == "__main__":
    unittest.main()
