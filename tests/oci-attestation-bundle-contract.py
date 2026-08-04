# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
FETCHER_PATH = ROOT_DIR / "scripts" / "fetch-oci-attestation.py"
sys.dont_write_bytecode = True


def load_fetcher() -> Any:
    spec = importlib.util.spec_from_file_location("oci_attestation_fetcher", FETCHER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load OCI attestation fetcher")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


class RegistryFixture:
    def __init__(self, fetcher: Any) -> None:
        self.fetcher = fetcher
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.referrers_status = 404
        self.bundle = json_bytes(
            {
                "dsseEnvelope": {
                    "payload": "fixture",
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [],
                },
                "mediaType": fetcher.BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {
                    "certificate": {},
                    "timestampVerificationData": {},
                    "tlogEntries": [],
                },
            }
        )
        self.bundle_digest = digest(self.bundle)
        self.manifest = json_bytes(
            {
                "artifactType": fetcher.BUNDLE_MEDIA_TYPE,
                "config": {
                    "digest": fetcher.EMPTY_CONFIG_DIGEST,
                    "mediaType": fetcher.EMPTY_CONFIG_MEDIA_TYPE,
                    "size": 2,
                },
                "layers": [
                    {
                        "digest": self.bundle_digest,
                        "mediaType": fetcher.BUNDLE_MEDIA_TYPE,
                        "size": len(self.bundle),
                    }
                ],
                "mediaType": fetcher.OCI_MANIFEST_MEDIA_TYPE,
                "schemaVersion": 2,
                "subject": {
                    "digest": fetcher.SUBJECT_DIGEST,
                    "mediaType": fetcher.OCI_INDEX_MEDIA_TYPE,
                    "size": 1609,
                },
            }
        )
        self.manifest_digest = digest(self.manifest)
        self.index = json_bytes(
            {
                "manifests": [
                    {
                        "annotations": {
                            "dev.sigstore.bundle.content": "dsse-envelope",
                            "dev.sigstore.bundle.predicateType": fetcher.SLSA_PREDICATE,
                        },
                        "artifactType": fetcher.BUNDLE_MEDIA_TYPE,
                        "digest": self.manifest_digest,
                        "mediaType": fetcher.OCI_MANIFEST_MEDIA_TYPE,
                        "size": len(self.manifest),
                    }
                ],
                "mediaType": fetcher.OCI_INDEX_MEDIA_TYPE,
                "schemaVersion": 2,
            }
        )

    def request(
        self,
        url: str,
        headers: dict[str, str],
        max_bytes: int,
        allowed_statuses: frozenset[int],
    ) -> tuple[int, str, bytes]:
        del max_bytes
        self.calls.append((url, headers))
        if url == self.fetcher.TOKEN_URL:
            self.assert_no_authorization(headers)
            return 200, "application/json", json_bytes({"token": "anonymous-fixture"})

        self.assert_anonymous_bearer(headers)
        if url == self.fetcher.REFERRERS_URL:
            if self.referrers_status not in allowed_statuses:
                raise AssertionError("fixture referrer status was not allowed")
            if self.referrers_status == 200:
                return 200, self.fetcher.OCI_INDEX_MEDIA_TYPE, self.index
            return self.referrers_status, "application/json", b"{}"
        if url == self.fetcher.FALLBACK_INDEX_URL:
            return 200, self.fetcher.OCI_INDEX_MEDIA_TYPE, self.index
        if url.startswith(f"{self.fetcher.REGISTRY_BASE_URL}/manifests/sha256:"):
            return 200, self.fetcher.OCI_MANIFEST_MEDIA_TYPE, self.manifest
        if url.startswith(f"{self.fetcher.REGISTRY_BASE_URL}/blobs/sha256:"):
            return 200, self.fetcher.BUNDLE_MEDIA_TYPE, self.bundle
        raise AssertionError(f"unexpected fixture URL: {url}")

    def assert_no_authorization(self, headers: dict[str, str]) -> None:
        if "Authorization" in headers:
            raise AssertionError("token request unexpectedly carried authorization")

    def assert_anonymous_bearer(self, headers: dict[str, str]) -> None:
        if headers.get("Authorization") != "Bearer anonymous-fixture":
            raise AssertionError("registry request did not use the anonymous bearer")


class OciAttestationBundleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fetcher = load_fetcher()

    def test_fetches_fallback_referrer_and_writes_verified_private_bundle(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            self.fetcher.fetch_bundle(output, request_bytes=fixture.request)

            self.assertEqual(output.read_bytes(), fixture.bundle)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(
                [url for url, _headers in fixture.calls],
                [
                    self.fetcher.TOKEN_URL,
                    self.fetcher.REFERRERS_URL,
                    self.fetcher.FALLBACK_INDEX_URL,
                    self.fetcher.manifest_url(fixture.manifest_digest),
                    self.fetcher.blob_url(fixture.bundle_digest),
                ],
            )

    def test_rejects_wrong_subject_before_writing_bundle(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        manifest = json.loads(fixture.manifest)
        manifest["subject"]["digest"] = (
            "sha256:6a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
        )
        fixture.manifest = json_bytes(manifest)
        fixture.manifest_digest = digest(fixture.manifest)
        index = json.loads(fixture.index)
        index["manifests"][0]["digest"] = fixture.manifest_digest
        index["manifests"][0]["size"] = len(fixture.manifest)
        fixture.index = json_bytes(index)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with self.assertRaisesRegex(ValueError, "subject digest"):
                self.fetcher.fetch_bundle(output, request_bytes=fixture.request)
            self.assertFalse(output.exists())

    def test_uses_standard_referrers_response_without_fallback_when_available(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        fixture.referrers_status = 200
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            self.fetcher.fetch_bundle(output, request_bytes=fixture.request)
            requested_urls = [url for url, _headers in fixture.calls]
            self.assertNotIn(self.fetcher.FALLBACK_INDEX_URL, requested_urls)
            self.assertEqual(output.read_bytes(), fixture.bundle)

    def test_rejects_multiple_matching_slsa_bundles(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        index = json.loads(fixture.index)
        index["manifests"].append(dict(index["manifests"][0]))
        fixture.index = json_bytes(index)
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with self.assertRaisesRegex(ValueError, "exactly one"):
                self.fetcher.fetch_bundle(output, request_bytes=fixture.request)
            self.assertFalse(output.exists())

    def test_rejects_manifest_digest_mismatch(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        index = json.loads(fixture.index)
        index["manifests"][0]["digest"] = f"sha256:{'0' * 64}"
        fixture.index = json_bytes(index)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with self.assertRaisesRegex(ValueError, "manifest digest"):
                self.fetcher.fetch_bundle(output, request_bytes=fixture.request)
            self.assertFalse(output.exists())

    def test_rejects_bundle_digest_mismatch(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        manifest = json.loads(fixture.manifest)
        manifest["layers"][0]["digest"] = f"sha256:{'0' * 64}"
        fixture.manifest = json_bytes(manifest)
        fixture.manifest_digest = digest(fixture.manifest)
        index = json.loads(fixture.index)
        index["manifests"][0]["digest"] = fixture.manifest_digest
        index["manifests"][0]["size"] = len(fixture.manifest)
        fixture.index = json_bytes(index)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with self.assertRaisesRegex(ValueError, "bundle digest"):
                self.fetcher.fetch_bundle(output, request_bytes=fixture.request)
            self.assertFalse(output.exists())

    def test_refuses_to_overwrite_an_existing_path(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            output.write_text("existing")
            with self.assertRaises(FileExistsError):
                self.fetcher.fetch_bundle(output, request_bytes=fixture.request)
            self.assertEqual(output.read_text(), "existing")

    def test_blob_redirect_is_host_bound_and_drops_registry_authorization(self) -> None:
        redirected_blob_digest = f"sha256:{'2' * 64}"
        registry_blob_digest = f"sha256:{'3' * 64}"
        request = urllib.request.Request(
            self.fetcher.blob_url(f"sha256:{'1' * 64}"),
            headers={"Accept": self.fetcher.BUNDLE_MEDIA_TYPE, "Authorization": "Bearer fixture"},
            method="GET",
        )
        redirected = self.fetcher.SafeBlobRedirects().redirect_request(
            request,
            None,
            307,
            "temporary redirect",
            {},
            f"https://pkg-containers.githubusercontent.com/ghcrblobs13/blobs/{redirected_blob_digest}?sig=fixture",
        )
        self.assertNotIn("Authorization", redirected.headers)
        self.assertEqual(redirected.get_method(), "GET")

        rejected_urls = (
            f"https://attacker.example/ghcrblobs13/blobs/{redirected_blob_digest}?sig=fixture",
            f"https://pkg-containers.githubusercontent.com/ghcr13/blobs/{redirected_blob_digest}?sig=fixture",
            f"https://pkg-containers.githubusercontent.com:444/ghcrblobs13/blobs/{redirected_blob_digest}?sig=fixture",
            f"https://pkg-containers.githubusercontent.com/ghcrblobs13/blobs/{redirected_blob_digest}/extra?sig=fixture",
            f"http://pkg-containers.githubusercontent.com/ghcrblobs13/blobs/{redirected_blob_digest}?sig=fixture",
        )
        for rejected_url in rejected_urls:
            with self.subTest(url=rejected_url):
                with self.assertRaisesRegex(ValueError, "unapproved redirect"):
                    self.fetcher.SafeBlobRedirects().redirect_request(
                        request,
                        None,
                        307,
                        "temporary redirect",
                        {},
                        rejected_url,
                    )

        self.assertFalse(
            self.fetcher._is_registry_blob_url(
                f"{self.fetcher.blob_url(registry_blob_digest)}/extra"
            )
        )


if __name__ == "__main__":
    unittest.main()
