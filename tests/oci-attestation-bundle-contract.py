# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock


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
        self.subject = json_bytes(
            {
                "manifests": [
                    {
                        "digest": f"sha256:{'1' * 64}",
                        "mediaType": fetcher.OCI_MANIFEST_MEDIA_TYPE,
                        "platform": {"architecture": "amd64", "os": "linux"},
                        "size": 1024,
                    },
                    {
                        "digest": f"sha256:{'2' * 64}",
                        "mediaType": fetcher.OCI_MANIFEST_MEDIA_TYPE,
                        "platform": {"architecture": "arm64", "os": "linux"},
                        "size": 1024,
                    },
                ],
                "mediaType": fetcher.OCI_INDEX_MEDIA_TYPE,
                "schemaVersion": 2,
            }
        )
        self.subject_digest = digest(self.subject)
        fetcher.SUBJECT_DIGEST = self.subject_digest
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {},
            "predicateType": fetcher.SLSA_PREDICATE,
            "subject": [
                {
                    "digest": {"sha256": self.subject_digest.removeprefix("sha256:")},
                    "name": fetcher.SUBJECT_NAME,
                }
            ],
        }
        self.bundle = json_bytes(
            {
                "dsseEnvelope": {
                    "payload": base64.b64encode(json_bytes(self.statement)).decode(),
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
                    "size": len(self.subject),
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

    def replace_bundle_subject(self, name: str, subject_digest: str) -> None:
        statement = json.loads(json.dumps(self.statement))
        statement["subject"][0] = {
            "digest": {"sha256": subject_digest.removeprefix("sha256:")},
            "name": name,
        }
        bundle = json.loads(self.bundle)
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(
            json_bytes(statement)
        ).decode()
        self.bundle = json_bytes(bundle)
        self.bundle_digest = digest(self.bundle)
        manifest = json.loads(self.manifest)
        manifest["layers"][0]["digest"] = self.bundle_digest
        manifest["layers"][0]["size"] = len(self.bundle)
        self.manifest = json_bytes(manifest)
        self.manifest_digest = digest(self.manifest)
        index = json.loads(self.index)
        index["manifests"][0]["digest"] = self.manifest_digest
        index["manifests"][0]["size"] = len(self.manifest)
        self.index = json_bytes(index)

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
        if url == self.fetcher.manifest_url(self.fetcher.SUBJECT_DIGEST):
            return 200, self.fetcher.OCI_INDEX_MEDIA_TYPE, self.subject
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

    def assert_descriptor_closed(self, descriptor: int) -> None:
        try:
            os.fstat(descriptor)
        except OSError:
            return
        os.close(descriptor)
        self.fail("file descriptor remained open")

    def http_error_opener(self, status: int, body: bytes = b"{}") -> Any:
        class ErrorOpener:
            def open(_self, request: urllib.request.Request, timeout: int) -> Any:
                del timeout
                raise urllib.error.HTTPError(
                    request.full_url,
                    status,
                    "fixture response",
                    {
                        "Content-Length": str(len(body)),
                        "Content-Type": "application/json",
                    },
                    io.BytesIO(body),
                )

        return ErrorOpener()

    def test_fetches_fallback_referrer_and_writes_verified_private_bundle(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        with tempfile.TemporaryDirectory() as temp_dir:
            subject = Path(temp_dir) / "api-image-index.json"
            output = Path(temp_dir) / "attestation.json"
            self.fetcher.fetch_bundle(
                output,
                request_bytes=fixture.request,
                subject_output_path=subject,
            )

            self.assertEqual(subject.read_bytes(), fixture.subject)
            self.assertEqual(stat.S_IMODE(subject.stat().st_mode), 0o600)
            self.assertEqual(output.read_bytes(), fixture.bundle)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(
                [url for url, _headers in fixture.calls],
                [
                    self.fetcher.TOKEN_URL,
                    self.fetcher.manifest_url(fixture.subject_digest),
                    self.fetcher.REFERRERS_URL,
                    self.fetcher.FALLBACK_INDEX_URL,
                    self.fetcher.manifest_url(fixture.manifest_digest),
                    self.fetcher.blob_url(fixture.bundle_digest),
                ],
            )

    def test_rejects_subject_index_digest_mismatch_without_writing_outputs(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        fixture.subject += b"\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            subject = Path(temp_dir) / "api-image-index.json"
            output = Path(temp_dir) / "attestation.json"
            with self.assertRaisesRegex(ValueError, "subject index digest"):
                self.fetcher.fetch_bundle(
                    output,
                    request_bytes=fixture.request,
                    subject_output_path=subject,
                )
            self.assertFalse(subject.exists())
            self.assertFalse(output.exists())

    def test_refuses_to_overwrite_an_existing_subject_path(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        with tempfile.TemporaryDirectory() as temp_dir:
            subject = Path(temp_dir) / "api-image-index.json"
            output = Path(temp_dir) / "attestation.json"
            subject.write_text("existing")
            with self.assertRaises(FileExistsError):
                self.fetcher.fetch_bundle(
                    output,
                    request_bytes=fixture.request,
                    subject_output_path=subject,
                )
            self.assertEqual(subject.read_text(), "existing")
            self.assertFalse(output.exists())

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

    def test_rejects_wrong_signed_statement_subject_name(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        fixture.replace_bundle_subject("ghcr.io/secpal/not-api", fixture.subject_digest)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with self.assertRaisesRegex(ValueError, "statement subject identity"):
                self.fetcher.fetch_bundle(output, request_bytes=fixture.request)
            self.assertFalse(output.exists())

    def test_rejects_wrong_signed_statement_subject_digest(self) -> None:
        fixture = RegistryFixture(self.fetcher)
        fixture.replace_bundle_subject(
            self.fetcher.SUBJECT_NAME,
            f"sha256:{'9' * 64}",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with self.assertRaisesRegex(ValueError, "statement subject identity"):
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

    def test_allowed_http_error_404_reaches_referrer_fallback(self) -> None:
        fixture = RegistryFixture(self.fetcher)

        def request(
            url: str,
            headers: dict[str, str],
            max_bytes: int,
            allowed_statuses: frozenset[int],
        ) -> tuple[int, str, bytes]:
            if url == self.fetcher.REFERRERS_URL:
                with mock.patch.object(
                    self.fetcher, "HTTPS_OPENER", self.http_error_opener(404)
                ):
                    return self.fetcher._request_bytes(
                        url, headers, max_bytes, allowed_statuses
                    )
            return fixture.request(url, headers, max_bytes, allowed_statuses)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            self.fetcher.fetch_bundle(output, request_bytes=request)
            self.assertEqual(output.read_bytes(), fixture.bundle)
            self.assertIn(
                self.fetcher.FALLBACK_INDEX_URL,
                [url for url, _headers in fixture.calls],
            )

    def test_unexpected_http_error_status_remains_fail_closed(self) -> None:
        with mock.patch.object(
            self.fetcher, "HTTPS_OPENER", self.http_error_opener(401)
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 401"):
                self.fetcher._request_bytes(
                    self.fetcher.REFERRERS_URL,
                    {"Accept": self.fetcher.OCI_INDEX_MEDIA_TYPE},
                    self.fetcher.MANIFEST_RESPONSE_LIMIT,
                    frozenset({200, 404}),
                )

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

    def test_closes_descriptor_and_removes_file_when_fchmod_fails(self) -> None:
        real_open = os.open
        opened: list[int] = []

        def tracking_open(*args: Any, **kwargs: Any) -> int:
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with (
                mock.patch.object(self.fetcher.os, "open", side_effect=tracking_open),
                mock.patch.object(
                    self.fetcher.os, "fchmod", side_effect=OSError("fixture fchmod")
                ),
            ):
                with self.assertRaisesRegex(OSError, "fixture fchmod"):
                    self.fetcher._write_private_file(output, b"fixture")
            self.assertEqual(len(opened), 1)
            self.assert_descriptor_closed(opened[0])
            self.assertFalse(output.exists())

    def test_closes_descriptor_and_removes_file_when_fdopen_fails(self) -> None:
        real_open = os.open
        opened: list[int] = []

        def tracking_open(*args: Any, **kwargs: Any) -> int:
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with (
                mock.patch.object(self.fetcher.os, "open", side_effect=tracking_open),
                mock.patch.object(
                    self.fetcher.os, "fdopen", side_effect=OSError("fixture fdopen")
                ),
            ):
                with self.assertRaisesRegex(OSError, "fixture fdopen"):
                    self.fetcher._write_private_file(output, b"fixture")
            self.assertEqual(len(opened), 1)
            self.assert_descriptor_closed(opened[0])
            self.assertFalse(output.exists())

    def test_wrapper_closes_descriptor_and_removes_file_when_write_fails(self) -> None:
        real_open = os.open
        real_fdopen = os.fdopen
        opened: list[int] = []

        def tracking_open(*args: Any, **kwargs: Any) -> int:
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        class FailingWriter:
            def __init__(self, descriptor: int, mode: str) -> None:
                self.output = real_fdopen(descriptor, mode)

            def __enter__(self) -> "FailingWriter":
                return self

            def __exit__(self, *_error: Any) -> None:
                self.output.close()

            def write(self, _body: bytes) -> None:
                raise OSError("fixture write")

            def flush(self) -> None:
                self.output.flush()

            def fileno(self) -> int:
                return self.output.fileno()

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "attestation.json"
            with (
                mock.patch.object(self.fetcher.os, "open", side_effect=tracking_open),
                mock.patch.object(self.fetcher.os, "fdopen", side_effect=FailingWriter),
            ):
                with self.assertRaisesRegex(OSError, "fixture write"):
                    self.fetcher._write_private_file(output, b"fixture")
            self.assertEqual(len(opened), 1)
            self.assert_descriptor_closed(opened[0])
            self.assertFalse(output.exists())

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
