#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fetch a reviewed SecPal image index and Sigstore bundle from public GHCR."""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


REGISTRY = "ghcr.io"
REPOSITORY = "secpal/api"
SUBJECT_NAME = "ghcr.io/secpal/api"
SUBJECT_DIGEST = (
    "sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
)
TOKEN_URL = (
    "https://ghcr.io/token?service=ghcr.io&scope=repository%3Asecpal%2Fapi%3Apull"
)
REGISTRY_BASE_URL = f"https://{REGISTRY}/v2/{REPOSITORY}"
REFERRERS_URL = f"{REGISTRY_BASE_URL}/referrers/{SUBJECT_DIGEST}"
FALLBACK_INDEX_URL = (
    f"{REGISTRY_BASE_URL}/manifests/{SUBJECT_DIGEST.replace(':', '-', 1)}"
)

OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
EMPTY_CONFIG_DIGEST = (
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"

TOKEN_RESPONSE_LIMIT = 64 * 1024
MANIFEST_RESPONSE_LIMIT = 1024 * 1024
BUNDLE_RESPONSE_LIMIT = 16 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 30
REQUEST_ATTEMPTS = 2
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
BEARER_PATTERN = re.compile(r"[A-Za-z0-9._~+/-]{1,32768}={0,2}")
REGISTRY_BLOB_PATH_PATTERN = re.compile(
    rf"/v2/{re.escape(REPOSITORY)}/blobs/sha256:[0-9a-f]{{64}}"
)
GITHUB_BLOB_PATH_PATTERN = re.compile(r"/ghcrblobs[0-9]+/blobs/sha256:[0-9a-f]{64}")
DIAGNOSTIC_FAILURE_PREFIX = "SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:"
DIAGNOSTIC_STAGES = frozenset(
    {
        "workload-api-attestation-fetch",
        "workload-frontend-attestation-fetch",
    }
)
DIAGNOSTIC_FAILURE_REASONS = frozenset(
    {
        "attestation-content-rejected",
        "contract-rejected",
        "filesystem-error",
        "registry-policy-rejected",
        "registry-request-failed",
        "registry-response-rejected",
    }
)

RequestBytes = Callable[
    [str, dict[str, str], int, frozenset[int]], tuple[int, str, str, bytes]
]


def closed_failure_reason(error: OSError | RuntimeError | ValueError) -> str:
    if isinstance(error, OSError):
        return "filesystem-error"
    if isinstance(error, RuntimeError):
        return "registry-request-failed"
    message = str(error)
    if message in {
        "expected registry path was not canonical",
        "canonical image did not match the expected registry path",
        "canonical image digest was not a canonical SHA-256 value",
    }:
        return "contract-rejected"
    if "redirect" in message:
        return "registry-policy-rejected"
    if "response" in message or "registry bearer" in message:
        return "registry-response-rejected"
    return "attestation-content-rejected"


def configure_identity(
    canonical_image: str,
    canonical_digest: str,
    expected_registry_path: str,
) -> None:
    """Bind every registry URL and signed subject check to explicit inputs."""
    global REPOSITORY
    global SUBJECT_NAME
    global SUBJECT_DIGEST
    global TOKEN_URL
    global REGISTRY_BASE_URL
    global REFERRERS_URL
    global FALLBACK_INDEX_URL
    global REGISTRY_BLOB_PATH_PATTERN

    if re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*", expected_registry_path) is None:
        raise ValueError("expected registry path was not canonical")
    if canonical_image != f"{REGISTRY}/{expected_registry_path}":
        raise ValueError("canonical image did not match the expected registry path")
    _require_digest(canonical_digest, "canonical image")

    REPOSITORY = expected_registry_path
    SUBJECT_NAME = canonical_image
    SUBJECT_DIGEST = canonical_digest
    quoted_scope = urllib.parse.quote(f"repository:{REPOSITORY}:pull", safe="")
    TOKEN_URL = f"https://{REGISTRY}/token?service={REGISTRY}&scope={quoted_scope}"
    REGISTRY_BASE_URL = f"https://{REGISTRY}/v2/{REPOSITORY}"
    REFERRERS_URL = f"{REGISTRY_BASE_URL}/referrers/{SUBJECT_DIGEST}"
    FALLBACK_INDEX_URL = (
        f"{REGISTRY_BASE_URL}/manifests/{SUBJECT_DIGEST.replace(':', '-', 1)}"
    )
    REGISTRY_BLOB_PATH_PATTERN = re.compile(
        rf"/v2/{re.escape(REPOSITORY)}/blobs/sha256:[0-9a-f]{{64}}"
    )


def _is_default_https_url(parsed: urllib.parse.SplitResult) -> bool:
    try:
        return (
            parsed.scheme == "https"
            and parsed.port in {None, 443}
            and parsed.username is None
            and parsed.password is None
            and parsed.fragment == ""
        )
    except ValueError:
        return False


def _is_registry_blob_url(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return (
        _is_default_https_url(parsed)
        and parsed.hostname == REGISTRY
        and REGISTRY_BLOB_PATH_PATTERN.fullmatch(parsed.path) is not None
        and parsed.query == ""
    )


def _is_github_blob_url(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return (
        _is_default_https_url(parsed)
        and parsed.hostname == "pkg-containers.githubusercontent.com"
        and GITHUB_BLOB_PATH_PATTERN.fullmatch(parsed.path) is not None
    )


class SafeBlobRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request:
        del file_pointer, message, headers
        if (
            code not in {302, 307}
            or not _is_registry_blob_url(request.full_url)
            or not _is_github_blob_url(new_url)
        ):
            raise ValueError("public registry returned an unapproved redirect")
        safe_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() != "authorization"
        }
        return urllib.request.Request(new_url, headers=safe_headers, method="GET")


HTTPS_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    SafeBlobRedirects(),
)


def manifest_url(digest: str) -> str:
    _require_digest(digest, "manifest")
    return f"{REGISTRY_BASE_URL}/manifests/{digest}"


def blob_url(digest: str) -> str:
    _require_digest(digest, "bundle")
    return f"{REGISTRY_BASE_URL}/blobs/{digest}"


def _request_bytes_once(
    url: str,
    headers: dict[str, str],
    max_bytes: int,
    allowed_statuses: frozenset[int],
) -> tuple[int, str, str, bytes]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        response = HTTPS_OPENER.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        if error.code not in allowed_statuses:
            raise RuntimeError(f"public registry request failed with HTTP {error.code}") from error
        response = error

    with response:
        status = response.getcode()
        if not isinstance(status, int) or status not in allowed_statuses:
            raise RuntimeError(f"public registry request returned HTTP {status}")
        final_url = response.geturl()
        if final_url != url and not (
            _is_registry_blob_url(url) and _is_github_blob_url(final_url)
        ):
            raise RuntimeError("public registry request was redirected")
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as error:
                raise ValueError("registry response had an invalid content length") from error
            if declared_length < 0 or declared_length > max_bytes:
                raise ValueError("registry response exceeded its size limit")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("registry response exceeded its size limit")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
        registry_digest = response.headers.get("Docker-Content-Digest", "").strip()
        return status, content_type, registry_digest, body


def _request_bytes(
    url: str,
    headers: dict[str, str],
    max_bytes: int,
    allowed_statuses: frozenset[int],
) -> tuple[int, str, str, bytes]:
    transient_errors = (
        urllib.error.URLError,
        ConnectionError,
        TimeoutError,
        ssl.SSLError,
        http.client.IncompleteRead,
    )
    for attempt in range(REQUEST_ATTEMPTS):
        try:
            return _request_bytes_once(url, headers, max_bytes, allowed_statuses)
        except transient_errors as error:
            if attempt + 1 == REQUEST_ATTEMPTS:
                raise RuntimeError("public registry request failed") from error
    raise RuntimeError("public registry request failed")


def _parse_object(body: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} was not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} was not a JSON object")
    return value


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} digest was not a canonical SHA-256 value")
    return value


def _require_size(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{label} size was invalid")
    return value


def _require_media_type(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise ValueError(f"{label} media type was not {expected}")


def _validate_bytes(body: bytes, expected_digest: str, expected_size: int, label: str) -> None:
    observed_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
    if observed_digest != expected_digest:
        raise ValueError(f"{label} digest did not match its descriptor")
    if len(body) != expected_size:
        raise ValueError(f"{label} size did not match its descriptor")


def _select_bundle_descriptor(index: dict[str, Any]) -> tuple[str, int]:
    if index.get("schemaVersion") != 2 or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE:
        raise ValueError("OCI referrer index shape was invalid")
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("OCI referrer index did not contain manifests")

    matching: list[dict[str, Any]] = []
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            continue
        annotations = descriptor.get("annotations")
        if (
            descriptor.get("artifactType") == BUNDLE_MEDIA_TYPE
            and descriptor.get("mediaType") == OCI_MANIFEST_MEDIA_TYPE
            and isinstance(annotations, dict)
            and annotations.get("dev.sigstore.bundle.content") == "dsse-envelope"
            and annotations.get("dev.sigstore.bundle.predicateType") == SLSA_PREDICATE
        ):
            matching.append(descriptor)

    if len(matching) != 1:
        raise ValueError("expected exactly one SLSA Sigstore bundle referrer")
    descriptor = matching[0]
    return (
        _require_digest(descriptor.get("digest"), "manifest"),
        _require_size(descriptor.get("size"), "manifest"),
    )


def _select_bundle_layer(manifest: dict[str, Any]) -> tuple[str, int]:
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE
        or manifest.get("artifactType") != BUNDLE_MEDIA_TYPE
    ):
        raise ValueError("OCI attestation manifest shape was invalid")

    config = manifest.get("config")
    if not isinstance(config, dict) or (
        config.get("mediaType") != EMPTY_CONFIG_MEDIA_TYPE
        or config.get("digest") != EMPTY_CONFIG_DIGEST
        or config.get("size") != 2
    ):
        raise ValueError("OCI attestation manifest config was invalid")

    subject = manifest.get("subject")
    if not isinstance(subject, dict) or (
        subject.get("mediaType") != OCI_INDEX_MEDIA_TYPE
        or subject.get("digest") != SUBJECT_DIGEST
    ):
        raise ValueError("OCI attestation subject digest was not the reviewed image digest")
    _require_size(subject.get("size"), "subject")

    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1 or not isinstance(layers[0], dict):
        raise ValueError("OCI attestation manifest did not contain exactly one bundle layer")
    layer = layers[0]
    if layer.get("mediaType") != BUNDLE_MEDIA_TYPE:
        raise ValueError("OCI attestation bundle layer media type was invalid")
    return (
        _require_digest(layer.get("digest"), "bundle"),
        _require_size(layer.get("size"), "bundle"),
    )


def _validate_bundle_shape(body: bytes) -> None:
    bundle = _parse_object(body, "Sigstore bundle")
    envelope = bundle.get("dsseEnvelope")
    if (
        bundle.get("mediaType") != BUNDLE_MEDIA_TYPE
        or not isinstance(envelope, dict)
        or not isinstance(bundle.get("verificationMaterial"), dict)
    ):
        raise ValueError("Sigstore bundle shape was invalid")
    payload = envelope.get("payload")
    if (
        envelope.get("payloadType") != "application/vnd.in-toto+json"
        or not isinstance(payload, str)
    ):
        raise ValueError("Sigstore DSSE envelope shape was invalid")
    try:
        statement_body = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Sigstore statement payload was not valid base64") from error
    statement = _parse_object(statement_body, "Sigstore statement")
    subjects = statement.get("subject")
    expected_digest = SUBJECT_DIGEST.removeprefix("sha256:")
    if (
        statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != SLSA_PREDICATE
        or not isinstance(subjects, list)
        or len(subjects) != 1
        or not isinstance(subjects[0], dict)
        or subjects[0].get("name") != SUBJECT_NAME
        or not isinstance(subjects[0].get("digest"), dict)
        or subjects[0]["digest"].get("sha256") != expected_digest
    ):
        raise ValueError(
            "Sigstore statement subject identity was not the reviewed image"
        )


def _validate_subject_index(body: bytes) -> None:
    observed_digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
    if observed_digest != SUBJECT_DIGEST:
        raise ValueError("subject index digest was not the reviewed image digest")
    index = _parse_object(body, "OCI subject index")
    if (
        index.get("schemaVersion") != 2
        or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE
        or not isinstance(index.get("manifests"), list)
        or not index["manifests"]
    ):
        raise ValueError("OCI subject index shape was invalid")


def _write_private_file(path: Path, body: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    wrapped = False
    try:
        os.fchmod(descriptor, 0o600)
        output = os.fdopen(descriptor, "wb")
        wrapped = True
        with output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if not wrapped:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def fetch_bundle(
    output_path: Path,
    request_bytes: RequestBytes = _request_bytes,
    subject_output_path: Path | None = None,
) -> None:
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing path: {output_path}")
    if not output_path.parent.is_dir():
        raise FileNotFoundError(f"bundle output directory does not exist: {output_path.parent}")
    if subject_output_path is not None:
        if subject_output_path.exists() or subject_output_path.is_symlink():
            raise FileExistsError(
                f"refusing to overwrite existing path: {subject_output_path}"
            )
        if not subject_output_path.parent.is_dir():
            raise FileNotFoundError(
                f"subject output directory does not exist: {subject_output_path.parent}"
            )

    _status, content_type, _registry_digest, token_body = request_bytes(
        TOKEN_URL,
        {"Accept": "application/json"},
        TOKEN_RESPONSE_LIMIT,
        frozenset({200}),
    )
    _require_media_type(content_type, "application/json", "anonymous token response")
    token = _parse_object(token_body, "anonymous token response").get("token")
    if not isinstance(token, str) or BEARER_PATTERN.fullmatch(token) is None:
        raise ValueError("anonymous registry bearer was missing or malformed")

    registry_headers = {
        "Accept": OCI_INDEX_MEDIA_TYPE,
        "Authorization": f"Bearer {token}",
    }
    subject_body = b""
    if subject_output_path is not None:
        status, content_type, registry_digest, subject_body = request_bytes(
            manifest_url(SUBJECT_DIGEST),
            registry_headers,
            MANIFEST_RESPONSE_LIMIT,
            frozenset({200}),
        )
        if status != 200:
            raise RuntimeError("OCI subject index was unavailable")
        _require_media_type(content_type, OCI_INDEX_MEDIA_TYPE, "OCI subject index")
        if registry_digest != SUBJECT_DIGEST:
            raise ValueError("OCI subject registry digest header did not match")
        _validate_subject_index(subject_body)

    status, content_type, _registry_digest, index_body = request_bytes(
        REFERRERS_URL,
        registry_headers,
        MANIFEST_RESPONSE_LIMIT,
        frozenset({200, 404}),
    )
    if status == 404:
        status, content_type, _registry_digest, index_body = request_bytes(
            FALLBACK_INDEX_URL,
            registry_headers,
            MANIFEST_RESPONSE_LIMIT,
            frozenset({200}),
        )
    if status != 200:
        raise RuntimeError("OCI referrer discovery did not return a manifest")
    _require_media_type(content_type, OCI_INDEX_MEDIA_TYPE, "OCI referrer index")
    manifest_digest, manifest_size = _select_bundle_descriptor(
        _parse_object(index_body, "OCI referrer index")
    )

    status, content_type, _registry_digest, manifest_body = request_bytes(
        manifest_url(manifest_digest),
        {
            "Accept": OCI_MANIFEST_MEDIA_TYPE,
            "Authorization": f"Bearer {token}",
        },
        MANIFEST_RESPONSE_LIMIT,
        frozenset({200}),
    )
    if status != 200:
        raise RuntimeError("OCI attestation manifest was unavailable")
    _require_media_type(content_type, OCI_MANIFEST_MEDIA_TYPE, "OCI attestation manifest")
    _validate_bytes(manifest_body, manifest_digest, manifest_size, "manifest")
    bundle_digest, bundle_size = _select_bundle_layer(
        _parse_object(manifest_body, "OCI attestation manifest")
    )

    status, content_type, _registry_digest, bundle_body = request_bytes(
        blob_url(bundle_digest),
        {
            "Accept": BUNDLE_MEDIA_TYPE,
            "Authorization": f"Bearer {token}",
        },
        BUNDLE_RESPONSE_LIMIT,
        frozenset({200}),
    )
    if status != 200:
        raise RuntimeError("OCI attestation bundle was unavailable")
    if content_type not in {BUNDLE_MEDIA_TYPE, "application/octet-stream"}:
        raise ValueError("OCI attestation bundle media type was invalid")
    _validate_bytes(bundle_body, bundle_digest, bundle_size, "bundle")
    _validate_bundle_shape(bundle_body)
    if subject_output_path is None:
        _write_private_file(output_path, bundle_body)
        return

    _write_private_file(subject_output_path, subject_body)
    try:
        _write_private_file(output_path, bundle_body)
    except BaseException:
        subject_output_path.unlink(missing_ok=True)
        raise


def main(argv: list[str]) -> int:
    diagnostic_stage: str | None = None
    if len(argv) == 8 and argv[6] == "--diagnostic-stage":
        diagnostic_stage = argv[7]
    if len(argv) not in {6, 8} or (
        len(argv) == 8 and diagnostic_stage not in DIAGNOSTIC_STAGES
    ):
        print(
            f"Usage: {Path(argv[0]).name} SUBJECT_OUTPUT_PATH BUNDLE_OUTPUT_PATH "
            "CANONICAL_IMAGE CANONICAL_DIGEST EXPECTED_REGISTRY_PATH "
            "[--diagnostic-stage CLOSED_STAGE]",
            file=sys.stderr,
        )
        return 2
    try:
        configure_identity(argv[3], argv[4], argv[5])
        fetch_bundle(Path(argv[2]), subject_output_path=Path(argv[1]))
    except (OSError, RuntimeError, ValueError) as error:
        if diagnostic_stage is not None:
            reason = closed_failure_reason(error)
            print(
                f"{DIAGNOSTIC_FAILURE_PREFIX}{diagnostic_stage}:{reason}:none",
                file=sys.stderr,
            )
        print(f"ERROR: anonymous OCI attestation bundle retrieval failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
