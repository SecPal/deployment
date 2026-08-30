#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed candidate and LKG handling for CloudFront Origin prefixes.

This utility only observes the AWS public source and maintains portable local
state. A downstream consumer validates a candidate and explicitly acknowledges
its digest before that exact candidate is atomically promoted to the LKG.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from typing import Any, Iterator
import urllib.error
import urllib.request


SOURCE_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
SERVICE = "CLOUDFRONT_ORIGIN_FACING"
SCHEMA_VERSION = 1
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
CANDIDATE_FILE = "candidate.json"
LKG_FILE = "accepted-lkg.json"
LOCK_FILE = ".cloudfront-origin-prefix-lkg.lock"
LOCK_TIMEOUT_SECONDS = 2.0
LOCK_RETRY_SECONDS = 0.05
MAX_PROVIDER_FUTURE_SKEW_SECONDS = 300


class ContractError(RuntimeError):
    """A definite pre-commit failure that leaves accepted state unchanged."""


class CommitStateUncertain(RuntimeError):
    """The rename committed, but directory durability was not confirmed."""


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _decode_json(content: bytes) -> Any:
    return json.loads(
        content.decode("utf-8"),
        object_pairs_hook=_closed_object,
        parse_constant=_reject_json_constant,
    )


def _canonical_bytes(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def candidate_digest(candidate: dict[str, Any]) -> str:
    material = dict(candidate)
    material.pop("candidate_sha256", None)
    return hashlib.sha256(_canonical_bytes(material)).hexdigest()


def _require_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise ContractError(f"source provenance field {field} is missing or invalid")
    return value


def _validate_provenance(
    sync_token: str, create_date: str, retrieved_at: str
) -> datetime:
    if re.fullmatch(r"[1-9][0-9]*", sync_token) is None:
        raise ContractError("source sync token is invalid")
    if re.fullmatch(r"[0-9]{4}(?:-[0-9]{2}){5}", create_date) is None:
        raise ContractError("source creation date is invalid")
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", retrieved_at) is None:
        raise ContractError("retrieval timestamp is not canonical UTC")
    try:
        publication_from_token = datetime.fromtimestamp(int(sync_token), UTC)
        publication_from_date = datetime.strptime(
            create_date, "%Y-%m-%d-%H-%M-%S"
        ).replace(tzinfo=UTC)
        retrieval = datetime.strptime(
            retrieved_at, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
    except (OSError, OverflowError, ValueError) as error:
        raise ContractError("source freshness metadata is invalid") from error
    if publication_from_token != publication_from_date:
        raise ContractError("source publication metadata is inconsistent")
    if publication_from_token > retrieval + timedelta(
        seconds=MAX_PROVIDER_FUTURE_SKEW_SECONDS
    ):
        raise ContractError("source publication time is materially in the future")
    return publication_from_token


def _parse_network(value: Any, version: int) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ContractError("source CIDR is missing or ambiguous")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ContractError("source CIDR is malformed") from error
    if network.version != version or str(network) != value:
        raise ContractError("source CIDR is non-canonical or wrong family")
    if network.prefixlen == 0:
        raise ContractError("source CIDR must not be a default route")
    return str(network)


def _select_prefixes(document: dict[str, Any], collection: str, key: str, version: int) -> list[str]:
    entries = document.get(collection)
    if not isinstance(entries, list):
        raise ContractError(f"source collection {collection} is missing or invalid")
    selected: set[str] = set()
    for entry in entries:
        required = {
            key,
            "region",
            "service",
            "network_border_group",
        }
        if not isinstance(entry, dict) or not required <= set(entry):
            raise ContractError(f"source {collection} entry has an invalid schema")
        if not all(isinstance(entry[name], str) and entry[name] for name in required):
            raise ContractError(f"source {collection} entry contains an invalid value")
        prefix = _parse_network(entry[key], version)
        if entry["service"] != SERVICE:
            continue
        if prefix in selected:
            raise ContractError("source contains duplicate selected CIDRs")
        selected.add(prefix)
    if not selected:
        raise ContractError(f"source has no {SERVICE} IPv{version} prefixes")
    return sorted(selected, key=lambda prefix: (ipaddress.ip_network(prefix).network_address.packed, ipaddress.ip_network(prefix).prefixlen))


def build_candidate(source: dict[str, Any], *, retrieved_at: str) -> dict[str, Any]:
    """Normalize and admit an AWS document without filesystem or network I/O."""
    required = {"syncToken", "createDate", "prefixes", "ipv6_prefixes"}
    if not isinstance(source, dict) or not required <= set(source):
        raise ContractError("source document has an invalid schema")
    if not isinstance(retrieved_at, str) or not retrieved_at.endswith("Z"):
        raise ContractError("retrieval timestamp is invalid")
    sync_token = _require_string(source, "syncToken")
    create_date = _require_string(source, "createDate")
    _validate_provenance(sync_token, create_date, retrieved_at)
    candidate = {
        "schema_version": SCHEMA_VERSION,
        "source_url": SOURCE_URL,
        "source_sync_token": sync_token,
        "source_create_date": create_date,
        "retrieved_at": retrieved_at,
        "service": SERVICE,
        "ipv4_prefixes": _select_prefixes(source, "prefixes", "ip_prefix", 4),
        "ipv6_prefixes": _select_prefixes(source, "ipv6_prefixes", "ipv6_prefix", 6),
    }
    candidate["candidate_sha256"] = candidate_digest(candidate)
    return candidate


def validate_candidate(candidate: dict[str, Any]) -> None:
    expected = {
        "schema_version",
        "source_url",
        "source_sync_token",
        "source_create_date",
        "retrieved_at",
        "service",
        "ipv4_prefixes",
        "ipv6_prefixes",
        "candidate_sha256",
    }
    if not isinstance(candidate, dict) or set(candidate) != expected:
        raise ContractError("candidate has an invalid schema")
    if (
        type(candidate["schema_version"]) is not int
        or candidate["schema_version"] != SCHEMA_VERSION
        or candidate["source_url"] != SOURCE_URL
        or candidate["service"] != SERVICE
    ):
        raise ContractError("candidate identity is invalid")
    for field in ("source_sync_token", "source_create_date", "retrieved_at", "candidate_sha256"):
        if not isinstance(candidate[field], str) or not candidate[field]:
            raise ContractError("candidate provenance is invalid")
    _validate_provenance(
        candidate["source_sync_token"],
        candidate["source_create_date"],
        candidate["retrieved_at"],
    )
    for prefixes, version in ((candidate["ipv4_prefixes"], 4), (candidate["ipv6_prefixes"], 6)):
        if not isinstance(prefixes, list) or not prefixes:
            raise ContractError("candidate has an empty prefix family")
        normalized = [_parse_network(prefix, version) for prefix in prefixes]
        if prefixes != sorted(set(normalized), key=lambda prefix: (ipaddress.ip_network(prefix).network_address.packed, ipaddress.ip_network(prefix).prefixlen)):
            raise ContractError("candidate prefixes are not deterministic")
    if candidate["candidate_sha256"] != candidate_digest(candidate):
        raise ContractError("candidate digest does not bind its contents")


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(request.full_url, code, "redirect rejected", headers, fp)


def read_https_document() -> bytes:
    """Observe the one authoritative URL with normal certificate validation."""
    request = urllib.request.Request(SOURCE_URL, headers={"Accept": "application/json"})
    try:
        opener = urllib.request.build_opener(_RejectRedirect())
        with opener.open(request, timeout=20) as response:
            if response.geturl() != SOURCE_URL or response.status != 200:
                raise ContractError("source retrieval was not an exact successful response")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and (not content_length.isdecimal() or int(content_length) > MAX_SOURCE_BYTES):
                raise ContractError("source response is too large or ambiguous")
            payload = response.read(MAX_SOURCE_BYTES + 1)
    except ContractError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise ContractError("authenticated HTTPS source observation failed") from error
    if len(payload) > MAX_SOURCE_BYTES:
        raise ContractError("source response exceeds the maximum size")
    return payload


def observe_source() -> dict[str, Any]:
    try:
        source = _decode_json(read_https_document())
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ContractError("source JSON is malformed") from error
    if not isinstance(source, dict):
        raise ContractError("source JSON root is invalid")
    return source


def acquire_candidate_bytes() -> bytes:
    candidate = build_candidate(observe_source(), retrieved_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
    return _canonical_bytes(candidate)


def _fsync_directory(path: Path, label: str) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(descriptor)
    except OSError as error:
        raise ContractError(f"{label} durability synchronization failed") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _assert_safe_directory(path: Path, *, create: bool) -> Path:
    normalized = Path(os.path.normpath(path))
    if not path.is_absolute() or path != normalized or path == Path(path.anchor):
        raise ContractError("state directory must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if current != path or not create:
                raise ContractError("state directory ancestor is missing")
            try:
                current.mkdir(mode=0o700)
                metadata = current.lstat()
            except OSError as error:
                raise ContractError("state directory creation failed") from error
        except OSError as error:
            raise ContractError("state directory inspection failed") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ContractError("state directory contains an unsafe component")
        mode = stat.S_IMODE(metadata.st_mode)
        safe_sticky_root = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if current != path and mode & 0o022 and not safe_sticky_root:
            raise ContractError("state directory has a mutable trusted ancestor")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ContractError("state directory ownership or mode is unsafe")
    if create:
        # Synchronize on every mutating entry, including retries after an
        # earlier creation whose parent durability could not be confirmed.
        _fsync_directory(path.parent, "state directory entry")
    return path


def _state_file(directory: Path, name: str, *, required: bool) -> Path | None:
    path = directory / name
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if required:
            raise ContractError("required state file is missing") from None
        return None
    except OSError as error:
        raise ContractError("state file inspection failed") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ContractError("state file is unsafe")
    return path


@contextmanager
def _state_lock(directory: Path) -> Iterator[None]:
    lock = directory / LOCK_FILE
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as error:
        raise ContractError("state lock is unsafe or unavailable") from error
    try:
        try:
            opened = os.fstat(descriptor)
            linked = (directory / LOCK_FILE).lstat()
        except OSError as error:
            raise ContractError("state lock is unsafe or unavailable") from error
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise ContractError("state lock is unsafe")
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as error:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ContractError("state lock acquisition timed out") from error
                time.sleep(min(LOCK_RETRY_SECONDS, remaining))
            except OSError as error:
                raise ContractError("state lock is unavailable") from error
        yield
    finally:
        try:
            os.close(descriptor)
        except OSError:
            # Closing a lock descriptor cannot change an already published
            # document and must not obscure its explicit commit outcome.
            pass


def _atomic_write(directory: Path, name: str, content: bytes) -> None:
    if len(content) > MAX_STATE_BYTES:
        raise ContractError("state document exceeds the maximum size")
    temporary: str | None = None
    descriptor: int | None = None
    committed = False
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
        os.fchmod(descriptor, 0o600)
        output = os.fdopen(descriptor, "wb")
        descriptor = None
        with output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, directory / name)
        committed = True
        directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        if committed:
            raise CommitStateUncertain(
                f"COMMITTED_DURABILITY_UNCONFIRMED:{name}:authoritative readback required"
            ) from error
        raise ContractError("atomic state publication failed") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None and not committed:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                # The target was not replaced. Retaining a private temporary file
                # is safer than masking the definite pre-commit publication result.
                pass


def _read_document(directory: Path, name: str, *, required: bool) -> dict[str, Any] | None:
    path = _state_file(directory, name, required=required)
    if path is None:
        return None
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise ContractError("state file changed during validation")
        source = os.fdopen(descriptor, "rb")
        descriptor = None
        with source:
            content = source.read(MAX_STATE_BYTES + 1)
        if len(content) > MAX_STATE_BYTES:
            raise ContractError("state document exceeds the maximum size")
        document = _decode_json(content)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ContractError("state document is invalid") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if not isinstance(document, dict):
        raise ContractError("state document root is invalid")
    validate_candidate(document)
    return document


def write_candidate(state_directory: Path, candidate: dict[str, Any]) -> None:
    """Publish a validated candidate without changing the accepted LKG."""
    validate_candidate(candidate)
    directory = _assert_safe_directory(state_directory, create=True)
    with _state_lock(directory):
        _atomic_write(directory, CANDIDATE_FILE, _canonical_bytes(candidate))


def read_candidate(state_directory: Path) -> dict[str, Any]:
    directory = _assert_safe_directory(state_directory, create=False)
    with _state_lock(directory):
        candidate = _read_document(directory, CANDIDATE_FILE, required=True)
    assert candidate is not None
    return candidate


def accept_candidate(state_directory: Path, acknowledged_digest: str) -> None:
    """Atomically promote only the candidate explicitly acknowledged by digest."""
    if not isinstance(acknowledged_digest, str) or len(acknowledged_digest) != 64:
        raise ContractError("acknowledged candidate digest is invalid")
    directory = _assert_safe_directory(state_directory, create=False)
    _fsync_directory(directory.parent, "state directory entry")
    with _state_lock(directory):
        candidate = _read_document(directory, CANDIDATE_FILE, required=True)
        assert candidate is not None
        accepted = _read_document(directory, LKG_FILE, required=False)
        if accepted is not None:
            candidate_version = _validate_provenance(
                candidate["source_sync_token"],
                candidate["source_create_date"],
                candidate["retrieved_at"],
            )
            accepted_version = _validate_provenance(
                accepted["source_sync_token"],
                accepted["source_create_date"],
                accepted["retrieved_at"],
            )
            if candidate_version < accepted_version:
                raise ContractError("candidate would roll back the provider publication")
            if candidate_version == accepted_version and (
                candidate["source_url"],
                candidate["service"],
                candidate["ipv4_prefixes"],
                candidate["ipv6_prefixes"],
            ) != (
                accepted["source_url"],
                accepted["service"],
                accepted["ipv4_prefixes"],
                accepted["ipv6_prefixes"],
            ):
                raise ContractError(
                    "same provider publication has conflicting normalized content"
                )
        if candidate["candidate_sha256"] != acknowledged_digest:
            raise ContractError("acknowledgement does not match the current candidate")
        _atomic_write(directory, LKG_FILE, _canonical_bytes(candidate))


def read_lkg(state_directory: Path) -> dict[str, Any] | None:
    directory = _assert_safe_directory(state_directory, create=False)
    with _state_lock(directory):
        return _read_document(directory, LKG_FILE, required=False)


def _print_document(document: dict[str, Any]) -> None:
    try:
        sys.stdout.buffer.write(_canonical_bytes(document))
    except OSError as error:
        raise ContractError("state output failed") from error


def _report_error(message: str) -> None:
    try:
        print(message, file=sys.stderr)
    except (OSError, ValueError):
        # The transaction result remains authoritative even when its diagnostic
        # transport is closed or unavailable.
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fetch", help="observe AWS and write a candidate only")
    commands.add_parser("candidate", help="read and validate the current candidate")
    commands.add_parser("accepted", help="read and validate the accepted LKG")
    accept = commands.add_parser("accept", help="promote an exactly acknowledged candidate")
    accept.add_argument("--candidate-sha256", required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "fetch":
            candidate = _decode_json(acquire_candidate_bytes())
            write_candidate(arguments.state_dir, candidate)
        elif arguments.command == "candidate":
            _print_document(read_candidate(arguments.state_dir))
        elif arguments.command == "accepted":
            accepted = read_lkg(arguments.state_dir)
            if accepted is None:
                raise ContractError("no accepted LKG exists")
            _print_document(accepted)
        else:
            accept_candidate(arguments.state_dir, arguments.candidate_sha256)
    except CommitStateUncertain as error:
        _report_error(str(error))
        return 2
    except ContractError as error:
        _report_error(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
