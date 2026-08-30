#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Offline contract evidence for CloudFront Origin prefix LKG state."""

from __future__ import annotations

from contextlib import redirect_stderr
from datetime import UTC, datetime, timedelta
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import stat
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

    def versioned_source(self, publication: datetime, source: dict | None = None) -> dict:
        document = json.loads(json.dumps(self.valid_source if source is None else source))
        document["syncToken"] = str(int(publication.timestamp()))
        document["createDate"] = publication.strftime("%Y-%m-%d-%H-%M-%S")
        return document

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

        evolved = json.loads(json.dumps(self.valid_source))
        evolved["future_source_metadata"] = {"ignored": True}
        evolved["prefixes"][0]["future_entry_metadata"] = "ignored"
        self.assertEqual(first, self.candidate(evolved))

    def test_source_rejections_are_fail_closed(self) -> None:
        cases = {
            "missing provenance": lambda source: source.pop("syncToken"),
            "non-ASCII sync token": lambda source: source.__setitem__("syncToken", "١٧٠٠٠٠٠٠٠٠"),
            "ambiguous sync token": lambda source: source.__setitem__("syncToken", "01700000000"),
            "noncanonical creation date": lambda source: source.__setitem__(
                "createDate", "2026-8-30-00-00-00"
            ),
            "invalid shape": lambda source: source.__setitem__("prefixes", {}),
            "missing service": lambda source: source["prefixes"][0].pop("service"),
            "empty selected service": lambda source: [
                entry.__setitem__("service", "AMAZON") for entry in source["prefixes"] + source["ipv6_prefixes"]
            ],
            "malformed unselected CIDR": lambda source: source["prefixes"][1].__setitem__(
                "ip_prefix", "not-a-cidr"
            ),
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
        with self.assertRaises(self.lkg.ContractError):
            self.lkg.build_candidate(
                self.valid_source,
                retrieved_at="2026-08-30T12:00:00+00:00",
            )

    def test_fetch_rejects_network_and_certificate_validation_failures(self) -> None:
        with mock.patch.object(self.lkg.urllib.request, "build_opener", side_effect=OSError("offline")):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.observe_source()

        certificate_error = ssl.SSLCertVerificationError("certificate rejected")
        opener = mock.Mock()
        opener.open.side_effect = certificate_error
        with mock.patch.object(self.lkg.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(self.lkg.ContractError) as failure:
                self.lkg.read_https_document()
        self.assertIs(failure.exception.__cause__, certificate_error)

    def test_redirect_and_oversized_source_are_rejected(self) -> None:
        request = self.lkg.urllib.request.Request(self.lkg.SOURCE_URL)
        with self.assertRaises(self.lkg.urllib.error.HTTPError):
            self.lkg._RejectRedirect().redirect_request(
                request,
                None,
                302,
                "redirect",
                {},
                "https://example.invalid/ip-ranges.json",
            )

        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = self.lkg.SOURCE_URL
        response.status = 200
        response.headers = {}
        response.read.return_value = b"x" * (self.lkg.MAX_SOURCE_BYTES + 1)
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(self.lkg.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.read_https_document()

        response.status = 503
        response.read.return_value = b"{}"
        with mock.patch.object(self.lkg.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.read_https_document()

    def test_malformed_and_duplicate_key_json_are_rejected(self) -> None:
        with mock.patch.object(self.lkg, "read_https_document", return_value=b"not json"):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.acquire_candidate_bytes()
        duplicate = b'{"syncToken":"1","syncToken":"2"}'
        with mock.patch.object(self.lkg, "read_https_document", return_value=duplicate):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.observe_source()

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

    def test_unsafe_state_paths_and_files_are_rejected(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(private, target_is_directory=True)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.write_candidate(linked, candidate)

            unsafe_mode = root / "unsafe-mode"
            unsafe_mode.mkdir(mode=0o755)
            unsafe_mode.chmod(0o755)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.write_candidate(unsafe_mode, candidate)

            mutable_ancestor = root / "mutable-ancestor"
            mutable_ancestor.mkdir(mode=0o777)
            mutable_ancestor.chmod(0o777)
            nested_state = mutable_ancestor / "state"
            nested_state.mkdir(mode=0o700)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.read_lkg(nested_state)

            state = root / "state"
            self.lkg.write_candidate(state, candidate)
            candidate_path = state / self.lkg.CANDIDATE_FILE
            candidate_path.chmod(0o644)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.read_candidate(state)
            candidate_path.chmod(0o600)
            hard_link = state / "candidate-hard-link.json"
            os.link(candidate_path, hard_link)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.read_candidate(state)

            shape_state = root / "shape-state"
            shape_state.mkdir(mode=0o700)
            (shape_state / self.lkg.CANDIDATE_FILE).mkdir(mode=0o700)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.read_candidate(shape_state)

            oversized_state = root / "oversized-state"
            oversized_state.mkdir(mode=0o700)
            oversized_candidate = oversized_state / self.lkg.CANDIDATE_FILE
            oversized_candidate.write_bytes(b"x" * (self.lkg.MAX_STATE_BYTES + 1))
            oversized_candidate.chmod(0o600)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.read_candidate(oversized_state)

    def test_post_commit_durability_failure_requires_authoritative_readback(self) -> None:
        accepted = self.candidate()
        changed = self.versioned_source(
            datetime(2026, 8, 30, 1, 0, 0, tzinfo=UTC)
        )
        changed["prefixes"][0]["ip_prefix"] = "198.51.101.0/24"
        replacement = self.candidate(changed)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, accepted)
            self.lkg.accept_candidate(state, accepted["candidate_sha256"])
            self.lkg.write_candidate(state, replacement)
            errors = io.StringIO()
            real_fsync = self.lkg.os.fsync
            directory_fsyncs = 0

            def fail_directory_fsync(descriptor: int) -> None:
                nonlocal directory_fsyncs
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    directory_fsyncs += 1
                    if directory_fsyncs == 2:
                        raise OSError("injected directory fsync failure")
                real_fsync(descriptor)

            with (
                mock.patch.object(
                    self.lkg.sys,
                    "argv",
                    [
                        str(TOOL_PATH),
                        "--state-dir",
                        str(state),
                        "accept",
                        "--candidate-sha256",
                        replacement["candidate_sha256"],
                    ],
                ),
                mock.patch.object(self.lkg.os, "fsync", side_effect=fail_directory_fsync),
                redirect_stderr(errors),
            ):
                result = self.lkg.main()

            stored = json.loads((state / self.lkg.LKG_FILE).read_text(encoding="utf-8"))
            self.assertEqual(stored, replacement)
            self.assertEqual(result, 2)
            self.assertIn("COMMITTED_DURABILITY_UNCONFIRMED", errors.getvalue())

    def test_pre_commit_write_failure_definitely_preserves_lkg(self) -> None:
        accepted = self.candidate()
        changed = self.versioned_source(
            datetime(2026, 8, 30, 1, 0, 0, tzinfo=UTC)
        )
        changed["prefixes"][0]["ip_prefix"] = "198.51.101.0/24"
        replacement = self.candidate(changed)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, accepted)
            self.lkg.accept_candidate(state, accepted["candidate_sha256"])
            self.lkg.write_candidate(state, replacement)
            errors = io.StringIO()
            real_fsync = self.lkg.os.fsync

            def fail_file_fsync(descriptor: int) -> None:
                if stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("injected file fsync failure")
                real_fsync(descriptor)

            with (
                mock.patch.object(
                    self.lkg.sys,
                    "argv",
                    [
                        str(TOOL_PATH),
                        "--state-dir",
                        str(state),
                        "accept",
                        "--candidate-sha256",
                        replacement["candidate_sha256"],
                    ],
                ),
                mock.patch.object(
                    self.lkg.os,
                    "fsync",
                    side_effect=fail_file_fsync,
                ),
                redirect_stderr(errors),
            ):
                result = self.lkg.main()

            self.assertEqual(result, 1)
            self.assertIn("ERROR: atomic state publication failed", errors.getvalue())
            self.assertEqual(self.lkg.read_lkg(state), accepted)

    def test_filesystem_failures_and_state_directory_durability_are_bounded(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            real_lstat = Path.lstat

            def fail_state_lstat(path: Path):
                if path == state:
                    raise PermissionError("injected lstat failure")
                return real_lstat(path)

            with mock.patch.object(Path, "lstat", fail_state_lstat):
                with self.assertRaises(self.lkg.ContractError):
                    self.lkg.write_candidate(state, candidate)

            real_mkdir = Path.mkdir

            def race_state_mkdir(path: Path, *args, **kwargs):
                if path == state:
                    raise FileExistsError("injected concurrent create")
                return real_mkdir(path, *args, **kwargs)

            with mock.patch.object(Path, "mkdir", race_state_mkdir):
                with self.assertRaises(self.lkg.ContractError):
                    self.lkg.write_candidate(state, candidate)

            for label, existing in (("new", False), ("retry", True)):
                durable_state = root / f"durability-{label}"
                if existing:
                    durable_state.mkdir(mode=0o700)
                real_open = self.lkg.os.open

                def fail_parent_open(path, flags, mode=0o777):
                    if Path(path) == durable_state.parent and flags & self.lkg.os.O_DIRECTORY:
                        raise OSError("injected parent-directory open failure")
                    if flags & self.lkg.os.O_CREAT:
                        return real_open(path, flags, mode)
                    return real_open(path, flags)

                with self.subTest(label=label), mock.patch.object(
                    self.lkg.os, "open", side_effect=fail_parent_open
                ):
                    with self.assertRaises(self.lkg.ContractError):
                        self.lkg.write_candidate(durable_state, candidate)
                    self.assertFalse((durable_state / self.lkg.CANDIDATE_FILE).exists())

            safe_state = root / "safe-state"
            self.lkg.write_candidate(safe_state, candidate)
            candidate_path = safe_state / self.lkg.CANDIDATE_FILE

            def fail_candidate_lstat(path: Path):
                if path == candidate_path:
                    raise PermissionError("injected state-file lstat failure")
                return real_lstat(path)

            with mock.patch.object(Path, "lstat", fail_candidate_lstat):
                with self.assertRaises(self.lkg.ContractError):
                    self.lkg.read_candidate(safe_state)

    def test_lock_acquisition_retries_and_times_out_without_mutation(self) -> None:
        accepted = self.candidate()
        changed = json.loads(json.dumps(self.valid_source))
        changed["prefixes"][0]["ip_prefix"] = "198.51.101.0/24"
        replacement = self.candidate(changed)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, accepted)
            self.lkg.accept_candidate(state, accepted["candidate_sha256"])

            with (
                mock.patch.object(
                    self.lkg.fcntl,
                    "flock",
                    side_effect=[BlockingIOError("contended"), None],
                ),
                mock.patch("time.monotonic", side_effect=[0.0, 0.1]),
                mock.patch("time.sleep") as delay,
            ):
                self.assertEqual(self.lkg.read_candidate(state), accepted)
                delay.assert_called_once()

            before_candidate = (state / self.lkg.CANDIDATE_FILE).read_bytes()
            before_lkg = (state / self.lkg.LKG_FILE).read_bytes()
            with (
                mock.patch.object(
                    self.lkg.fcntl,
                    "flock",
                    side_effect=BlockingIOError("contended"),
                ),
                mock.patch("time.monotonic", side_effect=[0.0, 3.0]),
                mock.patch("time.sleep"),
            ):
                with self.assertRaisesRegex(self.lkg.ContractError, "timed out"):
                    self.lkg.write_candidate(state, replacement)
            self.assertEqual((state / self.lkg.CANDIDATE_FILE).read_bytes(), before_candidate)
            self.assertEqual((state / self.lkg.LKG_FILE).read_bytes(), before_lkg)

    def test_fetch_has_no_post_commit_output_failure_state(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            with (
                mock.patch.object(
                    self.lkg.sys,
                    "argv",
                    [str(TOOL_PATH), "--state-dir", str(state), "fetch"],
                ),
                mock.patch.object(
                    self.lkg,
                    "acquire_candidate_bytes",
                    return_value=self.lkg._canonical_bytes(candidate),
                ),
                mock.patch.object(
                    self.lkg,
                    "_print_document",
                    side_effect=BrokenPipeError("injected output failure"),
                ) as output,
            ):
                result = self.lkg.main()
            self.assertEqual(result, 0)
            output.assert_not_called()
            self.assertEqual(self.lkg.read_candidate(state), candidate)

    def test_candidate_schema_and_json_decoding_are_strict(self) -> None:
        for invalid in (True, False, 1.0, "1"):
            with self.subTest(schema_version=invalid):
                candidate = self.candidate()
                candidate["schema_version"] = invalid
                candidate["candidate_sha256"] = self.lkg.candidate_digest(candidate)
                with self.assertRaises(self.lkg.ContractError):
                    self.lkg.validate_candidate(candidate)

        source_bytes = json.dumps(self.valid_source).encode("utf-8")
        nonstandard_source = source_bytes[:-1] + b', "future": NaN}'
        with mock.patch.object(
            self.lkg, "read_https_document", return_value=nonstandard_source
        ):
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.observe_source()

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, self.candidate())
            path = state / self.lkg.CANDIDATE_FILE
            content = path.read_text(encoding="utf-8").replace(
                '"schema_version":1', '"schema_version":Infinity'
            )
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(self.lkg.ContractError) as failure:
                self.lkg.read_candidate(state)
            self.assertIsInstance(failure.exception.__cause__, ValueError)
            self.assertIn("non-standard JSON constant", str(failure.exception.__cause__))

    def test_provenance_semantics_and_provider_version_rollback(self) -> None:
        publication = datetime(2026, 8, 30, 10, 0, 0, tzinfo=UTC)
        retrieval = datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC)
        source = self.versioned_source(publication)
        current = self.lkg.build_candidate(
            source, retrieved_at=retrieval.strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        mismatch = self.versioned_source(publication)
        mismatch["createDate"] = (publication + timedelta(seconds=1)).strftime(
            "%Y-%m-%d-%H-%M-%S"
        )
        with self.assertRaises(self.lkg.ContractError):
            self.lkg.build_candidate(
                mismatch, retrieved_at=retrieval.strftime("%Y-%m-%dT%H:%M:%SZ")
            )

        allowed_skew = publication + timedelta(minutes=4)
        self.lkg.build_candidate(
            self.versioned_source(allowed_skew),
            retrieved_at=publication.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        with self.assertRaises(self.lkg.ContractError):
            self.lkg.build_candidate(
                self.versioned_source(publication + timedelta(minutes=6)),
                retrieved_at=publication.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            self.lkg.write_candidate(state, current)
            self.lkg.accept_candidate(state, current["candidate_sha256"])

            older = self.lkg.build_candidate(
                self.versioned_source(publication - timedelta(hours=1)),
                retrieved_at=retrieval.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            before = (state / self.lkg.LKG_FILE).read_bytes()
            self.lkg.write_candidate(state, older)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.accept_candidate(state, older["candidate_sha256"])
            self.assertEqual((state / self.lkg.LKG_FILE).read_bytes(), before)

            newer_source = self.versioned_source(publication + timedelta(hours=1))
            newer_source["prefixes"][0]["ip_prefix"] = "198.51.101.0/24"
            newer = self.lkg.build_candidate(
                newer_source,
                retrieved_at=retrieval.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            self.lkg.write_candidate(state, newer)
            self.lkg.accept_candidate(state, newer["candidate_sha256"])
            self.assertEqual(self.lkg.read_lkg(state), newer)

            same = self.lkg.build_candidate(
                newer_source,
                retrieved_at=(retrieval + timedelta(minutes=1)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            )
            self.lkg.write_candidate(state, same)
            self.lkg.accept_candidate(state, same["candidate_sha256"])
            self.assertEqual(self.lkg.read_lkg(state), same)

            conflicting_source = json.loads(json.dumps(newer_source))
            conflicting_source["prefixes"][0]["ip_prefix"] = "198.51.102.0/24"
            conflicting = self.lkg.build_candidate(
                conflicting_source,
                retrieved_at=(retrieval + timedelta(minutes=2)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            )
            self.lkg.write_candidate(state, conflicting)
            with self.assertRaises(self.lkg.ContractError):
                self.lkg.accept_candidate(state, conflicting["candidate_sha256"])
            self.assertEqual(self.lkg.read_lkg(state), same)


if __name__ == "__main__":
    unittest.main()
