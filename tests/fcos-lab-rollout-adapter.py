#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Test the FCOS lab adapter without guest credentials or external services."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fcos_lab_rollout_adapter import Frontend, native_children, prepare_request, request_line, ssh_arguments
from fcos_lab_rollout import RELEASE_PATHS, Release, source_release

OLD = Release("1" * 40, "2" * 64)
NEW = Release("3" * 40, "4" * 64)
DIGEST = "sha256:" + "5" * 64
SOURCE = "7" * 40


class AdapterContract(unittest.TestCase):
    def test_closed_transport_and_pinned_ssh(self):
        identity = Path("/private/identities")
        ssh = ssh_arguments("cx23", "10.76.0.9", identity)
        self.assertIn("StrictHostKeyChecking=yes", ssh)
        self.assertIn("IdentityAgent=none", ssh)
        self.assertIn("ClearAllForwardings=yes", ssh)
        self.assertEqual(ssh[-1], "secpal-lab-rollout@10.76.0.9")
        for host, address in (("dev", "10.76.0.9"), ("cx23", "127.0.0.1"), ("cx23", "8.8.8.8")):
            with self.assertRaises(ValueError):
                ssh_arguments(host, address, identity)
        self.assertEqual(request_line("prepare", "cx23", "linux/amd64", NEW, OLD, DIGEST).count(b"\n"), 1)
        for op, host, platform, child in (
            ("exec", "cx23", "linux/amd64", None),
            ("observe", "dev", "linux/amd64", None),
            ("observe", "cax21", "linux/amd64", None),
            ("activate", "cx23", "linux/amd64", DIGEST),
            ("prepare", "cx23", "linux/amd64", "tag"),
        ):
            with self.subTest(op=op, host=host, platform=platform, child=child), self.assertRaises(ValueError):
                request_line(op, host, platform, NEW, OLD, child)

    def test_prepare_only_sends_bounded_publisher_evidence(self):
        proof = ({"linux/amd64": DIGEST}, b"index", b"bundle")
        wire = prepare_request("cx23", "linux/amd64", NEW, OLD, proof)
        self.assertEqual(wire.splitlines(keepends=True),
                         [request_line("prepare", "cx23", "linux/amd64", NEW, OLD, DIGEST),
                          b"aW5kZXg=\n", b"YnVuZGxl\n"])
        with self.assertRaises(ValueError):
            prepare_request("cx23", "linux/amd64", NEW, OLD, (proof[0], b"a" * 2097152, b"bundle"))

    def test_exact_frontend_fields_are_data(self):
        source = f'FRONTEND_DIGEST = "{DIGEST}"\nFRONTEND_SOURCE_COMMIT = "{SOURCE}"\n'
        self.assertEqual(Frontend.from_source(source), Frontend(DIGEST, SOURCE))
        for malformed in (source + source, source.replace(DIGEST, "stable"), source.replace(SOURCE, "main")):
            with self.assertRaises(ValueError):
                Frontend.from_source(malformed)

    def test_signed_index_requires_both_native_children(self):
        amd = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": DIGEST,
               "platform": {"os": "linux", "architecture": "amd64"}}
        arm = {**amd, "digest": "sha256:" + "6" * 64,
               "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}}
        self.assertEqual(native_children(json.dumps({"manifests": [amd, arm]}).encode()),
                         {"linux/amd64": amd["digest"], "linux/arm64": arm["digest"]})
        for entries in ([amd], [amd, arm, arm], [amd, {**arm, "digest": "tag"}]):
            with self.assertRaises(ValueError):
                native_children(json.dumps({"manifests": entries}).encode())


class GuestContract(unittest.TestCase):
    def setUp(self):
        self.guest = Path(__file__).resolve().parents[1] / "scripts/fcos-lab-rollout-guest.sh"

    def test_guest_rejects_inexact_or_misscoped_wire_requests(self):
        command = 'source "$1"; host=cx23; platform=linux/amd64; parse_request "$2"'
        wire = request_line("prepare", "cx23", "linux/amd64", NEW, OLD, DIGEST)
        for request, accepted in (
            (wire, True), (wire + b"\n", False), (wire[:-1] + b" shell\n", False),
            (wire.replace(b"cx23", b"cx33"), False), (wire.replace(b"prepare", b"delete"), False),
            (wire.replace(b"sha256:", b"tag:"), False), (wire.replace(b"cx23", b"cx\x0023"), False),
        ):
            with self.subTest(request=request), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "request"
                path.write_bytes(request)
                result = subprocess.run(["bash", "-c", command, "test", self.guest, path],
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, accepted)

    def test_guest_needs_exact_publisher_evidence(self):
        command = ('source "$1"; scratch=$2; peer="$scratch"; '
                   'verify_publisher "$3" "$4"')
        digest = "sha256:" + hashlib.sha256(b"index").hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            fake = path / "gh"
            fake.write_text('#!/bin/bash\nif [[ $1 == --version ]]; then echo "gh version 2.97.0 (test)"; '
                            'else [[ $* == *"--source-digest ' + SOURCE + '"* && '
                            '$(cat "$3") == index && $(cat "$5") == bundle ]]; fi\n')
            fake.chmod(0o700)
            for proof, expected_digest, accepted in (
                (b"aW5kZXg=\nYnVuZGxl\n", digest, True),
                (b"aW5kZXg=\nYnVuZGxl\n", DIGEST, False),
                (b"aW5kZXg=\nYm9ndXM=\n", digest, False),
                (b"aW5kZXg=\nYnVuZGxl", digest, False),
                (b"aW5kZXg=\nYnVuZGxl\n\n", digest, False),
                (b"aW5kZXg=\nYnVuZGxl\x00\n", digest, False),
            ):
                with self.subTest(proof=proof, digest=expected_digest):
                    (path / "proof").write_bytes(proof)
                    result = subprocess.run(["bash", "-c", command, "test", self.guest, path,
                                             expected_digest, SOURCE], capture_output=True, check=False)
                    self.assertEqual(result.returncode == 0, accepted)

    def test_guest_and_coordinator_agree_on_reviewed_inputs_and_frontend_only_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.check_output(["git", "-C", temp, *args], stderr=subprocess.DEVNULL)

            def commit():
                git("add", "--all")
                git("-c", "user.name=Fixture", "-c", "user.email=fcos@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Fixture")
                return git("rev-parse", "HEAD").decode().strip()

            git("init", "-q")
            for name in RELEASE_PATHS:
                path = root / name
                if name.endswith("fcos-security"):
                    path /= "config.yaml"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("frozen\n")
            fixture = root / "scripts/integration_runtime_contract.py"
            fixture.write_text(f'FRONTEND_DIGEST = "{DIGEST}"\nFRONTEND_SOURCE_COMMIT = "{SOURCE}"\nAPP_ROLE = "original"\n')
            foundation = commit()
            fixture.write_text(f'FRONTEND_DIGEST = "sha256:{"9" * 64}"\nFRONTEND_SOURCE_COMMIT = "{SOURCE}"\nAPP_ROLE = "original"\n')
            candidate = commit()
            command = (
                'source "$1"; git_object() { git -C "$repo" "$@"; }; '
                'repo=$2; foundation=$3; mapfile -t inputs < <(grep -vE "^(#|$)" "$4"); '
                'frozen_sources=(); for path in "${inputs[@]}"; do '
                '[[ "$path" == "$contract" ]] || frozen_sources+=("$path"); done; '
                'frontend_only "$5" && fingerprint "$5"'
            )
            paths = self.guest.with_name("fcos-lab-release-paths.txt")
            def guest(revision):
                return subprocess.run(["bash", "-c", command, "test", self.guest, root,
                                       foundation, paths, revision], capture_output=True, check=False)

            accepted = guest(candidate)
            self.assertEqual(accepted.returncode, 0)
            self.assertEqual(accepted.stdout.decode().strip(), source_release(root, candidate).fingerprint)
            fixture.write_text(f'FRONTEND_DIGEST = "sha256:{"9" * 64}"\nFRONTEND_SOURCE_COMMIT = "{SOURCE}"\nAPP_ROLE = "changed"\n')
            self.assertNotEqual(guest(commit()).returncode, 0)
            fixture.write_text(f'FRONTEND_DIGEST = "sha256:{"9" * 64}"\nFRONTEND_SOURCE_COMMIT = "{SOURCE}"\nAPP_ROLE = "original"\n')
            (root / "scripts/production-migrate.php").write_text("changed\n")
            self.assertNotEqual(guest(commit()).returncode, 0)


if __name__ == "__main__":
    unittest.main()
