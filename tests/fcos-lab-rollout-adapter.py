#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Test the FCOS lab adapter without guest credentials or external services."""

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fcos_lab_rollout_adapter import Frontend, check_host_pin, native_children, prepare_request, release_witness, request_line, ssh_arguments
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

    def test_only_one_exact_ed25519_host_pin_is_admitted(self):
        raw = b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))
        public = base64.b64encode(raw)
        entry = b"cx23 ssh-ed25519 " + public + b"\n"
        self.assertIsNone(check_host_pin("cx23", entry))
        for host_pin in (
            entry.replace(b"cx23 ", b"* "), entry.replace(b"cx23 ", b"cx33 "),
            entry.replace(b"cx23 ", b"cx23,cx33 "), entry + entry, b"@cert-authority " + entry,
            entry.replace(public, b"A" * 68),
        ):
            with self.subTest(host_pin=host_pin), self.assertRaises(ValueError):
                check_host_pin("cx23", host_pin)

    def test_release_writes_a_single_child_under_the_exact_witness(self):
        witness = "00000000-0000-4000-8000-000000000001"
        child = "00000000-0000-4000-8000-000000000002"
        units = {}

        def request(site, path, status, *, method="GET", data=None):
            self.assertEqual(site, "https://api.example.test")
            base = "/v1/organizational-units"
            if path == base + "/" + witness:
                self.assertEqual((method, status), ("GET", 200))
                return json.dumps({"data": {"id": witness, "name": "FCOS lab rollout witness"}})
            if path == base + "/" + witness + "/descendants":
                self.assertEqual((method, status), ("GET", 200))
                return json.dumps({"data": list(units.values())})
            if path == "/sanctum/csrf-cookie":
                self.assertEqual((method, status), ("GET", 204))
                return ""
            self.assertEqual((path, method, status), (base, "POST", 201))
            self.assertEqual(data["parent_id"], witness)
            self.assertEqual(data["name"], f"FCOS rollout receipt {NEW.fingerprint}")
            self.assertEqual(data["type"], "company")
            self.assertFalse(units, "repeated acceptance must not create another child")
            units[child] = {"id": child, "name": data["name"], "type": data["type"]}
            return json.dumps({"data": units[child]})

        for _ in range(2):
            release_witness(request, "https://api.example.test", witness, NEW.fingerprint)
        self.assertEqual(len(units), 1)

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
        lab_digest = "sha256:" + "9" * 64
        lab_source = "8" * 40
        override = f'LAB_FRONTEND_DIGEST = "{lab_digest}"\nLAB_FRONTEND_SOURCE_COMMIT = "{lab_source}"\n'
        self.assertEqual(Frontend.from_source(source + override), Frontend(lab_digest, lab_source))
        for malformed in (source + source, source.replace(DIGEST, "stable"), source.replace(SOURCE, "main"),
                          source + override.splitlines()[0] + "\n", source + override + override):
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

    def test_guest_image_config_id_accepts_native_podman_forms(self):
        command = ('source "$1"; normalize_image "$2"; '
                   'normalize_image "$3"')
        value = "a" * 64
        result = subprocess.run(["bash", "-c", command, "test", self.guest, value, "sha256:" + value],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.stdout.splitlines(), [value, value])

    def test_guest_rejects_extra_frontend_override_and_duplicate_worker(self):
        expected = "secpal-int-haproxy01-scheduler\nsecpal-int-haproxy01-worker-general\nsecpal-int-haproxy01-worker-hash-chain"
        command = ('source "$1"; dropin_dir="$2"; names="$3"; '
                   'runtime() { printf "%s\n" "$names"; }; exact_rollout_dropin && singleton_roles')
        with tempfile.TemporaryDirectory() as directory:
            def check(names):
                return subprocess.run(["bash", "-c", command, "test", self.guest, directory, names],
                                      capture_output=True, check=False).returncode
            self.assertEqual(check(expected), 0)
            self.assertNotEqual(check(expected + "\nsecpal-int-duplicate-worker-hash-chain"), 0)
            (Path(directory) / "99-extra.conf").touch()
            self.assertNotEqual(check(expected), 0)

    def test_worker_identity_comes_from_the_actual_container(self):
        command = ('source "$1"; reported="$2"; '
                   'runtime() { [[ "${!#}" == secpal-int-haproxy01-worker-general ]] && '
                   'printf "%s\n" "$reported"; }; worker_hostname general')
        for hostname, accepted in (("deadbeefcafe", True), ("worker-general", True), ("", False), ("wrong role!", False)):
            with self.subTest(hostname=hostname):
                checked = subprocess.run(["bash", "-c", command, "test", self.guest, hostname],
                                         capture_output=True, text=True, check=False)
                self.assertEqual(checked.returncode == 0, accepted)
                self.assertEqual(checked.stdout, hostname + "\n" if accepted else "")

    def test_recording_acceptance_rechecks_fixture_drift(self):
        command = ('source "$1"; state=$2; '
                   'matches() { [[ "$1" == checked ]]; }; '
                   'check_installed() { [[ "$state" == intact ]]; }; '
                   'singleton_roles() { return 0; }; '
                   'save() { printf "%s %s\n" "$1" "$2"; }; '
                   'persist_accepted checked')
        for layout in ("intact", "drifted"):
            result = subprocess.run(["bash", "-c", command, "test", self.guest, layout],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode == 0, layout == "intact")
            self.assertEqual(result.stdout, "accepted.json checked\n" if layout == "intact" else "")

    def test_frontend_restart_preserves_the_live_gateway(self):
        command = (
            'source "$1"; scenario=$2; running_gateway=original; '
            'runtime() { case "$1" in '
            'systemctl) [[ "$*" == "systemctl --user is-active --quiet $slot-edge-network.service" '
            '&& "$scenario" != missing-network ]];; '
            'podman) [[ "${!#}" == "$slot-gateway" ]] && printf "%s\n" "$running_gateway";; '
            '*) return 1;; esac; }; '
            'timeout() { [[ "$*" == *"systemctl --user --job-mode=ignore-requirements restart $frontend.service" ]] '
            '|| return 1; if [[ "$scenario" == gateway-changed ]]; then running_gateway=replaced; fi; }; '
            'restart_frontend'
        )
        for scenario, allowed in (("healthy", True), ("missing-network", False), ("gateway-changed", False)):
            with self.subTest(scenario=scenario):
                result = subprocess.run(["bash", "-c", command, "test", self.guest, scenario],
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, allowed)

    def test_guest_needs_exact_publisher_evidence(self):
        command = ('source "$1"; scratch=$2; peer="$scratch"; platform=linux/amd64; '
                   'verify_publisher "$3" "$4"')
        digest = "sha256:" + hashlib.sha256(b"index").hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            fake = path / "gh"
            fake.write_text('#!/bin/bash\nif [[ $1 == --version ]]; then echo "gh version 2.97.0 (test)"; '
                            'else [[ $* == *"--source-digest ' + SOURCE + '"* && '
                            '$(cat "$3") == index && $(cat "$5") == bundle ]]; fi\n')
            fake.chmod(0o700)
            executable_hash = hashlib.sha256(fake.read_bytes()).hexdigest()
            (path / "gh-binary-sha256.txt").write_text(f"linux/amd64 {executable_hash}\n")
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
            (path / "proof").write_bytes(b"aW5kZXg=\nYnVuZGxl\n")
            with fake.open("a") as altered:
                altered.write("# modified after approval\n")
            result = subprocess.run(["bash", "-c", command, "test", self.guest, path, digest, SOURCE],
                                    capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)

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
            original = f'FRONTEND_DIGEST = "{DIGEST}"\nFRONTEND_SOURCE_COMMIT = "{SOURCE}"\nAPP_ROLE = "original"\n'
            fixture.write_text(original)
            foundation = commit()
            lab = f'LAB_FRONTEND_DIGEST = "sha256:{"9" * 64}"\nLAB_FRONTEND_SOURCE_COMMIT = "{"8" * 40}"\n'
            fixture.write_text(original + lab)
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
            fixture.write_text(original.replace(DIGEST, "sha256:" + "a" * 64) + lab)
            self.assertNotEqual(guest(commit()).returncode, 0)
            fixture.write_text((original + lab).replace('APP_ROLE = "original"', 'APP_ROLE = "changed"'))
            self.assertNotEqual(guest(commit()).returncode, 0)
            fixture.write_text(original + lab.splitlines()[0] + "\n")
            self.assertNotEqual(guest(commit()).returncode, 0)
            fixture.write_text(original + lab)
            (root / "scripts/production-migrate.php").write_text("changed\n")
            self.assertNotEqual(guest(commit()).returncode, 0)


if __name__ == "__main__":
    unittest.main()
