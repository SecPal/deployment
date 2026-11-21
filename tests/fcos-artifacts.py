#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Digest and signer admission reject altered artifacts and wrong signers."""
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import ast
import inspect
import symtable
import textwrap

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "fcos_artifacts", ROOT / "scripts/verify_fcos_artifacts.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class ArtifactTests(unittest.TestCase):
    def test_native_rpm_admission_requires_signature_metadata_digest_and_elf(self):
        lock = json.loads((ROOT / "config/fcos/artifacts.json").read_text())
        signer = lock["fedora_signer"]
        status = (
            f"    Header V4 RSA/SHA256 Signature, key ID {signer[-8:].lower()}: OK\n"
            "    Payload SHA256 digest: OK\n"
        )
        for architecture, machine in (("x86_64", 62), ("aarch64", 183)):
            with self.subTest(architecture=architecture):
                binary = b"\x7fELF\x02\x01\x01" + b"\0" * 11 + machine.to_bytes(2, "little")
                identity = f"coreos-installer|0|0.27.0|1.fc44|{architecture}"
                digest = hashlib.sha256(binary).hexdigest()
                module.admit_rpm_signature(status, signer)
                module.admit_rpm_payload(identity, identity, binary, digest, architecture)
                for altered in ("", status.replace("6d9f90a6", "deadbeef"),
                                status.replace("Payload SHA256 digest: OK", "")):
                    with self.assertRaises(module.VerificationError):
                        module.admit_rpm_signature(altered, signer)
                for wrong_identity, wrong_binary, wrong_digest in (
                    ("wrong", binary, digest),
                    (identity, binary + b"x", digest),
                    (identity, b"\0" * len(binary), hashlib.sha256(b"\0" * len(binary)).hexdigest()),
                ):
                    with self.assertRaises(module.VerificationError):
                        module.admit_rpm_payload(wrong_identity, identity, wrong_binary,
                                                 wrong_digest, architecture)

    def test_artifact_normalization_admission_and_assembly_are_pure(self):
        allowed = {"tuple", "VerificationError"}
        for function in (
            module.admit_digest,
            module.normalize_signature,
            module.admit_signature,
            module.assemble_verification,
        ):
            source = textwrap.dedent(inspect.getsource(function))
            pending = list(
                symtable.symtable(source, "artifact-pure", "exec").get_children()
            )
            while pending:
                scope = pending.pop()
                self.assertLessEqual(
                    {
                        symbol.get_name()
                        for symbol in scope.get_symbols()
                        if symbol.is_global() and symbol.is_referenced()
                    },
                    allowed,
                )
                pending.extend(scope.get_children())

    def test_semantic_stage_inventory_is_closed_and_declared(self):
        import json

        manifest = json.loads((ROOT / ".secpal/evidence-architecture.json").read_text())
        rows = {
            entry["id"]: entry
            for entry in manifest["external_operations"]
            if entry["id"].startswith("fcos-artifacts.")
        }
        self.assertEqual(
            set(rows), {"fcos-artifacts." + stage for stage in module.STAGES}
        )
        for name, row in rows.items():
            self.assertEqual(
                row,
                {
                    "id": name,
                    "reachable": True,
                    "fallible": True,
                    "trusted": True,
                    "diagnostic_identity": {"id": name, "kind": "semantic"},
                },
            )

    def test_signature_observation_failure_has_bounded_secret_free_stage(self):
        with patch.object(
            module.subprocess, "run", side_effect=OSError("SYNTHETIC-SECRET")
        ):
            with self.assertRaises(module.VerificationError) as caught:
                module.at_stage(
                    "image.aarch64.signature",
                    lambda: module.verify_signature(
                        Path("/unused"), Path("/unused"), Path("/unused"), "A" * 40
                    ),
                )
        self.assertEqual(caught.exception.stage, "image.aarch64.signature")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_modified_artifact_fails_digest_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(b"original")
            expected = hashlib.sha256(b"original").hexdigest()
            module.verify_digest(path, expected)
            path.write_bytes(b"modified")
            with self.assertRaises(module.VerificationError):
                module.verify_digest(path, expected)

    def test_valid_signature_requires_exact_trusted_fingerprint_and_exit_zero(self):
        fingerprint = "A" * 40
        status = "[GNUPG:] VALIDSIG " + fingerprint + " remaining-public-fields"
        module.admit_signature(module.normalize_signature(0, status), fingerprint)
        for exit_code, text, trusted in [
            (1, status, fingerprint),
            (0, status, "B" * 40),
            (0, "", fingerprint),
        ]:
            with self.subTest(exit_code=exit_code, trusted=trusted), self.assertRaises(
                module.VerificationError
            ):
                module.admit_signature(
                    module.normalize_signature(exit_code, text), trusted
                )


if __name__ == "__main__":
    unittest.main()
