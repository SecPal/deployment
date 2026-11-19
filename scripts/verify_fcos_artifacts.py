#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Offline verification of the pinned public FCOS bootstrap artifact cache."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


STAGES = frozenset(
    {
        "image.x86_64.signature",
        "tool.ignition_validator.digest",
        "pins.read",
        "cache.verify",
        "installer.index",
        "tool.ignition_validator.signature",
        "image.aarch64.digest",
        "key.import",
        "image.x86_64.digest",
        "tool.butane.digest",
        "tool.butane.signature",
        "image.aarch64.signature",
    }
)


class VerificationError(ValueError):
    def __init__(self, code, stage="cache.verify"):
        self.code = code
        self.stage = stage if stage in STAGES else "cache.verify"
        super().__init__(code)


def at_stage(stage, operation):
    try:
        return operation()
    except VerificationError as error:
        if error.stage != "cache.verify":
            raise
        raise VerificationError(error.code, stage) from None
    except Exception:
        raise VerificationError("artifact.verification.failed", stage) from None


def verify_digest(path, expected):
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        while chunk := artifact.read(1024 * 1024):
            digest.update(chunk)
    admit_digest(digest.hexdigest(), expected)


def admit_digest(observed, expected):
    if observed != expected:
        raise VerificationError("artifact.digest.invalid")


def normalize_signature(exit_code, status):
    return {
        "exit_code": exit_code,
        "fingerprints": tuple(
            line.split()[2]
            for line in status.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ")
        ),
    }


def admit_signature(observed, expected):
    if observed["exit_code"] != 0 or observed["fingerprints"] != (expected,):
        raise VerificationError("artifact.signature.invalid")


def command(argv, *, timeout=60):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise VerificationError("artifact.tool.failed")
    return result


def verify_signature(keyring, artifact, signature, fingerprint):
    result = subprocess.run(
        [
            "gpg",
            "--homedir",
            str(keyring),
            "--batch",
            "--no-auto-key-retrieve",
            "--status-fd=1",
            "--verify",
            str(signature),
            str(artifact),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    admit_signature(normalize_signature(result.returncode, result.stdout), fingerprint)


def verify(cache, lock):
    with tempfile.TemporaryDirectory(prefix="secpal-fcos-verify-") as directory:
        scratch = Path(directory)
        keyring = scratch / "gnupg"
        keyring.mkdir(mode=0o700)
        at_stage(
            "key.import",
            lambda: command(
                [
                    "gpg",
                    "--homedir",
                    str(keyring),
                    "--batch",
                    "--import",
                    str(cache / "fedora.gpg"),
                ]
            ),
        )
        records = []
        for architecture, pin in lock["architectures"].items():
            name = f"fedora-coreos-{lock['release']}-metal.{architecture}.raw.xz"
            image = cache / name
            at_stage(
                f"image.{architecture}.digest",
                lambda: verify_digest(image, pin["image_sha256"]),
            )
            at_stage(
                f"image.{architecture}.signature",
                lambda: verify_signature(
                    keyring, image, Path(str(image) + ".sig"), lock["fedora_signer"]
                ),
            )
            records.append(
                {
                    "architecture": architecture,
                    "image": "digest-and-signature-verified",
                }
            )
        for key, name, signature in [
            ("butane", f"butane-v{lock['butane']['version']}", "butane.asc"),
            ("ignition_validator", "ignition-validate", "ignition-validate.asc"),
        ]:
            at_stage(
                f"tool.{key}.digest",
                lambda: verify_digest(cache / name, lock[key]["x86_64_sha256"]),
            )
            at_stage(
                f"tool.{key}.signature",
                lambda: verify_signature(
                    keyring, cache / name, cache / signature, lock["fedora_signer"]
                ),
            )
        at_stage(
            "installer.index",
            lambda: verify_digest(
                cache / "installer-manifest.json",
                lock["installer"]["image"].split("sha256:")[1],
            ),
        )
        return assemble_verification(lock["release"], records)


def assemble_verification(release, records):
    return {
        "code": "artifacts.verified",
        "release": release,
        "records": records,
        "tools": "butane-and-ignition-validator-verified",
        "installer": "index-digest-only; blobs-and-publisher-admission-pending",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path)
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        lock = at_stage(
            "pins.read",
            lambda: json.loads((root / "config/fcos/artifacts.json").read_text()),
        )
        result = at_stage("cache.verify", lambda: verify(args.cache, lock))
        print(json.dumps(result, sort_keys=True))
        return 0
    except VerificationError as error:
        print(json.dumps({"code": error.code, "stage": error.stage}))
    except Exception:
        print('{"code":"artifact.verification.failed"}')
    return 1


if __name__ == "__main__":
    sys.exit(main())
