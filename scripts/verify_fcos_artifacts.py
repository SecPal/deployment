#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT
"""Offline verification of the pinned public FCOS bootstrap artifact cache."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


STAGES = frozenset(
    {
        "image.x86_64.signature",
        "tool.ignition_validator.digest",
        "pins.read",
        "cache.verify",
        "installer.key",
        "installer.x86_64.rpm",
        "installer.aarch64.rpm",
        "installer.output",
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


def command(argv, *, timeout=60, binary=False, input_data=None):
    result = subprocess.run(
        argv, capture_output=True, text=not binary, timeout=timeout,
        input=input_data, env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode:
        raise VerificationError("artifact.tool.failed")
    return result


def admit_rpm_signature(status, fingerprint):
    keys = re.findall(
        r"^\s*Header .* Signature, key ID ([a-f0-9]{8,40}): OK[ \t]*$",
        status,
        re.MULTILINE | re.IGNORECASE,
    )
    if len(keys) != 1 or not fingerprint.lower().endswith(keys[0].lower()):
        raise VerificationError("artifact.signature.invalid")
    if "Payload SHA256 digest: OK" not in status:
        raise VerificationError("artifact.signature.invalid")


def admit_rpm_payload(observed, expected, binary, digest, architecture):
    machine = {"x86_64": 62, "aarch64": 183}[architecture]
    if (observed != expected or binary[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(binary[18:20], "little") != machine):
        raise VerificationError("artifact.installer.identity.invalid")
    admit_digest(hashlib.sha256(binary).hexdigest(), digest)


def rpm_trust(keyring, scratch, fingerprint):
    gpg = ["gpg", "--homedir", str(keyring), "--batch", "--no-auto-key-retrieve"]
    public_key = scratch / "fedora-release.asc"
    public_key.write_text(command([*gpg, "--armor", "--export", fingerprint]).stdout)
    identity = command([*gpg, "--with-colons", "--show-keys", str(public_key)]).stdout
    primary, found = False, []
    for line in identity.splitlines():
        fields = line.split(":")
        if fields[0] in {"pub", "sub"}:
            primary = fields[0] == "pub"
        if primary and fields[0] == "fpr":
            found.append(fields[9])
    if found != [fingerprint]:
        raise VerificationError("artifact.signature.invalid")
    database = scratch / "rpmdb"
    database.mkdir(mode=0o700)
    command(["rpm", "--dbpath", str(database), "--initdb"])
    command(["rpmkeys", "--dbpath", str(database), "--import", str(public_key)])
    return database


def verify_installer(cache, lock, scratch, database, architecture):
    installer = lock["installer"]
    version, release = installer["version"], installer["release"]
    pin = installer["architectures"][architecture]
    filename = f"coreos-installer-{version}-{release}.{architecture}.rpm"
    with (cache / filename).open("rb") as package:
        raw = package.read(8 * 1024 * 1024)
        if package.read(1):
            raise VerificationError("artifact.digest.invalid")
    admit_digest(hashlib.sha256(raw).hexdigest(), pin["rpm_sha256"])
    rpm = scratch / filename
    rpm.write_bytes(raw)
    status = command(["rpmkeys", "--dbpath", str(database), "--checksig", "--verbose", str(rpm)])
    admit_rpm_signature(status.stdout, lock["fedora_signer"])
    identity = command(["rpm", "--dbpath", str(database), "-qp", "--queryformat",
                        "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}", str(rpm)]).stdout
    expected = f"coreos-installer|{installer['epoch']}|{version}|{release}|{architecture}"
    payload = command(["rpm2cpio", str(rpm)], binary=True).stdout
    binary = command(
        ["cpio", "-i", "--quiet", "--to-stdout", "./usr/bin/coreos-installer", "usr/bin/coreos-installer"],
        input_data=payload, binary=True,
    ).stdout
    admit_rpm_payload(identity, expected, binary, pin["binary_sha256"], architecture)
    return {
        "architecture": architecture, "nevra": identity, "rpm_sha256": pin["rpm_sha256"],
        "binary_sha256": pin["binary_sha256"], "signer": lock["fedora_signer"],
    }, binary


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


def verify(cache, lock, installer_only=None, output=None):
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
        database = at_stage("installer.key", lambda: rpm_trust(keyring, scratch, lock["fedora_signer"]))
        installers = []
        for architecture in (installer_only,) if installer_only else lock["architectures"]:
            receipt, binary = at_stage(
                f"installer.{architecture}.rpm",
                lambda: verify_installer(cache, lock, scratch, database, architecture),
            )
            installers.append(receipt)
        if installer_only:
            if output is not None:
                def save_binary():
                    with output.open("xb") as destination:
                        destination.write(binary)

                at_stage("installer.output", save_binary)
            return {"code": "installer.rpm.verified", **installers[0]}
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
        return assemble_verification(lock["release"], records, installers)


def assemble_verification(release, records, installers):
    return {
        "code": "artifacts.verified",
        "release": release,
        "records": records,
        "tools": "butane-and-ignition-validator-verified",
        "installers": installers,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path)
    parser.add_argument("--installer-only", choices=("x86_64", "aarch64"))
    parser.add_argument("--output-binary", type=Path)
    args = parser.parse_args()
    if args.output_binary is not None and args.installer_only is None:
        parser.error("--output-binary requires --installer-only")
    try:
        root = Path(__file__).resolve().parents[1]
        lock = at_stage(
            "pins.read",
            lambda: json.loads((root / "config/fcos/artifacts.json").read_text()),
        )
        result = at_stage(
            "cache.verify",
            lambda: verify(args.cache, lock, args.installer_only, args.output_binary),
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except VerificationError as error:
        print(json.dumps({"code": error.code, "stage": error.stage}))
    except Exception:
        print('{"code":"artifact.verification.failed"}')
    return 1


if __name__ == "__main__":
    sys.exit(main())
