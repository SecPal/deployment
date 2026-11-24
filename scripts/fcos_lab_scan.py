#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Reevaluate signed Lab OCI inputs against a single current scanner snapshot."""

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory

from fcos_lab_rollout_adapter import (
    ARCHIVE_MAX, DIGEST, admission_governance, admit_component_update,
    api_native_attempt, download_publisher_artifact, verified_backend_archive, verified_frontend_archive,
)


def digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def timestamp():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def archived_material(product, pin, gh, *, current):
    """Read the native archives and the SPDX identities from the verified receipt."""
    if product == "frontend":
        with verified_frontend_archive(pin, gh=gh, current=current) as (_, run, attempt, children, _, root):
            material = {}
            for key, subject in children.items():
                _, platform = key
                arch = platform.removeprefix("linux/")
                native = root / arch
                download_publisher_artifact(gh, product, run, pin.source,
                                            f"frontend-native-{arch}-{run}-{attempt}", native, ARCHIVE_MAX)
                evaluation = json.loads((root / "qualification" / "scan" / arch / "evaluation.json").read_bytes())
                material[key] = (subject, native, evaluation["syft"]["spdx_digest"])
            yield material
    elif product == "api":
        with verified_backend_archive(pin, gh=gh, current=current) as (_, run, attempt, children, pair, _, root):
            material = {}
            for platform in sorted({key[1] for key in children}):
                arch = platform.removeprefix("linux/")
                native = root / arch
                producer = api_native_attempt(pair, platform, attempt)
                download_publisher_artifact(gh, product, run, pin.source,
                                            f"api-native-{arch}-{run}-{producer}", native, ARCHIVE_MAX)
                for role, role_record in pair["images"].items():
                    item, = (item for item in role_record["platforms"] if item["subject"]["platform"] == platform)
                    key = role, platform
                    material[key] = (children[key], native / role, item["sbom_sha256"])
            yield material
    else:
        raise ValueError("unknown comparison component")


class ScanSnapshot:
    def __init__(self, work, archives, *, database_root=None, refresh=True):
        governance = admission_governance()
        self.work = work
        self.databases = archives / "databases" if database_root is None else database_root
        self.cache = self.databases / "trivy"
        self.grype_archive = archives / "grype.tar.gz"
        flow = governance / ".github/workflows/reusable-vulnerability-reevaluation.yml"
        pins = dict(re.findall(
            r"^\s+(GRYPE_ARCHIVE_SHA256|TRIVY_ARCHIVE_SHA256|TRIVY_VERSION): ([0-9a-f.]+)\s*$",
            flow.read_text(encoding="utf-8"), flags=re.MULTILINE,
        ))
        if set(pins) != {"GRYPE_ARCHIVE_SHA256", "TRIVY_ARCHIVE_SHA256", "TRIVY_VERSION"}:
            raise ValueError("canonical scanner pins unavailable")
        self.trivy_digest = "sha256:" + pins["TRIVY_ARCHIVE_SHA256"]
        self.trivy_version = pins["TRIVY_VERSION"]
        self.ignore = governance / "policies/trivy-repository-scan-ignore-v1.yaml"

        spec = spec_from_file_location("secpal_reevaluation", governance / "scripts/secpal-vulnerability-reevaluation.py")
        self.evaluation = module_from_spec(spec)
        spec.loader.exec_module(self.evaluation)
        self.trivy = self.extract(archives / "trivy.tar.gz", "trivy", self.trivy_digest)
        if refresh:
            grype = self.extract(self.grype_archive, "grype", "sha256:" + pins["GRYPE_ARCHIVE_SHA256"])
            self.command(grype, ["db", "update"], environment={"GRYPE_DB_CACHE_DIR": str(self.databases / "grype"),
                                                              "GRYPE_CHECK_FOR_APP_UPDATE": "false"})
            for operation in ("--download-db-only", "--download-java-db-only"):
                self.trivy_command(["image", operation, "--cache-dir", str(self.cache)])
        self.trivy_database = self.trivy_snapshot()

    def extract(self, archive, name, expected):
        if not archive.is_file() or archive.stat().st_size > ARCHIVE_MAX or digest(archive) != expected:
            raise ValueError("scanner archive differs from the canonical pin")
        executable = self.work / name
        with tarfile.open(archive, "r:gz") as package:
            member = package.getmember(name)
            if not member.isfile() or not 0 < member.size <= 256 * 1024**2:
                raise ValueError("canonical scanner executable is unavailable")
            with package.extractfile(member) as source, executable.open("xb") as output:
                shutil.copyfileobj(source, output)
        executable.chmod(0o500)
        return executable

    def command(self, executable, args, *, directory=None, environment=None):
        config = self.work / "scanner-config.yaml"
        config.write_text("{}\n", encoding="ascii")
        subprocess.run(
            [executable, "--config", config, *args], cwd=directory, check=True, timeout=600,
            env={"PATH": os.defpath, "HOME": str(self.work), **(environment or {})},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def trivy_command(self, args, *, directory=None):
        self.command(self.trivy, [args[0], "--skip-version-check", *args[1:]], directory=directory)

    def trivy_snapshot(self):
        records = []
        for scanner, directory in (("trivy", "db"), ("trivy-java", "java-db")):
            root = self.cache / directory
            metadata = json.loads((root / "metadata.json").read_bytes())
            records.append(self.evaluation.database_identity(scanner, metadata, root))
        return self.evaluation.combine_database_identities(records)

    def scan(self, product, platform, artifact):
        subject_digest, native, signed_spdx = artifact
        if re.fullmatch(DIGEST, subject_digest) is None or digest(native / "syft.spdx.json") != signed_spdx:
            raise ValueError("native SPDX differs from the signed publisher receipt")
        image = native / "image"
        manifest = image / "blobs" / "sha256" / subject_digest.removeprefix("sha256:")
        descriptor, = json.loads((image / "index.json").read_bytes())["manifests"]
        if descriptor["digest"] != subject_digest or digest(manifest) != subject_digest:
            raise ValueError("native image differs from the signed platform subject")
        document = json.loads(manifest.read_bytes())
        for blob in (document["config"], *document["layers"]):
            value = blob["digest"]
            if re.fullmatch(DIGEST, value) is None:
                raise ValueError("invalid native OCI blob digest")
            path = image / "blobs" / "sha256" / value.removeprefix("sha256:")
            if path.stat().st_size != blob["size"] or digest(path) != value:
                raise ValueError("native OCI blob differs from the signed manifest")

        engine = self.evaluation
        subject = {"oci_digest": subject_digest, "platform": platform}
        association = json.loads((native / "association.json").read_bytes())
        spdx = native / "syft.spdx.json"
        engine.verify_syft_association(association, spdx.read_bytes(), subject)
        inventory = {"format": "SPDX", "subject": subject, "spdx_digest": signed_spdx}
        with TemporaryDirectory(prefix="native-", dir=self.work) as directory:
            root = Path(directory)
            raw, metadata, provenance = (root / name for name in ("grype.json", "grype-metadata.json", "grype-input.json"))
            engine.scan_verified_grype(self.grype_archive, spdx, association, subject, self.databases / "grype",
                                       raw, metadata, provenance)
            grype = engine.adapt_grype(json.loads(raw.read_bytes()), json.loads(metadata.read_bytes()),
                                       json.loads(provenance.read_bytes()), spdx.read_bytes(), association)
            reference = f"ghcr.io/secpal/{product}"
            staged = root / reference
            staged.parent.mkdir(parents=True)
            shutil.copytree(image, staged)
            native_report = root / "trivy.json"
            self.trivy_command([
                "image", "--scanners", "vuln", "--format", "json", "--show-suppressed",
                "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan",
                "--parallel", "2", "--cache-dir", str(self.cache), "--platform", platform, "--ignorefile", str(self.ignore),
                "--output", str(native_report), "--input", f"{reference}@{subject_digest}",
            ], directory=root)
            metadata = engine.scanner_run_metadata("trivy", self.trivy_database, subject, self.trivy_version,
                                                  self.trivy_digest, timestamp())
            trivy = engine.adapt_trivy(json.loads(native_report.read_bytes()), metadata)
        return engine.assemble_evaluation(subject, inventory, [grype, trivy], timestamp())


def compare_archives(product, installed, selected, gh, archives):
    """Generate both sides from the same snapshots and apply the existing policy."""
    with ExitStack() as stack:
        previous = stack.enter_context(archived_material(product, installed, gh, current=False))
        candidate = stack.enter_context(archived_material(product, selected, gh, current=True))
        temporary = Path(stack.enter_context(TemporaryDirectory(prefix="fcos-lab-scans-")))
        return compare_material(product, previous, candidate, ScanSnapshot(temporary, archives))


def compare_material(product, previous, candidate, scanner):
    if not previous or set(previous) != set(candidate):
        raise ValueError("comparison has mismatched platform roles")
    evidence = {
        "installed": {key: value[0] for key, value in previous.items()},
        "proposed": {key: value[0] for key, value in candidate.items()},
        "previous": {key: scanner.scan(product, key[1], value) for key, value in previous.items()},
        "candidate": {key: scanner.scan(product, key[1], value) for key, value in candidate.items()},
        "exposure_unchanged": True,
    }
    if scanner.trivy_snapshot() != scanner.trivy_database:
        raise ValueError("the shared Trivy snapshot changed during comparison")
    admit_component_update(**evidence, observed_at=timestamp())
    return evidence
