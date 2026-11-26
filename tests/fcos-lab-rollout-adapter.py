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
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from fcos_lab_rollout_adapter import Backend, Frontend, backend_declaration, backend_proof, backend_request, check_host_pin, native_children, prepare_request, release_witness, request_line, ssh_arguments, verify_dispatch_authority
from fcos_lab_rollout import RELEASE_PATHS, Release, source_release
from fcos_lab_rollout_adapter import frontend_acceptance, publisher_children

OLD = Release("1" * 40, "2" * 64)
NEW = Release("3" * 40, "4" * 64)
DIGEST = "sha256:" + "5" * 64
SOURCE = "7" * 40


class AdapterContract(unittest.TestCase):
    def test_missing_retained_predecessor_cannot_fall_back_to_actions(self):
        from fcos_lab_rollout_adapter import FRONTEND_ARCHIVE, verified_frontend_archive

        with (tempfile.TemporaryDirectory() as work,
              patch("fcos_lab_rollout_adapter.download_publisher_artifact") as download,
              patch("fcos_lab_rollout_adapter.github_json") as api):
            pin = Frontend(DIGEST, SOURCE, FRONTEND_ARCHIVE)
            with self.assertRaises(FileNotFoundError):
                with verified_frontend_archive(pin, current=False, retained=Path(work) / "missing"):
                    self.fail("missing predecessor was accepted")
            download.assert_not_called()
            api.assert_not_called()

    def test_exact_native_staging_rejects_altered_blobs_and_excludes_extra_files(self):
        import tarfile
        from fcos_lab_rollout_adapter import make_oci_archive

        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            layout = root / "image"
            blobs = layout / "blobs" / "sha256"
            blobs.mkdir(parents=True)

            def blob(content):
                digest = hashlib.sha256(content).hexdigest()
                (blobs / digest).write_bytes(content)
                return {"digest": "sha256:" + digest, "size": len(content)}

            config = blob(b'{"architecture":"amd64"}')
            layer = blob(b"layer")
            manifest = blob(json.dumps({"config": config, "layers": [layer]}).encode())
            (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
            (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [manifest]}))
            (blobs / "extraneous").write_bytes(b"unexpected")
            result = root / "native.tar"
            make_oci_archive(layout, manifest["digest"], result)
            with tarfile.open(result) as archive:
                self.assertCountEqual(archive.getnames(), ["oci-layout", "index.json"] + [
                    "blobs/sha256/" + item["digest"].removeprefix("sha256:")
                    for item in (config, layer, manifest)
                ])
            (blobs / layer["digest"].removeprefix("sha256:")).write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "blob differs"):
                make_oci_archive(layout, manifest["digest"], root / "wrong.tar")

    def test_capture_and_restore_use_verified_exact_native_material(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        import fcos_lab_rollout_adapter as adapter
        import fcos_lab_scan as scan

        platform = "linux/amd64"
        gh = Path("/trusted/gh")
        for product, role in (("api", "php-fpm"), ("frontend", "frontend")):
            with self.subTest(product=product), tempfile.TemporaryDirectory() as work:
                root = Path(work)
                config = root / "controller"
                config.mkdir(mode=0o700)
                publisher = root / "publisher-download"
                qualification = publisher / "qualification"
                qualification.mkdir(parents=True)
                native = publisher / "amd64"
                if product == "api":
                    native /= role
                image = native / "image"
                blobs = image / "blobs" / "sha256"
                blobs.mkdir(parents=True)
                config_bytes = b'{"architecture":"amd64"}'
                config_digest = hashlib.sha256(config_bytes).hexdigest()
                (blobs / config_digest).write_bytes(config_bytes)
                manifest = json.dumps({
                    "config": {"digest": "sha256:" + config_digest, "size": len(config_bytes)},
                    "layers": [],
                }).encode()
                child = "sha256:" + hashlib.sha256(manifest).hexdigest()
                (blobs / child.removeprefix("sha256:")).write_bytes(manifest)
                (image / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
                (image / "index.json").write_text(json.dumps({
                    "schemaVersion": 2, "manifests": [{"digest": child, "size": len(manifest)}],
                }))
                spdx = native / "syft.spdx.json"
                spdx.write_bytes(b'{"spdxVersion":"SPDX-2.3"}')
                inventory = scan.digest(spdx)
                subject = {"oci_digest": child, "platform": platform}
                association = native / "association.json"
                association.write_text(json.dumps(subject))
                children = {(role, platform): child}

                def verify_association(observed, contents, expected):
                    if observed != expected or contents != spdx.read_bytes():
                        raise ValueError("unexpected SPDX association")

                report = {"database": {"next_update": "2026-11-25T13:00:00Z"}}
                if product == "api":
                    item = {"subject": subject, "sbom_sha256": inventory}
                    pair = {"workflow": {"run_id": "10", "run_attempt": "1"},
                            "images": {"php-fpm": {"candidate_index_digest": DIGEST, "platforms": [item]},
                                       "nginx": {"candidate_index_digest": DIGEST}}}
                    receipt = qualification / "unpublished-runtime-pair.json"
                    receipt.write_text(json.dumps(pair))
                    (qualification / "source-security.json").write_text(json.dumps(report))
                    pin = Backend(SOURCE, DIGEST, DIGEST, scan.digest(receipt), "2026-11-25T12:00:00Z",
                                  None, adapter.API_ARCHIVE)
                    downloaded = (gh, 10, 1, children, qualification, publisher)
                    acquire = "qualified_backend_source"
                    verifier = "verify_api_candidate"
                else:
                    proof_root = qualification / "publisher"
                    proof_root.mkdir()
                    proof = tuple(proof_root / name for name in adapter.FRONTEND_PROOF)
                    proof[-1].write_bytes(b"protected OCI index")
                    proof[-2].write_text(json.dumps({"records": [{"workflow_run_id": "10",
                                                                   "workflow_run_attempt": "1"}]}))
                    (proof_root / "source-security.json").write_text(json.dumps(report))
                    independent = publisher / "repository-security"
                    independent.mkdir()
                    (independent / "result.json").write_text(json.dumps(report))
                    evaluation = qualification / "scan" / "amd64"
                    evaluation.mkdir(parents=True)
                    (evaluation / "evaluation.json").write_text(json.dumps({"syft": {"spdx_digest": inventory}}))
                    pin = Frontend(scan.digest(proof[-1]), SOURCE, adapter.FRONTEND_ARCHIVE)
                    downloaded = (gh, 10, 1, children, proof, publisher)
                    acquire = "qualified_frontend_source"
                    verifier = "verify_frontend_candidate"

                with (patch.object(adapter, "PRIVATE", config),
                      patch.object(adapter, acquire, return_value=nullcontext(downloaded)) as acquire_publisher,
                      patch.object(adapter, verifier, return_value=(children, {})) as verify,
                      patch.object(adapter, "verified_gh"),
                      patch.object(scan, "download_publisher_artifact") as download,
                      patch.object(scan, "admission_governance"),
                      patch.object(scan, "reevaluation_engine", return_value=SimpleNamespace(
                          verify_syft_association=verify_association))):
                    with scan.component_archive(product, pin, gh, current=True, preserve=True):
                        stored = adapter.retained_archive(product, pin)
                        self.assertEqual(stored.stat().st_mode & 0o777, 0o700)
                    acquire_publisher.side_effect = AssertionError("Actions is unavailable")
                    with scan.archived_material(product, pin, gh, current=False) as restored:
                        self.assertEqual(restored[role, platform][0], child)
                        restored_association = restored[role, platform][1] / "association.json"
                    verify.assert_called_once()
                    if product == "api":
                        self.assertEqual(verify.call_args.kwargs["selected"], (10, 1))
                    download.assert_not_called()
                    restored_association.write_text("{}")
                    with self.assertRaisesRegex(ValueError, "unexpected SPDX association"):
                        with scan.archived_material(product, pin, gh, current=False):
                            self.fail("corrupt retained input was accepted")
                    restored_association.unlink()
                    with self.assertRaises(FileNotFoundError):
                        with scan.archived_material(product, pin, gh, current=False):
                            self.fail("partial retained input was accepted")
                    acquire_publisher.assert_called_once()
                    download.assert_not_called()

    def test_retained_qualification_cannot_authorize_activation(self):
        from fcos_lab_rollout_adapter import API_ARCHIVE, FRONTEND_ARCHIVE, verified_backend_archive, verified_frontend_archive

        frontend = Frontend(DIGEST, SOURCE, FRONTEND_ARCHIVE)
        backend = Backend(SOURCE, DIGEST, DIGEST, DIGEST, "2026-11-23T00:00:00Z", None, API_ARCHIVE)
        for verify, pin in ((verified_frontend_archive, frontend), (verified_backend_archive, backend)):
            with self.assertRaisesRegex(ValueError, "cannot authorize"):
                with verify(pin, current=True, retained=Path("/retained")):
                    self.fail("historical qualification was used for activation")

    def test_protected_release_verification_accepts_the_direct_launch_identity(self):
        from types import SimpleNamespace
        from fcos_lab_rollout_adapter import admit_source_text

        # A script and its imported module have distinct Release classes.
        direct = SimpleNamespace(revision=NEW.revision, fingerprint=NEW.fingerprint)
        with (patch("fcos_lab_rollout_adapter.git", return_value=b"contract"),
              patch("fcos_lab_rollout_adapter.source_release", return_value=NEW)):
            self.assertEqual(admit_source_text(Path("/repo"), direct), "contract")
            direct.fingerprint = OLD.fingerprint
            with self.assertRaisesRegex(ValueError, "fingerprint differs"):
                admit_source_text(Path("/repo"), direct)

    def test_pending_candidate_can_use_refreshed_evaluations_for_the_same_fingerprint(self):
        from fcos_lab_rollout_adapter import FRONTEND_ARCHIVE, Frontend, archived_component_evidence

        refreshed = Release("9" * 40, NEW.fingerprint)
        unrelated = Release("8" * 40, "6" * 64)
        frontend = Frontend(DIGEST, SOURCE, FRONTEND_ARCHIVE)
        installed = Frontend(DIGEST, "1" * 40)
        for latest, expected in ((refreshed, refreshed), (unrelated, NEW)):
            with (self.subTest(latest=latest),
                  patch("fcos_lab_rollout_adapter.admit_source_text"),
                  patch("fcos_lab_rollout_adapter.git"),
                  patch("fcos_lab_rollout_adapter.Backend.from_source", return_value="same"),
                  patch("fcos_lab_rollout_adapter.Frontend.from_source", side_effect=[frontend, installed]),
                  patch("fcos_lab_rollout_adapter.archived_frontend_evidence") as compare):
                archived_component_evidence(Path("/repo"), NEW, OLD, latest)
                compare.assert_called_once_with(Path("/repo"), NEW, OLD, expected)

    def test_expired_installed_api_uses_exact_indexes_for_comparison_only(self):
        from contextlib import nullcontext
        from fcos_lab_rollout_adapter import Backend, installed_backend_children

        backend = Backend(SOURCE, "sha256:" + "1" * 64, "sha256:" + "2" * 64,
                          DIGEST, "2026-11-23T00:00:00Z", None)
        calls = []

        def fetch(role, index):
            calls.append((role, index))
            children = {"linux/amd64": "sha256:" + "3" * 64, "linux/arm64": "sha256:" + "4" * 64}
            return json.dumps({"manifests": [
                {"platform": {"os": "linux", "architecture": platform.split("/")[1]},
                 "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest}
                for platform, digest in children.items()
            ]}).encode(), b"verified-bundle"

        with patch("fcos_lab_rollout_adapter.api_registry_subjects", return_value=nullcontext((None, fetch))):
            subjects = installed_backend_children(backend)
        self.assertEqual(calls, [("php-fpm", backend.fpm), ("nginx", backend.nginx)])
        self.assertEqual(len(subjects), 4)

    def test_candidate_comparison_binds_both_roles_and_platforms(self):
        from fcos_lab_rollout_adapter import admit_component_update

        def inputs(prefix):
            children = {
                (role, platform): "sha256:" + str(prefix + i) * 64
                for i, (role, platform) in enumerate(
                    (role, platform)
                    for role in ("php-fpm", "nginx")
                    for platform in ("linux/amd64", "linux/arm64")
                )
            }
            evidence = {key: {"subject": {"platform": key[1], "oci_digest": digest}}
                        for key, digest in children.items()}
            return children, evidence

        installed, previous = inputs(1)
        proposed, candidate = inputs(5)
        expected = {"predecessor": {"gate_state": "ACTIONABLE"},
                    "candidate": {"gate_state": "REVIEW_REQUIRED"}, "review_required": []}
        with patch("fcos_lab_rollout_adapter.compare_component_risk", return_value=expected) as compare:
            report = admit_component_update(installed, proposed, previous, candidate,
                                            exposure_unchanged=True, observed_at="2026-11-24T12:00:00Z")
            self.assertEqual(set(report), set(proposed))
            self.assertEqual(compare.call_count, 4)
            self.assertTrue(all(entry["candidate"]["gate_state"] == "REVIEW_REQUIRED" for entry in report.values()))

            def frontend(records):
                return {("frontend", platform): value for (role, platform), value in records.items()
                        if role == "nginx"}

            front = [frontend(records) for records in (installed, proposed, previous, candidate)]
            self.assertEqual(set(admit_component_update(*front, exposure_unchanged=True,
                             observed_at="2026-11-24T12:00:00Z")), set(front[0]))
            with self.assertRaisesRegex(ValueError, "incomplete platform"):
                admit_component_update(installed, proposed, previous, front[3],
                                       exposure_unchanged=True, observed_at="2026-11-24T12:00:00Z")
            changed = dict(previous)
            changed["php-fpm", "linux/amd64"] = candidate["php-fpm", "linux/amd64"]
            with self.assertRaisesRegex(ValueError, "predecessor"):
                admit_component_update(installed, proposed, changed, candidate,
                                       exposure_unchanged=True, observed_at="2026-11-24T12:00:00Z")
            with self.assertRaisesRegex(ValueError, "exposure"):
                admit_component_update(installed, proposed, previous, candidate,
                                       exposure_unchanged=False, observed_at="2026-11-24T12:00:00Z")
            compare.return_value = dict(expected, review_required=[{"reason": "changed_observation"}])
            with self.assertRaisesRegex(ValueError, "comparison requires review"):
                admit_component_update(installed, proposed, previous, candidate,
                                       exposure_unchanged=True, observed_at="2026-11-24T12:00:00Z")

    def test_frontend_candidate_attestation_binds_native_platforms_and_scan_evidence(self):
        from fcos_lab_rollout_adapter import verify_frontend_candidate

        def put(path, value):
            data = json.dumps(value, sort_keys=True).encode()
            path.write_bytes(data)
            return "sha256:" + hashlib.sha256(data).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            publisher = root / "publisher"
            publisher.mkdir()
            (publisher / "pre-registry.bundle.json").write_text("signed")
            scans, records, inventories, manifests = [], [], [], []
            for offset, arch in enumerate(("amd64", "arm64"), 1):
                platform = "linux/" + arch
                digest = "sha256:" + str(offset) * 64
                subject = {"platform": platform, "oci_digest": digest}
                records.append({"subject": {"platform": platform, "manifest_digest": digest},
                                "source": {"repository": "https://github.com/SecPal/frontend", "commit": SOURCE},
                                "runner_architecture": arch, "workflow_run_id": "123", "workflow_run_attempt": "2"})
                inventories.append({"platform": platform, "spdx_sha256": DIGEST})
                manifests.append({"digest": digest, "platform": {"architecture": arch, "os": "linux"},
                                  "mediaType": "application/vnd.oci.image.manifest.v1+json"})
                scan = root / "scan" / arch
                scan.mkdir(parents=True)
                evaluation = {"subject": subject, "syft": {"spdx_digest": DIGEST}}
                scans.append({"subject": subject, "evaluation_sha256": put(scan / "evaluation.json", evaluation),
                              "policy_sha256": put(scan / "policy-result.json",
                                  {**evaluation, "gate_state": "REVIEW_REQUIRED", "evidence_health": {"state": "HEALTHY"}})})
            index = put(publisher / "index.json", {"schemaVersion": 2, "manifests": manifests})
            prepared = put(publisher / "prepared.json", {"index_digest": index, "records": records, "inventories": inventories})
            put(publisher / "pre-registry.json", {"candidate_sha256": prepared, "results": scans})
            put(publisher / "source-security.json",
                {"schema_version": "secpal-trivy-repository-scan-v5",
                 "subject": {"repository": "SecPal/frontend", "commit": SOURCE},
                 "operation": {"name": "TRIVY_REPOSITORY_SCAN", "status": "SUCCEEDED"}, "gate_state": "CLEAN",
                 "database": {"status": "FRESH", "updated_at": "2026-01-01T00:00:00Z", "next_update": "2040-01-01T00:00:00Z"}})
            signer = [{"verificationResult": {"signature": {"certificate": {
                "runInvocationURI": "https://github.com/SecPal/frontend/actions/runs/123/attempts/2"}}}}]
            with patch("fcos_lab_rollout_adapter.verify_attestation", return_value=signer):
                children, evidence = verify_frontend_candidate(root, SOURCE, 123, 2, Path("gh"), {})
                self.assertEqual(len(children), 2)
                self.assertEqual(evidence["frontend", "linux/amd64"]["subject"]["oci_digest"], children["frontend", "linux/amd64"])
                with self.assertRaisesRegex(ValueError, "invocation"):
                    verify_frontend_candidate(root, SOURCE, 124, 2, Path("gh"), {})
                put(root / "scan" / "arm64" / "evaluation.json", {})
                with self.assertRaisesRegex(ValueError, "evaluation"):
                    verify_frontend_candidate(root, SOURCE, 123, 2, Path("gh"), {})

    def test_publisher_children_requires_acceptance_before_returning_proof(self):
        children = {f"linux/{arch}": "sha256:" + str(i) * 64
                    for i, arch in enumerate(("amd64", "arm64"), 1)}
        subject = json.dumps({"manifests": [
            {"platform": {"os": "linux", "architecture": platform.split("/")[1]},
             "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest}
            for platform, digest in children.items()
        ]}).encode()
        bundle = b"signed bundle"
        verified = [{"verificationResult": {"signature": {"certificate": {
            "runInvocationURI": "https://github.com/SecPal/frontend/actions/runs/123/attempts/2",
        }}}}]
        cli = Path("/fixture/gh")

        def run(command, **_):
            if command[0] == cli:
                self.assertEqual(command[1:3], ["attestation", "verify"])
                self.assertEqual(command[-2:], ["--format", "json"])
                self.assertEqual(command[3].read_bytes(), subject)
                self.assertEqual(command[5].read_bytes(), bundle)
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(verified).encode())
            self.assertEqual(command[-2:], [DIGEST, "secpal/frontend"])
            command[3].write_bytes(subject)
            command[4].write_bytes(bundle)

        for failure in (None, ValueError("publisher acceptance did not pass")):
            with (self.subTest(failure=failure),
                  patch("fcos_lab_rollout_adapter.verified_gh"),
                  patch("fcos_lab_rollout_adapter.subprocess.run", side_effect=run),
                  patch("fcos_lab_rollout_adapter.frontend_acceptance", side_effect=failure) as accept):
                if failure is None:
                    proof = publisher_children(Frontend(DIGEST, SOURCE), gh=cli, require_acceptance=True)
                    self.assertEqual(proof, (children, subject, bundle))
                else:
                    with self.assertRaisesRegex(ValueError, "publisher acceptance did not pass"):
                        publisher_children(Frontend(DIGEST, SOURCE), gh=cli, require_acceptance=True)
                accept.assert_called_once_with(verified, SOURCE)

    def test_verified_index_must_belong_to_the_exact_successful_publisher_attempt(self):
        invocation = "https://github.com/SecPal/frontend/actions/runs/123/attempts/2"
        verified = [{"verificationResult": {"signature": {"certificate": {
            "runInvocationURI": invocation,
        }}}}]
        run = {"id": 123, "run_attempt": 2, "head_sha": SOURCE, "head_branch": "main",
               "path": ".github/workflows/publish-container.yml", "event": "push",
               "head_repository": {"full_name": "SecPal/frontend"},
               "status": "completed", "conclusion": "success"}
        job = {"name": "Accept verified Frontend publication", "run_id": 123, "run_attempt": 2,
               "conclusion": "success", "steps": [
                   {"name": "Verify all subjects and publish only unique discovery tag", "conclusion": "success"},
               ]}

        def check(attempt, jobs):
            with patch("fcos_lab_rollout_adapter.frontend_actions_json",
                       side_effect=[attempt, {"total_count": len(jobs), "jobs": jobs}]) as api:
                frontend_acceptance(verified, SOURCE)
                self.assertEqual([call.args[0] for call in api.call_args_list],
                                 ["123/attempts/2", "123/attempts/2/jobs?per_page=100"])

        check(run, [job])
        for invalid_attempt, jobs in (
            (dict(run, conclusion="failure"), [job]),
            (dict(run, run_attempt=3), [job]),
            (dict(run, head_sha="8" * 40), [job]),
            (run, []),
            (run, [dict(job, run_attempt=1)]),
            (run, [dict(job, conclusion="skipped")]),
            (run, [dict(job, steps=[dict(job["steps"][0], conclusion="skipped")])]),
        ):
            with self.subTest(attempt=invalid_attempt, jobs=jobs), self.assertRaises(ValueError):
                check(invalid_attempt, jobs)

    def test_dispatch_authority_requires_exact_companion_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            scripts = root / "scripts"
            scripts.mkdir()
            validator = scripts / "secpal-evidence-architecture.py"
            module = scripts / "companion.py"
            validator.write_bytes(b"validator")
            module.write_bytes(b"companion")
            pins = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (validator, module)}
            renderer = ("VALIDATOR_SOURCE = " + repr(pins)).encode()
            verify_dispatch_authority(validator, renderer)
            module.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                verify_dispatch_authority(validator, renderer)

    def test_backend_dispatch_declaration_fails_on_missing_diagnostic(self):
        root = Path(__file__).resolve().parents[1]
        helper = (root / "scripts/fcos-lab-rollout-guest.sh").read_text()
        original = (root / ".secpal/evidence-architecture.json").read_text()
        declaration = backend_declaration(json.loads(original), helper)
        ids = {entry["id"] for entry in declaration["external_operations"]}
        self.assertIn("fcos-lab-backend.controller-dispatch", ids)
        self.assertIn("fcos-lab-backend.start-background", ids)
        with self.assertRaises(ValueError):
            backend_declaration(json.loads(original), helper.replace("backend_step start-background ", ""))

    def test_backend_pin_is_complete_and_backend_proof_uses_the_existing_prepare_operation(self):
        fields = {"API_SOURCE_COMMIT": SOURCE, "API_DIGEST": DIGEST,
                  "PHP_FPM_DIGEST": "sha256:" + "6" * 64, "API_PAIR_DIGEST": "sha256:" + "7" * 64,
                  "API_VEX_EXPIRES_AT": "2027-01-01T00:00:00Z"}
        original = "".join(f'{key} = "{value}"\n' for key, value in fields.items())
        override = "".join(f'LAB_{key} = "{value}"\n' for key, value in fields.items())
        self.assertEqual(Backend.from_source(original), Backend.from_source(original + override))
        self.assertIsNone(Backend.from_source(original).compatibility)
        record = f'LAB_API_COMPATIBILITY_SHA256 = "{"a" * 64}"\n'
        self.assertEqual(Backend.from_source(original + override + record).compatibility, "a" * 64)
        self.assertEqual(Backend.from_source(original + override + record), Backend.from_source(original))
        for broken in (original + 'LAB_API_DIGEST = "latest"\n', original + override + override,
                       original + override + 'LAB_API_COMPATIBILITY_SHA256 = "bad"\n',
                       original + override + record * 2):
            with self.assertRaises(ValueError):
                Backend.from_source(broken)
        head, *proof = backend_request("cx23", "linux/amd64", NEW, OLD, fields["API_PAIR_DIGEST"],
                                       (b"evidence",) * 7).splitlines()
        self.assertEqual(head + b"\n", request_line("prepare", "cx23", "linux/amd64", NEW, OLD,
                                                    fields["API_PAIR_DIGEST"]))
        self.assertEqual([base64.b64decode(row) for row in proof], [b"evidence"] * 7)

    def test_backend_publisher_binding_excludes_deployment_compatibility_digest(self):
        backend = Backend(SOURCE, DIGEST, "sha256:" + "6" * 64, "sha256:" + "7" * 64,
                          "2027-01-01T00:00:00Z", "a" * 64)
        platforms = [{"platform": f"linux/{arch}", "manifest_digest": "sha256:" + str(index) * 64}
                     for index, arch in enumerate(("amd64", "arm64"), 1)]
        index = {"manifests": [
            {"platform": {"os": "linux", "architecture": entry["platform"].split("/")[1]},
             "mediaType": "application/vnd.oci.image.manifest.v1+json",
             "digest": entry["manifest_digest"]} for entry in platforms]}

        def fetch(command, **_):
            command[3].write_text(json.dumps(index))
            command[4].write_bytes(b"bundle")
            if "--reviewed-lab-runtime-pair" in command:
                self.assertEqual(json.loads(command[-1]), {
                    "source": backend.source, "nginx": backend.nginx,
                    "fpm": backend.fpm, "expires": backend.expires})
                command[-3].write_text(json.dumps({
                    "images": {role: {"platforms": platforms} for role in ("nginx", "php-fpm")}}))

        with (patch("fcos_lab_rollout_adapter.verified_gh"),
              patch("fcos_lab_rollout_adapter.verify_attestation"),
              patch("fcos_lab_rollout_adapter.subprocess.run", side_effect=fetch)):
            self.assertEqual(len(backend_proof(backend)), 7)

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

    def test_guest_metadata_readback_rejects_a_stale_backend_source(self):
        command = ('source "$1"; fpm_pool=$2; current_source=$3; '
                   'release_asset() { [[ -f "$1" ]]; }; '
                   'backend_image_source() { printf "%s\\n" "$current_source"; }; '
                   'backend_release_matches test-image')
        source = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            pool = Path(directory) / "pool.conf"
            pool.write_text("[secpal]\n"
                            f"env[BOOTSTRAP_API_RELEASE_VERSION]=git.{source}\n"
                            f"env[BOOTSTRAP_API_RELEASE_SOURCE_URL]=https://codeload.github.com/SecPal/api/tar.gz/{source}\n")
            arguments = ["bash", "-c", command, "test", self.guest, pool]
            subprocess.run(arguments + [source], check=True)
            self.assertNotEqual(subprocess.run(arguments + ["b" * 40]).returncode, 0)

    def test_guest_metadata_label_failure_keeps_the_native_image_diagnostic(self):
        command = ('source "$1"; status=$2; '
                   'runtime() { '
                   'if [[ "$status" == failed ]]; then printf "raw inspection error\\n" >&2; return 1; fi; '
                   'printf "main\\n"; }; '
                   'backend_step native-image backend_image_source image')
        for mode in ("failed", "bad-label"):
            with self.subTest(mode=mode):
                checked = subprocess.run(["bash", "-c", command, "test", self.guest, mode],
                                         capture_output=True, text=True, check=False)
                self.assertNotEqual(checked.returncode, 0)
                self.assertEqual(checked.stdout, "")
                self.assertEqual(checked.stderr, "FCOS lab backend operation failed: fcos-lab-backend.native-image\n")

    def test_guest_release_metadata_binds_exact_sources(self):
        source = "a" * 40
        command = ('source "$1"; render_source_offer "$2"; '
                   'render_frontend_dropin "$3"')
        result = subprocess.run(["bash", "-c", command, "test", self.guest, source,
                                 "ghcr.io/secpal/frontend@" + DIGEST], capture_output=True,
                                text=True, check=True)
        manifest, dropin = result.stdout.split("\n", 1)
        self.assertEqual(json.loads(manifest), {"version": 1, "repositories": {
            "frontend": {"sourceUrl": "https://codeload.github.com/SecPal/frontend/tar.gz/" + source},
            "contracts": {"sourceUrl": "https://codeload.github.com/SecPal/contracts/tar.gz/"
                                       "f8771b74d887b84b84dcc94e2405df7b47222466"},
        }})
        self.assertIn("target=/usr/share/nginx/html/source-offer.json,ro=true", dropin)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "fpm.conf"
            original = "[secpal]\nenv[SESSION_DOMAIN]=$SESSION_DOMAIN\n"
            config.write_text(original + "env[BOOTSTRAP_API_RELEASE_VERSION]=previous\n")
            command = 'source "$1"; render_api_release "$2" "$3"'
            command_args = ["bash", "-c", command, "test", self.guest, config]
            output = subprocess.check_output(command_args + [source], text=True)
            self.assertEqual(output, original + f"env[BOOTSTRAP_API_RELEASE_VERSION]=git.{source}\n"
                             f"env[BOOTSTRAP_API_RELEASE_SOURCE_URL]=https://codeload.github.com/SecPal/api/tar.gz/{source}\n")
            self.assertNotEqual(subprocess.run(command_args + ["main"], capture_output=True).returncode, 0)

    def test_backend_transition_requires_exact_forward_evidence_and_separate_rollback_evidence(self):
        previous = "sha256:" + "1" * 64
        candidate = "sha256:" + "2" * 64
        evidence = {"linux/amd64": "sha256:" + "3" * 64, "linux/arm64": "sha256:" + "4" * 64}
        backward = {"linux/amd64": "sha256:" + "8" * 64, "linux/arm64": "sha256:" + "9" * 64}
        record = {"schema_version": 1, "previous_pair": previous, "candidate_pair": candidate,
                  "schema": "5" * 64, "ledger": "6" * 64, "forward": evidence, "rollback": None}
        command = 'source "$1"; validate_backend_compatibility "$2" "$3" "$4" "$5" "$6"'
        migration = {"schema": "a" * 64, "ledger": "b" * 64}
        changing = dict(record, schema_version=2, migration=migration, rollback=backward)
        cases = [(record, "false"), (dict(record, rollback=backward), "true"), ([record], None),
                 (dict(record, candidate_pair=previous), None), (dict(record, schema="7" * 64), None),
                 (dict(record, ledger="7" * 64), None), (dict(record, forward={}), None),
                 (dict(record, rollback=True), None), (dict(record, rollback=evidence), None),
                 (dict(record, rollback=backward, unexpected=True), None),
                 (changing, json.dumps({"rollback": True, "migration": migration}, separators=(",", ":"))),
                 (dict(changing, rollback=None), None),
                 (dict(changing, migration={"schema": migration["schema"], "ledger": record["ledger"]}), None),
                 (dict(changing, migration={**migration, "unexpected": "0" * 64}), None),
                 (dict(changing, schema_version=1), None)]
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "compatibility.json"
            for data, admitted in cases:
                with self.subTest(admitted=admitted, record=data):
                    fixture.write_text(json.dumps(data))
                    result = subprocess.run(["bash", "-c", command, "test", self.guest, fixture,
                                             previous, candidate, record["schema"], record["ledger"]],
                                            capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode == 0, admitted is not None, result.stderr)
                    if admitted is not None:
                        self.assertEqual(result.stdout.strip(), admitted)
            fixture.write_text(json.dumps(changing))
            resumed = subprocess.check_output(["bash", "-c", command, "test", self.guest, fixture,
                                               previous, candidate, migration["schema"], migration["ledger"]])
            self.assertEqual(json.loads(resumed), {"rollback": True, "migration": migration})

    def test_automatic_migration_allows_only_new_registered_definitions(self):
        before = [{"existing": "a" * 64}, []]
        after = [{"existing": "a" * 64, "new": "b" * 64}, []]
        command = 'source "$1"; additive_migrations "$2" "$3"'
        for candidate, allowed in (
            (after, True),
            (before, False),
            ([{"new": "b" * 64}, []], False),
            ([{"existing": "c" * 64, "new": "b" * 64}, []], False),
            ([after[0], {"pgsql-schema.sql": "d" * 64}], False),
        ):
            with self.subTest(allowed=allowed, candidate=candidate):
                check = subprocess.run(["bash", "-c", command, "test", self.guest,
                                        json.dumps(before), json.dumps(candidate)], capture_output=True, check=False)
                self.assertEqual(check.returncode == 0, allowed, check.stderr)

    def test_backend_guest_requires_the_same_attested_pair_and_native_children(self):
        encode = lambda value: json.dumps(value).encode()
        sha = lambda value: "sha256:" + hashlib.sha256(value).hexdigest()
        indexes = {}
        subjects = {}
        for role, first in (("nginx", 1), ("php-fpm", 3)):
            platforms = [{"platform": f"linux/{arch}", "manifest_digest": "sha256:" + str(first+i)*64}
                         for i, arch in enumerate(("amd64", "arm64"))]
            indexes[role] = encode({
                "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [{"digest": item["manifest_digest"],
                               "mediaType": "application/vnd.oci.image.manifest.v1+json",
                               "platform": {"os": "linux", "architecture": item["platform"].split("/")[1]}}
                              for item in platforms],
            })
            subjects[role] = {"reference": "ghcr.io/secpal/api@" + sha(indexes[role]), "platforms": platforms}
        command = ('source "$1"; scratch=$2; platform=linux/amd64; '
                   'verify_signature() { [[ "$4" == api && $(cat "$2") == verified ]]; }; '
                   'verify_backend "$3" "$4" "$5" "$6"')
        for scenario in ("accepted", "wrong-child", "wrong-component", "unsigned"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                images = json.loads(json.dumps(subjects))
                if scenario == "wrong-child":
                    images["nginx"]["platforms"][1]["manifest_digest"] = DIGEST
                if scenario == "wrong-component":
                    images["nginx"]["reference"] = images["php-fpm"]["reference"]
                document = encode({"schema_version": "1.0.0", "images": images,
                                   "source": {"repository": "https://github.com/SecPal/api", "commit": SOURCE}})
                pair = encode({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                               "artifactType": "application/vnd.secpal-build-evidence.v1+json",
                               "layers": [{"mediaType": "application/json", "digest": sha(document),
                                           "annotations": {"org.opencontainers.image.title": "runtime-pair.json"}}]})
                bundle = b"wrong" if scenario == "unsigned" else b"verified"
                parts = (pair, bundle, document, indexes["php-fpm"], b"verified", indexes["nginx"], b"verified")
                (Path(temp) / "proof").write_bytes(b"".join(base64.b64encode(part)+b"\n" for part in parts))
                result = subprocess.run(["bash", "-c", command, "test", self.guest, temp, SOURCE, sha(pair),
                                         sha(indexes["nginx"]), sha(indexes["php-fpm"])],
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, scenario == "accepted", result.stderr)

    def test_archived_frontend_binds_index_to_signed_qualification(self):
        def encoded(value):
            return json.dumps(value, sort_keys=True).encode()

        def sha(data):
            return "sha256:" + hashlib.sha256(data).hexdigest()

        index = encoded({"manifests": [{"digest": DIGEST}]})
        prepared = encoded({"index_digest": sha(index)})
        binding = encoded({"candidate_sha256": sha(prepared)})
        command = ('source "$1"; scratch=$2; '
                   'verify_signature() { [[ "$4" == frontend && $(cat "$2") == verified ]]; }; '
                   'verify_archived_frontend "$3" "$4"')
        for example, digest, images in (
            ("admitted", sha(index), index), ("wrong-index-pin", DIGEST, index),
            ("changed-index", sha(index), encoded({"manifests": []})),
        ):
            with self.subTest(example=example), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "proof").write_bytes(b"".join(
                    base64.b64encode(value) + b"\n"
                    for value in (binding, b"verified", prepared, images)))
                result = subprocess.run(["bash", "-c", command, "test", self.guest,
                                         directory, digest, SOURCE], capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, example == "admitted", result.stderr)

    def test_archived_backend_matches_signed_receipt_and_deadline(self):
        source_end = "2040-01-01T00:00:00Z"
        expiry = "2039-12-31T00:00:00Z"
        indexes = {"nginx": "sha256:" + "1" * 64, "php-fpm": "sha256:" + "2" * 64}
        images = {role: {"candidate_index_digest": index, "platforms": [
            {"subject": {"platform": platform, "manifest_digest": "sha256:" + str(i) * 64}}
            for i, platform in enumerate(("linux/amd64", "linux/arm64"), 3 + 2 * offset)
        ]} for offset, (role, index) in enumerate(indexes.items())}
        receipt = {"schema_version": "1.0.0", "published": False, "qualification": "SUCCEEDED",
                   "source": {"commit": SOURCE, "repository": "https://github.com/SecPal/api"},
                   "images": images}
        assessment = {"schema_version": "secpal-trivy-repository-scan-v5",
                      "subject": {"repository": "SecPal/api", "commit": SOURCE}, "gate_state": "CLEAN",
                      "operation": {"name": "TRIVY_REPOSITORY_SCAN", "status": "SUCCEEDED"},
                      "database": {"status": "FRESH", "updated_at": "2026-01-01T00:00:00Z", "next_update": source_end}}
        command = ('source "$1"; scratch=$2; platform=linux/arm64; '
                   'verify_signature() { [[ "$4" == api && $(cat "$2") == verified ]]; }; '
                   'verify_archived_backend "$3" "$4" "$5" "$6" "$7"')
        for case in ("admitted", "wrong-pair", "wrong-index", "unsigned", "published", "late", "unqualified-source"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                raw = json.dumps(dict(receipt, published=case == "published")).encode()
                pair = "sha256:" + hashlib.sha256(raw).hexdigest()
                bundle = b"refused" if case == "unsigned" else b"verified"
                scan = json.dumps(dict(assessment, gate_state="UNKNOWN" if case == "unqualified-source" else "CLEAN")).encode()
                (Path(tmp) / "proof").write_bytes(b"".join(base64.b64encode(b) + b"\n" for b in (raw, bundle, scan)))
                result = subprocess.run(["bash", "-c", command, "test", self.guest, tmp, SOURCE,
                                         DIGEST if case == "wrong-pair" else pair,
                                         DIGEST if case == "wrong-index" else indexes["nginx"], indexes["php-fpm"],
                                         "2041-01-01T00:00:00Z" if case == "late" else expiry],
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, case == "admitted", result.stderr)
                if case == "admitted":
                    self.assertEqual((Path(tmp) / "nginx.child").read_text().strip(), "sha256:" + "4" * 64)
                    self.assertEqual((Path(tmp) / "fpm.child").read_text().strip(), "sha256:" + "6" * 64)

    def test_archived_prepare_transports_only_bounded_complete_native_images(self):
        import io
        from fcos_lab_rollout_adapter import Backend, write_backend_archive_request

        command = ('source "$1"; scratch=$2; host=cx23; platform=linux/amd64; '
                   'read_request && decode_backend_evidence pair bundle source && receive_archived_backend')
        names = ("unpublished-runtime-pair.json", "bundle.jsonl", "source-security.json")
        data = (b"image\x00one\n", b"image\x00two\r\n")
        candidate = Backend(SOURCE, DIGEST, DIGEST, DIGEST, "2040-01-01T00:00:00Z", None)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                (root / name).write_text(name)
            paths = tuple(root / role for role in ("nginx.tar", "fpm.tar"))
            for path, content in zip(paths, data, strict=True):
                path.write_bytes(content)
            stream = io.BytesIO()
            write_backend_archive_request(
                stream, "cx23", "linux/amd64", NEW, OLD, candidate, root, paths,
            )
            wire = stream.getvalue()
            for case, message in (
                ("accepted", wire), ("truncated", wire[:-1]), ("trailing", wire + b"X"),
                ("wrong-operation", wire.replace(b"prepare cx23", b"activate cx23", 1)),
                ("oversize", wire.replace(f"{len(data[0])} {len(data[1])}\n".encode(),
                                          b"150000001 12\n", 1)),
            ):
                with self.subTest(case=case):
                    scratch = root / case
                    scratch.mkdir()
                    checked = subprocess.run(["bash", "-c", command, "test", self.guest, scratch],
                                             input=message, capture_output=True, check=False)
                    self.assertEqual(checked.returncode == 0, case == "accepted", checked.stderr)
                    if case == "accepted":
                        for image, content in zip(paths, data, strict=True):
                            self.assertEqual((scratch / image.name).read_bytes(), content)

    def test_backend_database_change_fails_admission(self):
        command = ('source "$1"; current=$2; '
                   'backend_database() { printf "%s\n" "$current"; }; same_backend_database "$3"')
        for observed, expected in (("a" * 64, True), ("b" * 64, False), ("", False)):
            result = subprocess.run(["bash", "-c", command, "test", self.guest, observed, "a" * 64],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode == 0, expected)

    def test_backend_prepares_changed_application_with_unchanged_migrations(self):
        command = '''
            source "$1"
            scratch=$2 previous=old revision=new wanted=fingerprint platform=linux/amd64
            scenario=$3
            pin() { printf 'sha256:%064d\n' "$1"; }
            child=$(pin 1)
            frontend_field() { printf 'unchanged\n'; }
            backend_helper_hash() { printf 'helper\n'; }
            backend_expiry() { return 0; }
            singleton_roles() { return 0; }
            backend_database() { printf '%064d\n' 1; }
            backend_compatibility() { [[ $scenario != failed-rehearsal ]] && printf 'false\n'; }
            verify_backend() {
                printf '%s\n' "$(pin 6)" > "$scratch/fpm.child"
                printf '%s\n' "$(pin 7)" > "$scratch/nginx.child"
            }
            runtime() {
                local ref="${!#}"
                case "$*" in
                    *"podman pull "*) return 0;;
                    *"podman image inspect "*) printf '%064d %s amd64 10001\n' 8 "${ref##*@}";;
                    *) return 1;;
                esac
            }
            backend_role_ref() { printf 'old-app\n'; }
            fpm_migrations() {
                if [[ $scenario == changed-migration && $1 != old-app ]]; then
                    printf '%064d\n' 2
                else
                    printf '%064d\n' 1
                fi
            }
            run_staged() { return 0; }
            validate_backend_quadlets() { return 0; }
            save() { printf '%s\n' "$2"; }
            prepare_backend '{}' "$(printf '%s\n' candidate "$(pin 1)" "$(pin 2)" "$(pin 3)" date)" \
                                 "$(printf '%s\n' predecessor "$(pin 4)" "$(pin 2)" "$(pin 5)" date)"
        '''
        for scenario in ("code-change", "changed-migration", "failed-rehearsal"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                result = subprocess.run(["bash", "-c", command, "test", self.guest, temp, scenario],
                                        capture_output=True, text=True, check=False)
                if scenario == "code-change":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(json.loads(result.stdout)["rollback"])
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")

    def test_backend_rollback_requires_an_explicit_positive_decision(self):
        command = ('source "$1"; test_expiry=$3; backend_field() { printf "%s\n" "$test_expiry"; }; '
                   'backend_rollback_admitted "$2" predecessor')
        for record, expiry, admitted in (({}, "2100", False), ({"rollback": "true"}, "2100", False),
                                         ({"rollback": False}, "2100", False), ({"rollback": True}, "2100", True),
                                         ({"rollback": True}, "2000", False)):
            result = subprocess.run(["bash", "-c", command, "test", self.guest, json.dumps(record),
                                     f"{expiry}-01-01T00:00:00Z"],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode == 0, admitted)

    def test_backend_guest_rejects_helper_bytes_absent_from_reviewed_source(self):
        command = ('source "$1"; peer=$2; revision="$3"; '
                   'stat() { printf "0 0 755\n"; }; '
                   'git_object() { printf "%s" "$expected_content"; }; '
                   'expected_content=$4; backend_helper_hash')
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "guest").write_text("reviewed")
            for expected, accepted in (("reviewed", True), ("unrelated", False)):
                result = subprocess.run(["bash", "-c", command, "test", self.guest, temp, SOURCE, expected],
                                        capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, accepted)

    def test_backend_switch_stops_http_and_background_roles_before_restarting_the_pair(self):
        command = (
            'source "$1"; units=$2; migration=$4; '
            'image_digest=$3; '
            'backend_role_ref() { printf "ghcr.io/secpal/api@%s\n" "$image_digest"; }; '
            'untouched_instances() { printf "unrelated identity\n"; }; '
            'matches() { return 0; }; singleton_roles() { return 0; }; check_installed() { return 0; }; '
            'write_release_asset() { [[ "$3" == "$fpm_pool" && "$4" =~ ^$sha$ ]] && printf "metadata\\n"; }; '
            'runtime() { case "$*" in '
            '"podman image exists "*) return 0;; '
            '"podman image inspect "*) printf "%040d\\n" 1;; '
            '"systemctl --user show "*"-migrate.service") printf "%s\n" "$migration";; '
            '"systemctl --user show "*) printf "inactive\n";; '
            '"systemctl --user "*) printf "%s\n" "$*";; '
            '*) return 1;; esac; }; switch_backend "$5"'
        )
        slot = "secpal-int-haproxy01"
        with tempfile.TemporaryDirectory() as temp:
            for role in ("api", "php-fpm", "worker-general", "worker-hash-chain", "scheduler"):
                directory = Path(temp) / f"{slot}-{role}.container.d"
                directory.mkdir()
                (directory / "90-rollout.conf").write_text("candidate override")
            active = subprocess.run(["bash", "-c", command, "test", self.guest, temp, DIGEST, "active", "{}"],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(active.returncode, 0)
            self.assertEqual(active.stdout, "")
            expired = subprocess.run(["bash", "-c", command, "test", self.guest, temp, DIGEST, "inactive",
                                      '{"backend":{"expires":"2000-01-01T00:00:00Z"}}'],
                                     capture_output=True, text=True, check=False)
            self.assertNotEqual(expired.returncode, 0)
            self.assertEqual(expired.stdout, "")
            result = subprocess.run(["bash", "-c", command, "test", self.guest, temp, DIGEST, "inactive", "{}"],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(list(Path(temp).iterdir()), [])
        background = " ".join(f"{slot}-{role}.service"
                              for role in ("worker-general", "worker-hash-chain", "scheduler"))
        self.assertEqual(result.stdout.splitlines(), [
            f"systemctl --user --job-mode=ignore-requirements stop {slot}-api.service",
            f"systemctl --user --job-mode=ignore-requirements stop {slot}-php-fpm.service {background}",
            "metadata",
            "systemctl --user daemon-reload",
            f"systemctl --user --job-mode=ignore-dependencies start {slot}-php-fpm.service",
            f"systemctl --user --job-mode=ignore-dependencies start {slot}-api.service",
            f"systemctl --user --job-mode=ignore-dependencies start {background}",
        ])

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
                'lab_pins_only "$5" && fingerprint "$5"'
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
