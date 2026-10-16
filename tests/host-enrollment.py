#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Real OpenSSL and PostgreSQL 18 behavior; conformance/provider adapters are synthetic."""
import concurrent.futures
import dataclasses
import importlib.util
import json
import itertools
import socket
import getpass
import shutil
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

import psycopg

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("host_enrollment", ROOT / "scripts/host_enrollment.py")
enrollment = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = enrollment
spec.loader.exec_module(enrollment)
provider = enrollment.provider


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.dsn = os.environ.get("SECPAL_ENROLLMENT_TEST_DSN")
        if not self.dsn:
            self.fail("SECPAL_ENROLLMENT_TEST_DSN must name an isolated disposable PG18 database")
        self.connect = lambda: psycopg.connect(self.dsn, connect_timeout=5)
        with self.connect() as db:
            name = db.info.dbname
            if not name.startswith("secpal_enrollment_test_"):
                self.fail("refusing non-test database")
            present = db.execute(
                "SELECT 1 FROM pg_namespace WHERE nspname='secpal_enrollment'").fetchone()
            if present:
                self.fail("refusing pre-existing enrollment state")
        self.addCleanup(self.drop_schema)
        self.temporary = tempfile.TemporaryDirectory(prefix="secpal-enrollment-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ca = self.root / "ca.pem"
        self.key = self.root / "ca-key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-sha256", "-days", "1",
                        "-subj", "/CN=Synthetic Enrollment Test Authority",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                        "-keyout", str(self.key), "-out", str(self.ca)],
                       check=True, capture_output=True)
        self.key.chmod(0o600)
        self.ca.chmod(0o600)
        self.deployment = str(uuid.uuid4())
        self.target = provider.ResourceTarget("synthetic-provider", "project/region",
                                              "node-1", "resource-1", "incarnation-1")
        self.machine = {"machine_id": "a" * 32,
                        "ssh_host_key": "SHA256:" + "A" * 43}
        self.machine_patch = patch.object(enrollment, "observe_machine", return_value=self.machine)
        self.machine_observer = self.machine_patch.start()
        self.addCleanup(self.machine_patch.stop)
        self.host = enrollment.LocalHost.create(self.root / "host", self.deployment,
                                               self.target, "single-host", ready=lambda: None)
        enrollment.initialize_authority_store(self.connect, self.ca,
                                             directory=self.root / "authority")
        with self.connect() as db:
            db.execute("GRANT USAGE ON SCHEMA secpal_enrollment TO secpal_enrollment_runtime")
            db.execute("GRANT SELECT ON ALL TABLES IN SCHEMA secpal_enrollment"
                       " TO secpal_enrollment_runtime")
            db.execute("GRANT INSERT ON secpal_enrollment.grants,"
                       " secpal_enrollment.enrollments TO secpal_enrollment_runtime")
            db.execute("GRANT UPDATE(consumed) ON secpal_enrollment.grants"
                       " TO secpal_enrollment_runtime")
        self.authority = enrollment.EnrollmentAuthority(
            self.root / "authority", self.ca, self.key, self.deployment, self.target,
            "single-host", observe=self.observe, ready=lambda observed: None, connect=self.runtime_connect)
        self.request = self.host.request()

    def runtime_connect(self):
        db = self.connect()
        db.execute("SET ROLE secpal_enrollment_runtime")
        return db

    def drop_schema(self):
        with self.connect() as db:
            db.execute("DROP SCHEMA IF EXISTS secpal_enrollment CASCADE")

    def observe(self, request):
        target = self.target
        parameters = "b" * 64
        authority = provider.ExecutionAuthority("synthetic-inspection", "synthetic-adapter",
                                                "c" * 40, target,
                                                frozenset({provider.Operation.INSPECT}),
                                                parameters, "synthetic-test-only")
        call = provider.CapabilityRequest(str(uuid.uuid4()), authority.adapter_id,
                                          authority.source_revision, provider.Operation.INSPECT,
                                          target, parameters)
        result = provider.CapabilityResult(call.request_id, call.adapter_id,
                                            call.source_revision, call.operation,
                                            target, parameters, provider.Outcome.OBSERVED,
                                            provider.CleanupOutcome.NOT_APPLICABLE,
                                            target.provider_resource_id,
                                            target.expected_version)
        return enrollment.TrustedHost(call, authority, result, dict(self.machine),
                                      enrollment.digest(request), enrollment.now())

    def complete(self, purpose="enroll"):
        grant = self.authority.grant(self.request, purpose=purpose)
        proof = self.host.prove(grant, self.ca)
        credential = self.authority.consume(self.request, grant, proof)
        return grant, credential

    def test_real_signed_enrollment_and_private_custody(self):
        grant, credential = self.complete()
        identity = self.host.accept(credential, self.ca)
        self.assertEqual(identity["state"], "ENROLLED")
        self.assertEqual(identity["deployment_id"], self.deployment)
        self.assertEqual(identity["resource"]["provider_resource_id"], "resource-1")
        self.assertEqual(identity["generation"], 1)
        self.assertEqual((self.root / "host/host-key.pem").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "host").stat().st_mode & 0o777, 0o700)
        public = json.dumps([self.request, grant, credential, identity])
        self.assertNotIn("PRIVATE KEY", public)
        challenge = os.urandom(32)
        signature = self.host.prove_identity(identity, challenge)
        verified = self.authority.authenticate(identity, challenge, signature)
        self.assertEqual(verified, identity)
        text = enrollment.openssl("inspect-certificate", ["x509", "-text", "-noout"],
                                  input_bytes=credential["certificate"].encode()).decode()
        self.assertIn("TLS Web Client Authentication", text)
        self.assertIn("CA:FALSE", text)
        self.assertNotIn("TLS Web Server Authentication", text)

    def test_no_conformance_no_key_or_grant(self):
        def reject(*args):
            raise enrollment.EnrollmentError("conformance-rejected")
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.LocalHost.create(self.root / "not-ready", self.deployment,
                                        self.target, "single-host", ready=reject)
        self.assertFalse((self.root / "not-ready").exists())
        with patch.object(self.authority, "ready", reject):
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.grant(self.request)
        with patch.object(self.authority, "ready", lambda observed: True):
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.grant(self.request)

    def test_unsigned_metadata_or_uncorrelated_management_is_not_authority(self):
        actual = self.observe(self.request)
        bad = [None, self.machine,
               dataclasses.replace(actual, request_digest="0" * 64),
               dataclasses.replace(actual, observed_at=int(time.time()) - 61),
               dataclasses.replace(actual, machine={**self.machine, "machine_id": "b" * 32}),
               dataclasses.replace(actual, result=dataclasses.replace(
                   actual.result, provider_resource_id="another-resource")),
               dataclasses.replace(actual, authority=dataclasses.replace(
                   actual.authority, operations=frozenset({provider.Operation.DELETE})))]
        for observation in bad:
            with self.subTest(observation=type(observation).__name__):
                with patch.object(self.authority, "observe", return_value=observation):
                    with self.assertRaises(enrollment.EnrollmentError):
                        self.authority.grant(self.request)

    def test_expired_replayed_and_tampered_grants_fail_closed(self):
        grant = self.authority.grant(self.request, ttl=30)
        proof = self.host.prove(grant, self.ca)
        with patch.object(enrollment, "now", return_value=int(time.time()) + 31):
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.consume(self.request, grant, proof)
        for field, value in [("deployment_id", str(uuid.uuid4())),
                             ("public_key_sha256", "0" * 64),
                             ("role", "green"), ("generation", 2),
                             ("expires_at", int(time.time()) + 1000)]:
            bad = json.loads(json.dumps(grant))
            bad["payload"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(enrollment.EnrollmentError):
                    self.host.prove(bad, self.ca)
        credential = self.authority.consume(self.request, grant, proof)
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.consume(self.request, grant, proof)
        self.host.accept(credential, self.ca)
        with self.assertRaises(enrollment.EnrollmentError):
            self.host.accept(credential, self.ca)
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.grant(self.host.request())

    def test_wrong_deployment_role_resource_and_copied_machine_fail(self):
        for field, value in [("deployment_id", str(uuid.uuid4())),
                             ("role", "green"),
                             ("resource", dataclasses.asdict(dataclasses.replace(
                                 self.target, provider_resource_id="another-resource")))]:
            request = {**self.request, field: value}
            with self.subTest(field=field):
                with self.assertRaises(enrollment.EnrollmentError):
                    self.authority.grant(request)
        grant, credential = self.complete()
        self.host.accept(credential, self.ca)
        with patch.object(enrollment, "observe_machine", return_value={
                **self.machine, "machine_id": "b" * 32}):
            with self.assertRaises(enrollment.EnrollmentError):
                self.host.request()
            with self.assertRaises(enrollment.EnrollmentError):
                self.host.prove(grant, self.ca)

    def test_certificate_without_key_wrong_key_and_missing_proof_rejected(self):
        grant = self.authority.grant(self.request)
        for proof in ["", "AA==", self.request["csr"]]:
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.consume(self.request, grant, proof)
        proof = self.host.prove(grant, self.ca)
        credential = self.authority.consume(self.request, grant, proof)
        other = enrollment.LocalHost.create(self.root / "other", self.deployment,
                                             self.target, "single-host", ready=lambda: None)
        with self.assertRaises(enrollment.EnrollmentError):
            other.accept(credential, self.ca)
        key = self.root / "host/host-key.pem"
        key.rename(key.with_suffix(".retained"))
        with self.assertRaises(enrollment.EnrollmentError):
            self.host.prove(grant, self.ca)

    def test_atomic_single_use_under_concurrent_consumption(self):
        grant = self.authority.grant(self.request)
        proof = self.host.prove(grant, self.ca)
        def consume(_):
            try:
                self.authority.consume(self.request, grant, proof)
                return "accepted"
            except enrollment.EnrollmentError:
                return "rejected"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(consume, range(2))), ["accepted", "rejected"])

    def test_interruption_rolls_back_before_consumption(self):
        grant = self.authority.grant(self.request)
        proof = self.host.prove(grant, self.ca)
        with patch.object(self.authority, "_certificate",
                          side_effect=enrollment.EnrollmentError("issue-certificate")):
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.consume(self.request, grant, proof)
        credential = self.authority.consume(self.request, grant, proof)
        self.assertEqual(self.host.accept(credential, self.ca)["generation"], 1)

    def test_lost_response_requires_fresh_recovery_authorization(self):
        self.complete()  # Authority committed; delivery was interrupted.
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.grant(self.host.request(), purpose="recover")
        self.authority.recovery = lambda request, previous: None
        self.request = self.host.request()
        grant, credential = self.complete(purpose="recover")
        identity = self.host.accept(credential, self.ca)
        self.assertEqual(identity["generation"], 2)
        self.assertEqual(grant["payload"]["purpose"], "recover")
        self.assertEqual(identity["public_key_sha256"], self.request["public_key_sha256"])

    def test_recovery_revokes_previous_generation(self):
        _, first = self.complete()
        old = self.host.accept(first, self.ca)
        self.authority.recovery = lambda request, previous: None
        self.request = self.host.request()
        _, second = self.complete(purpose="recover")
        current = self.host.accept(second, self.ca)
        challenge = os.urandom(32)
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.authenticate(old, challenge, self.host.prove_identity(old, challenge))
        self.assertEqual(self.authority.authenticate(
            current, challenge, self.host.prove_identity(current, challenge)), current)

    def test_private_state_paths_modes_and_no_overwrite(self):
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.LocalHost.create(self.root / "host", self.deployment,
                                        self.target, "single-host", ready=lambda: None)
        key = self.root / "host/host-key.pem"
        key.chmod(0o644)
        with self.assertRaises(enrollment.EnrollmentError):
            self.host.request()
        key.chmod(0o600)
        state = self.root / "linked"
        state.symlink_to(self.root / "host", target_is_directory=True)
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.LocalHost(state).request()

    def test_json_boundary_is_closed_and_diagnostics_do_not_echo_input(self):
        for request in [{**self.request, "secret": "do-not-echo"},
                        {**self.request, "created_at": True},
                        {**self.request, "csr": "untrusted\nPRIVATE KEY\ntext"}]:
            with self.assertRaises(enrollment.EnrollmentError) as caught:
                self.authority.grant(request)
            self.assertRegex(str(caught.exception), r"^[a-z][a-z0-9-]{0,79}$")
            self.assertNotIn("do-not-echo", str(caught.exception))

    def test_public_verifier_never_needs_enrollment_signing_authority(self):
        _, credential = self.complete()
        identity = self.host.accept(credential, self.ca)
        verifier = enrollment.EnrollmentVerifier(
            self.root / "consumer", self.ca, self.deployment, self.target,
            "single-host", observe=self.observe,
            current=lambda host_id: self.authority.current_identity())
        challenge = os.urandom(32)
        proof = self.host.prove_identity(identity, challenge)
        self.key.rename(self.key.with_suffix(".retained"))
        self.assertEqual(verifier.verify(credential, challenge, proof), identity)
        with self.assertRaises(enrollment.EnrollmentError):
            verifier.verify(credential, os.urandom(32), proof)
        with patch.object(verifier, "current", return_value=None):
            with self.assertRaises(enrollment.EnrollmentError):
                verifier.verify(credential, challenge, proof)

    def test_known_key_and_host_id_cannot_move_between_resources(self):
        self.complete()
        other_target = dataclasses.replace(self.target, requested_key="node-2",
                                            provider_resource_id="resource-2")
        other = enrollment.LocalHost.create(self.root / "fresh-host", self.deployment,
                                             other_target, "single-host", ready=lambda: None)
        fresh = other.request()
        self.target = other_target
        other_authority = enrollment.EnrollmentAuthority(
            self.root / "authority", self.ca, self.key, self.deployment,
            other_target, "single-host", observe=self.observe,
            ready=lambda observed: None, connect=self.runtime_connect)
        for request in [
                {**self.request, "resource": dataclasses.asdict(enrollment.host_resource(other_target))},
                {**fresh, "host_id": self.request["host_id"]}]:
            with self.assertRaises(enrollment.EnrollmentError):
                other_authority.grant(request)

    def test_expired_client_credential_and_untrusted_certificate_rejected(self):
        _, credential = self.complete()
        identity = self.host.accept(credential, self.ca)
        verifier = enrollment.EnrollmentVerifier(
            self.root / "consumer", self.ca, self.deployment, self.target,
            "single-host", observe=self.observe, current=lambda host_id: self.authority.current_identity())
        challenge = os.urandom(32)
        proof = self.host.prove_identity(identity, challenge)
        with patch.object(enrollment, "now", return_value=int(time.time()) + 301):
            with self.assertRaises(enrollment.EnrollmentError):
                verifier.verify(credential, challenge, proof)
        forged = subprocess.run([
            "openssl", "req", "-x509", "-key", str(self.root / "host/host-key.pem"),
            "-days", "1", "-subj", "/CN=" + enrollment.digest(credential["grant"]["payload"])],
            capture_output=True, check=True).stdout.decode()
        with self.assertRaises(enrollment.EnrollmentError):
            verifier.verify({**credential, "certificate": forged}, challenge, proof)

    def test_recovery_refusal_and_new_generation_race(self):
        self.complete()
        self.request = self.host.request()
        self.authority.recovery = lambda request, previous: True
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.grant(self.request, purpose="recover")
        self.authority.recovery = lambda request, previous: None
        one = self.authority.grant(self.request, purpose="recover")
        two = self.authority.grant(self.request, purpose="recover")
        self.authority.consume(self.request, one, self.host.prove(one, self.ca))
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.consume(self.request, two, self.host.prove(two, self.ca))

    def test_missing_authority_state_is_never_silently_recreated(self):
        self.drop_schema()
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.EnrollmentAuthority(
                self.root / "authority", self.ca, self.key, self.deployment,
                self.target, "single-host", observe=self.observe,
                ready=lambda observed: None, connect=self.runtime_connect)
        with self.connect() as db:
            self.assertIsNone(db.execute(
                "SELECT 1 FROM pg_namespace WHERE nspname='secpal_enrollment'").fetchone())

    def test_native_operation_failure_has_closed_non_secret_diagnostic(self):
        with patch.object(subprocess, "run", side_effect=OSError("secret-not-to-echo")):
            with self.assertRaises(enrollment.EnrollmentError) as caught:
                enrollment.openssl("verify-csr", ["req", "-verify"])
        self.assertEqual(str(caught.exception), "verify-csr")
        self.assertEqual(str(enrollment.EnrollmentError("unsafe user secret")), "contract-failed")

    def test_runtime_database_authority_cannot_replace_or_erase_state(self):
        self.complete()
        for query in [
                "DROP SCHEMA secpal_enrollment CASCADE",
                "DELETE FROM secpal_enrollment.enrollments",
                "UPDATE secpal_enrollment.authority SET authority_sha256='altered'",
                "UPDATE secpal_enrollment.grants SET envelope='altered'",
                "CREATE TABLE secpal_enrollment.backdoor(value text)"]:
            with self.subTest(query=query):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with self.runtime_connect() as db:
                        db.execute(query)
        self.assertEqual(self.authority.current_identity()["identity"]["generation"], 1)

    def test_missing_issued_grant_and_wrong_authority_store_rejected(self):
        grant = self.authority.grant(self.request)
        proof = self.host.prove(grant, self.ca)
        with self.connect() as db:
            db.execute("DELETE FROM secpal_enrollment.grants")
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.consume(self.request, grant, proof)
        with self.connect() as db:
            db.execute("UPDATE secpal_enrollment.authority SET authority_sha256=%s", ("0"*64,))
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.grant(self.request)

    def test_registered_identity_survives_bootstrap_certificate_expiry(self):
        _, credential = self.complete()
        identity = self.host.accept(credential, self.ca)
        verifier = enrollment.EnrollmentVerifier(
            self.root / "consumer", self.ca, self.deployment, self.target,
            "single-host", observe=self.observe,
            current=lambda host_id: self.authority.current_identity())
        with patch.object(enrollment, "now", return_value=int(time.time()) + 301):
            challenge = os.urandom(32)
            proof = self.host.prove_identity(identity, challenge)
            self.assertEqual(verifier.authenticate(identity, challenge, proof), identity)
            with self.assertRaises(enrollment.EnrollmentError):
                verifier.authenticate(identity, os.urandom(32), proof)
            with patch.object(verifier, "current", return_value={
                    **self.authority.current_identity(), "csr": "not-a-csr"}):
                with self.assertRaises(enrollment.EnrollmentError):
                    verifier.authenticate(identity, challenge, proof)

    def test_renamed_logical_target_does_not_bypass_resource_uniqueness(self):
        self.complete()
        self.target = dataclasses.replace(self.target, requested_key="renamed-logical-node")
        other = enrollment.LocalHost.create(
            self.root / "fresh", self.deployment, self.target, "single-host",
            ready=lambda: None)
        authority = enrollment.EnrollmentAuthority(
            self.root / "authority", self.ca, self.key, self.deployment,
            self.target, "single-host", observe=self.observe,
            ready=lambda observed: None, connect=self.runtime_connect)
        with self.assertRaises(enrollment.EnrollmentError):
            authority.grant(other.request())

    def test_expiration_during_certificate_issuance_does_not_commit(self):
        grant = self.authority.grant(self.request, ttl=30)
        proof = self.host.prove(grant, self.ca)
        issue = self.authority._certificate
        clock = patch.object(enrollment, "now", return_value=grant["payload"]["expires_at"])
        def expire(request, envelope):
            certificate = issue(request, envelope)
            clock.start()
            return certificate
        try:
            with patch.object(self.authority, "_certificate", side_effect=expire):
                with self.assertRaises(enrollment.EnrollmentError):
                    self.authority.consume(self.request, grant, proof)
        finally:
            clock.stop()
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.current_identity()
        credential = self.authority.consume(self.request, grant, proof)
        self.assertEqual(self.host.accept(credential, self.ca)["generation"], 1)

    def test_database_transport_rejects_untrusted_local_sockets(self):
        path = self.root / "socket"
        path.mkdir(mode=0o700)
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path / ".s.PGSQL.5432"))
            enrollment.admit_database_transport(str(path), None, False)
            for candidate in ["/tmp", str(path) + "/../socket"]:
                with self.assertRaises(enrollment.EnrollmentError):
                    enrollment.admit_database_transport(candidate, None, False)
            path.chmod(0o777)
            with self.assertRaises(enrollment.EnrollmentError):
                enrollment.admit_database_transport(str(path), None, False)
            path.chmod(0o700)
            alias = self.root / "socket-alias"
            alias.symlink_to(path, target_is_directory=True)
            with self.assertRaises(enrollment.EnrollmentError):
                enrollment.admit_database_transport(str(alias), None, False)

    def test_database_transport_rejects_plaintext_and_unverified_network(self):
        enrollment.admit_database_transport("db.example", "verify-full", True)
        for mode, encrypted in [("disable", False), ("prefer", True),
                                ("require", True), ("verify-ca", True),
                                ("verify-full", False)]:
            with self.subTest(mode=mode, encrypted=encrypted):
                with self.assertRaises(enrollment.EnrollmentError):
                    enrollment.admit_database_transport("db.example", mode, encrypted)

    def test_grant_lifetime_uses_one_clock_observation(self):
        clock = itertools.count(int(time.time()))
        with patch.object(enrollment, "now", side_effect=lambda: next(clock)):
            grant = self.authority.grant(self.request)
        payload = grant["payload"]
        self.assertEqual(payload["expires_at"] - payload["issued_at"], 300)

    def test_database_writer_without_ca_key_cannot_forge_current_identity(self):
        _, credential = self.complete()
        previous = self.host.accept(credential, self.ca)
        self.authority.recovery = lambda request, identity: None
        request = self.host.request()
        issued = self.authority.grant(request, purpose="recover")
        p = issued["payload"]
        forged = {**previous, "generation": 2, "grant_id": p["grant_id"]}
        self.key.rename(self.key.with_suffix(".retained"))
        with self.runtime_connect() as db:
            db.execute("INSERT INTO secpal_enrollment.enrollments VALUES(%s,%s,%s,%s,%s,%s,%s,%s)", (
                p["grant_id"], enrollment.resource_slot(self.target), 2, p["host_id"],
                p["public_key_sha256"], enrollment.canonical(request).decode(),
                credential["certificate"], enrollment.canonical(forged).decode()))
            db.execute("UPDATE secpal_enrollment.grants SET consumed=true WHERE grant_id=%s",
                       (p["grant_id"],))
        challenge = os.urandom(32)
        proof = self.host.prove_identity(forged, challenge)
        record = {"identity": forged, "csr": request["csr"], "machine": self.machine,
                  "credential": {"grant": issued, "certificate": credential["certificate"]}}
        verifier = enrollment.EnrollmentVerifier(
            self.root / "consumer", self.ca, self.deployment, self.target,
            "single-host", observe=self.observe, current=lambda host_id: record)
        for operation in [self.authority.current_identity,
                          lambda: verifier.authenticate(forged, challenge, proof)]:
            with self.subTest(operation=operation):
                with self.assertRaises(enrollment.EnrollmentError):
                    operation()
        self.key.with_suffix(".retained").rename(self.key)
        recovery_calls = []
        self.authority.recovery = lambda *args: recovery_calls.append(args)
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.grant(self.host.request(), purpose="recover")
        self.assertEqual(recovery_calls, [])

    def test_management_observation_binds_the_fresh_possession_exchange(self):
        grant = self.authority.grant(self.request)
        proof = self.host.prove(grant, self.ca)
        request_only = self.observe(self.request)
        with patch.object(self.authority, "observe", return_value=request_only):
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.consume(self.request, grant, proof)
        credential = self.authority.consume(self.request, grant, proof)
        identity = self.host.accept(credential, self.ca)
        challenge = os.urandom(32)
        proof = self.host.prove_identity(identity, challenge)
        identity_only = self.observe({**identity, "machine": self.machine})
        with patch.object(self.authority, "observe", return_value=identity_only):
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.authenticate(identity, challenge, proof)

    def test_restored_pre_consumption_database_fails_closed(self):
        grant = self.authority.grant(self.request)
        proof = self.host.prove(grant, self.ca)
        self.authority.consume(self.request, grant, proof)
        with self.connect() as db:
            db.execute("DELETE FROM secpal_enrollment.enrollments")
            db.execute("UPDATE secpal_enrollment.grants SET consumed=false")
        for operation in [
                lambda: self.authority.consume(self.request, grant, proof),
                self.authority.current_identity,
                lambda: enrollment.EnrollmentAuthority(
                    self.root / "authority", self.ca, self.key, self.deployment,
                    self.target, "single-host", observe=self.observe,
                    ready=lambda observed: None, connect=self.runtime_connect)]:
            with self.subTest(operation=operation):
                with self.assertRaises(enrollment.EnrollmentError):
                    operation()

    def test_restored_database_cannot_reactivate_a_revoked_generation(self):
        _, first = self.complete()
        previous = self.host.accept(first, self.ca)
        self.authority.recovery = lambda request, identity: None
        self.request = self.host.request()
        second_grant, second = self.complete(purpose="recover")
        self.host.accept(second, self.ca)
        with self.connect() as db:
            db.execute("DELETE FROM secpal_enrollment.enrollments WHERE generation=2")
            db.execute("DELETE FROM secpal_enrollment.grants WHERE grant_id=%s",
                       (second_grant["payload"]["grant_id"],))
        challenge = os.urandom(32)
        proof = self.host.prove_identity(previous, challenge)
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.authenticate(previous, challenge, proof)

    def test_ambiguous_commit_never_automatically_rebaselines_integrity(self):
        grant = self.authority.grant(self.request)
        proof = self.host.prove(grant, self.ca)
        pin = self.root / "authority/database-sha256.json"
        previous = pin.read_bytes()
        with patch.object(psycopg.Connection, "commit",
                          side_effect=psycopg.OperationalError("synthetic-commit-ambiguity")):
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority.consume(self.request, grant, proof)
        self.assertNotEqual(pin.read_bytes(), previous)
        for operation in [self.authority.current_identity,
                          lambda: self.authority.consume(self.request, grant, proof)]:
            with self.assertRaises(enrollment.EnrollmentError):
                operation()
        pin.unlink()
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.current_identity()
        self.assertFalse(pin.exists())

    def test_signed_grant_id_cannot_alias_a_different_ledger_key(self):
        grant, _ = self.complete()
        alias = str(uuid.uuid4())
        with self.runtime_connect() as db:
            db.execute("INSERT INTO secpal_enrollment.grants VALUES(%s,%s,true)",
                       (alias, enrollment.canonical(grant).decode()))
            from psycopg.rows import dict_row
            db.row_factory = dict_row
            row = db.execute("SELECT * FROM secpal_enrollment.enrollments").fetchone()
            with self.assertRaises(enrollment.EnrollmentError):
                self.authority._record(db, {**row, "grant_id": alias})

    def test_local_state_lock_wait_is_bounded(self):
        code = (
            "import sys;sys.path.insert(0,sys.argv[1]);import host_enrollment as e; "
            "host=e.LocalHost(sys.argv[2]);"
            "\ntry: host.request()"
            "\nexcept e.EnrollmentError as error: print(str(error))")
        with enrollment._lock(self.root / "host"):
            result = subprocess.run(
                [sys.executable, "-c", code, str(ROOT / "scripts"), str(self.root / "host")],
                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "state-lock-timeout")

    def test_waiting_cannot_extend_management_observation_freshness(self):
        generation = self.authority._generation
        clock = patch.object(enrollment, "now", return_value=int(time.time()) + 61)
        def delayed(*args):
            value = generation(*args)
            clock.start()
            return value
        try:
            with patch.object(self.authority, "_generation", side_effect=delayed):
                with self.assertRaises(enrollment.EnrollmentError):
                    self.authority.grant(self.request)
        finally:
            clock.stop()
        with self.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM secpal_enrollment.grants").fetchone()[0], 0)

    def test_issuance_cannot_outlive_management_observation_freshness(self):
        grant = self.authority.grant(self.request)
        proof = self.host.prove(grant, self.ca)
        issue = self.authority._certificate
        clock = patch.object(enrollment, "now", return_value=int(time.time()) + 61)
        def delayed(*args):
            certificate = issue(*args)
            clock.start()
            return certificate
        try:
            with patch.object(self.authority, "_certificate", side_effect=delayed):
                with self.assertRaises(enrollment.EnrollmentError):
                    self.authority.consume(self.request, grant, proof)
        finally:
            clock.stop()
        credential = self.authority.consume(self.request, grant, proof)
        self.assertEqual(self.host.accept(credential, self.ca)["generation"], 1)

    def test_blue_green_resources_have_distinct_host_identities(self):
        _, blue_credential = self.complete()
        blue = self.host.accept(blue_credential, self.ca)
        self.target = dataclasses.replace(self.target, requested_key="green",
                                            provider_resource_id="resource-green")
        green_host = enrollment.LocalHost.create(
            self.root / "green", self.deployment, self.target, "green",
            ready=lambda: None)
        green_authority = enrollment.EnrollmentAuthority(
            self.root / "authority", self.ca, self.key, self.deployment,
            self.target, "green", observe=self.observe,
            ready=lambda observed: None, connect=self.runtime_connect)
        request = green_host.request()
        grant = green_authority.grant(request)
        credential = green_authority.consume(request, grant, green_host.prove(grant, self.ca))
        green = green_host.accept(credential, self.ca)
        self.assertNotEqual(blue["host_id"], green["host_id"])
        self.assertNotEqual(blue["public_key_sha256"], green["public_key_sha256"])
        self.assertEqual(blue["deployment_id"], green["deployment_id"])
        self.assertEqual((blue["generation"], green["generation"]), (1, 1))

    def test_rebuilt_machine_requires_fresh_key_and_explicit_recovery(self):
        _, credential = self.complete()
        old = self.host.accept(credential, self.ca)
        self.machine = {**self.machine, "machine_id": "b"*32,
                        "ssh_host_key": "SHA256:" + "B"*43}
        self.machine_observer.return_value = self.machine
        fresh = enrollment.LocalHost.create(
            self.root / "rebuilt", self.deployment, self.target, "single-host",
            ready=lambda: None)
        request = fresh.request()
        self.assertNotEqual(request["public_key_sha256"], old["public_key_sha256"])
        with self.assertRaises(enrollment.EnrollmentError):
            self.authority.grant(request, purpose="recover")
        self.authority.recovery = lambda request, previous: None
        grant = self.authority.grant(request, purpose="recover")
        credential = self.authority.consume(request, grant, fresh.prove(grant, self.ca))
        identity = fresh.accept(credential, self.ca)
        self.assertEqual(identity["generation"], 2)
        self.assertNotEqual(identity["host_id"], old["host_id"])

    def test_provider_inspection_version_is_not_a_cloned_host_identity(self):
        _, credential = self.complete()
        identity = self.host.accept(credential, self.ca)
        self.target = dataclasses.replace(self.target, expected_version="next-readback-version")
        challenge = os.urandom(32)
        self.assertEqual(self.authority.authenticate(
            identity, challenge, self.host.prove_identity(identity, challenge)), identity)


@contextmanager
def postgres_fixture():
    """Disposable native PG18, private Unix socket, no network listener."""
    choices = [Path("/usr/pgsql-18/bin"), Path("/usr/lib64/pgsql"),
               Path("/usr/lib/postgresql/18/bin")]
    found = shutil.which("initdb")
    if found:
        choices.insert(0, Path(found).parent)
    binaries = next((p for p in choices if (p / "initdb").is_file()), None)
    if binaries is None or os.geteuid() == 0:
        raise RuntimeError("native PG18 binaries and an unprivileged test user are required")
    version = subprocess.run([binaries / "initdb", "--version"],
                             check=True, capture_output=True, text=True).stdout
    if "PostgreSQL) 18." not in version:
        raise RuntimeError("refusing a non-PG18 fixture")
    root = Path(tempfile.mkdtemp(prefix="secpal-enrollment-pg-"))
    data, socket = root / "data", root / "socket"
    socket.mkdir(mode=0o700)
    subprocess.run([binaries / "initdb", "-D", data, "--no-locale",
                    "--encoding=UTF8", "--auth-local=peer", "--auth-host=reject"],
                   check=True, capture_output=True)
    options = (f"-c listen_addresses='' -c unix_socket_directories={socket} "
               "-c max_connections=16 -c shared_buffers=16MB -c fsync=on")
    try:
        subprocess.run([binaries / "pg_ctl", "-D", data, "-l", root / "server.log",
                        "-o", options, "-w", "-t", "30", "start"],
                       check=True, capture_output=True, timeout=40)
        from psycopg.conninfo import make_conninfo
        connection = make_conninfo(host=str(socket), port=5432,
                                   user=getpass.getuser(), dbname="postgres")
        with psycopg.connect(connection, autocommit=True) as db:
            db.execute("CREATE DATABASE secpal_enrollment_test_contract")
            db.execute("CREATE ROLE secpal_enrollment_runtime NOLOGIN")
        os.environ["SECPAL_ENROLLMENT_TEST_DSN"] = make_conninfo(
            connection, dbname="secpal_enrollment_test_contract")
        yield
    finally:
        status = subprocess.run([binaries / "pg_ctl", "-D", data, "status"],
                                capture_output=True, timeout=10)
        if status.returncode == 0:
            subprocess.run([binaries / "pg_ctl", "-D", data, "-m", "fast",
                            "-w", "-t", "30", "stop"],
                           check=True, capture_output=True, timeout=40)
        elif status.returncode != 3:
            raise RuntimeError("fixture state ambiguous; retained for bounded cleanup")
        os.environ.pop("SECPAL_ENROLLMENT_TEST_DSN", None)
        # Cleanup follows successful shutdown even when unittest raises SystemExit.
        shutil.rmtree(root)


if __name__ == "__main__":
    with postgres_fixture():
        unittest.main()
