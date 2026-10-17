#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Real OpenSSL, AES-GCM/key-wrap and PG18; provider/custodian adapters synthetic."""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("enrollment_fixture", ROOT / "tests/host-enrollment.py")
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)
import secret_authority as secret
enrollment = fixture.enrollment


class MemoryCustody:
    """Synthetic independent actor, never evidence of actual operational custody."""
    def __init__(self):
        self.key = os.urandom(32)
        self.saved = None

    def retain(self, encrypted, manifest):
        self.saved = (bytes(encrypted), dict(manifest))

    def recover(self):
        return self.saved[0], self.key, self.saved[1]


class SecretAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.EnrollmentTests("runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        _, credential = self.f.complete()
        self.identity = self.f.host.accept(credential, self.f.ca)
        self.root = self.f.root
        self.key = os.urandom(32)
        self.store = secret.PostgresStore.initialize(
            self.root / "secrets", self.f.dba_database, self.f.deployment,
            unseal=lambda: self.key)
        self.addCleanup(self.drop_secrets)
        self.custody = MemoryCustody()
        self.admin = secret.SecretAdministration(self.store)
        self.bootstrap = self.admin.bootstrap(self.custody, recovery_key=self.custody.key)
        self.verifier = enrollment.EnrollmentVerifier(
            self.root / "verifier", self.f.ca, self.f.deployment, self.f.target,
            "single-host", observe=self.f.observe, current=lambda host: self.f.authority.current_identity())
        self.allowed = True
        def authorize(identity, purpose, generations):
            if not self.allowed:
                raise secret.SecretError("purpose-not-authorized")
        self.activation = secret.DeploymentActivation(
            self.store, verifier=self.verifier, authorize=authorize)
        self.delivery = secret.ProtectedCredentials(self.root / "credentials")
        self.app = self.bootstrap["app-key"]
        self.tenant = self.bootstrap["tenant-kek"]

    def drop_secrets(self):
        with self.f.connect() as db:
            db.execute("DROP SCHEMA IF EXISTS secpal_secrets CASCADE")

    def challenge(self, refs=None, purpose="api", ttl=60):
        return self.activation.challenge(
            self.identity, purpose, refs or [self.app, self.tenant], ttl=ttl)

    def redeem(self, challenge, identity=None, proof=None, delivery=None):
        identity = self.identity if identity is None else identity
        proof = self.f.host.prove_identity(identity, challenge["challenge"]) if proof is None else proof
        return self.activation.activate(challenge["session_id"], identity, proof,
                                        delivery=delivery or self.delivery)

    def test_current_enrollment_materializes_only_authorized_purpose(self):
        challenge = self.challenge()
        result = self.redeem(challenge)
        self.assertEqual(result["purpose"], "api")
        path = Path(result["directory"])
        self.assertEqual(set(p.name for p in path.iterdir()), {"app-key", "app-previous-keys", "tenant-kek"})
        self.assertEqual((path / "tenant-kek").stat().st_mode & 0o777, 0o600)
        self.assertEqual(len((path / "tenant-kek").read_bytes()), 32)
        self.assertTrue((path / "app-key").read_bytes().startswith(b"base64:"))
        self.assertNotIn("PRIVATE KEY", json.dumps(result))
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge)

    def test_missing_possession_and_expired_session_fail_without_delivery(self):
        challenge = self.challenge()
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge, proof="not-a-proof")
        with patch.object(secret, "now", return_value=challenge["expires_at"]):
            with self.assertRaises(secret.SecretError):
                self.redeem(challenge)
        self.assertEqual(list((self.root / "credentials").iterdir()), [])

    def test_enrollment_does_not_authorize_all_purposes_or_key_classes(self):
        for purpose, refs in [("frontend", [self.app]), ("haproxy", [self.app]),
                              ("api", [self.bootstrap["backup-key"]]),
                              ("worker-general", [self.bootstrap["root-kek"]]),
                              ("api", [self.bootstrap["postgres-ca"]])]:
            with self.subTest(purpose=purpose, refs=refs):
                with self.assertRaises(secret.SecretError):
                    self.challenge(refs, purpose)
        self.allowed = False
        with self.assertRaises(secret.SecretError):
            self.challenge()

    def test_policy_and_registration_are_read_back_at_redemption(self):
        challenge = self.challenge()
        self.allowed = False
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge)
        self.allowed = True
        self.f.authority.recovery = lambda request, previous: None
        _, credential = self.f.complete(purpose="recover")
        self.f.host.accept(credential, self.f.ca)
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge)

    def test_concurrent_redemption_releases_exactly_once(self):
        challenge = self.challenge()
        proof = self.f.host.prove_identity(self.identity, challenge["challenge"])
        def consume():
            try:
                self.redeem(challenge, proof=proof)
                return "accepted"
            except secret.SecretError:
                return "rejected"
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(lambda _: consume(), range(2))),
                             ["accepted", "rejected"])

    def test_wrong_host_deployment_resource_incarnation_role_fail(self):
        for field, value in [
            ("host_id", str(uuid.uuid4())), ("deployment_id", str(uuid.uuid4())),
            ("incarnation_id", str(uuid.uuid4())), ("role", "green"),
            ("generation", 2), ("resource", {**self.identity["resource"],
                                            "provider_resource_id": "different"})]:
            with self.subTest(field=field):
                challenge = self.challenge()
                wrong = {**self.identity, field: value}
                proof = self.f.host.prove_identity(self.identity, challenge["challenge"])
                with self.assertRaises(secret.SecretError):
                    self.redeem(challenge, identity=wrong, proof=proof)

    def test_database_contains_only_authenticated_ciphertext_and_rejects_tampering(self):
        with self.f.connect() as db:
            blob = bytes(db.execute("SELECT ciphertext FROM secpal_secrets.state").fetchone()[0])
        self.assertFalse(b"app-key" in blob, "plaintext metadata in authority state")
        self.assertFalse(b"base64:" in blob, "plaintext secret in authority state")
        with self.f.connect() as db:
            db.execute("UPDATE secpal_secrets.state SET ciphertext=%s", (blob[:-1] + bytes([blob[-1] ^ 1]),))
        with self.assertRaises(secret.SecretError):
            self.challenge()

    def test_ambiguous_commit_cannot_publish_secrets(self):
        challenge = self.challenge()
        with self.f.connect() as db:
            original = bytes(db.execute("SELECT ciphertext FROM secpal_secrets.state").fetchone()[0])
        commit = psycopg.Connection.commit
        injected = []
        def lost_ack(db):
            if db.info.get_parameters().get("options") == "-c role=secpal_enrollment_runtime":
                return commit(db)
            row = db.execute("SELECT ciphertext FROM secpal_secrets.state").fetchone()
            value = bytes(row["ciphertext"] if isinstance(row, dict) else row[0])
            commit(db)
            if value != original:
                injected.append(True)
                raise psycopg.OperationalError("synthetic-lost-ack")
        with patch.object(psycopg.Connection, "commit", lost_ack):
            with self.assertRaises(secret.SecretError):
                self.redeem(challenge)
        self.assertTrue(injected)
        self.assertEqual(list((self.root / "credentials").iterdir()), [])
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge)

    def test_existing_delivery_survives_authority_outage(self):
        result = self.redeem(self.challenge())
        path = Path(result["directory"]) / "tenant-kek"
        previous = path.read_bytes()
        def unavailable():
            raise RuntimeError("synthetic authority outage; no raw detail allowed")
        self.store.unseal = unavailable
        with self.assertRaises(secret.SecretError):
            self.challenge()
        self.assertTrue(__import__("hmac").compare_digest(path.read_bytes(), previous),
                        "accepted delivery changed during authority outage")

    def test_recovery_rejects_missing_required_generation_and_needs_external_key(self):
        encrypted, key, manifest = self.custody.recover()
        missing = {str(uuid.uuid4()): {"generation": 1, "fingerprint": "f" * 64}}
        for candidate_key, requirements in [(os.urandom(32), manifest), (key, missing)]:
            with self.assertRaises(secret.SecretError):
                secret.recover_authority(encrypted, candidate_key, self.f.deployment,
                                         required=requirements)
        state = secret.recover_authority(encrypted, key, self.f.deployment, required=manifest)
        self.assertEqual(state["sessions"], {})
        self.assertEqual(state["deployment_id"], self.f.deployment)

    def test_missing_custody_blocks_first_use(self):
        with patch.object(self.custody, "retain", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(secret.SecretError):
                self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        with self.assertRaises(secret.SecretError):
            self.challenge()

    def test_bootstrap_cannot_replace_existing_crypto_and_host_replacement_does_not_rotate(self):
        before = self.admin.metadata(self.app)
        with self.assertRaises(secret.SecretError):
            self.admin.bootstrap(self.custody, recovery_key=self.custody.key)
        after = self.admin.metadata(self.app)
        self.assertEqual(before, after)

    def test_partial_materialization_leaves_previous_delivery_and_consumes_session(self):
        first = self.redeem(self.challenge())
        old = Path(first["directory"])
        before = {p.name: secret._sha(p.read_bytes()) for p in old.iterdir()}
        challenge = self.challenge()
        write = enrollment._write
        calls = []
        def interrupted(path, value):
            if self.delivery.root in Path(path).parents:
                calls.append(str(path))
            if self.delivery.root in Path(path).parents and len(calls) == 2:
                raise OSError("synthetic interruption")
            return write(path, value)
        with patch.object(enrollment, "_write", interrupted):
            with self.assertRaises(secret.SecretError):
                self.redeem(challenge)
        self.assertEqual({p.name: secret._sha(p.read_bytes()) for p in old.iterdir()}, before)
        self.assertEqual(list(self.delivery.root.iterdir()), [old])
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge)

    def test_runtime_credentials_bind_the_exact_host_and_purpose(self):
        wrong_host = str(uuid.uuid4())
        value = secret._encode({"username": "secpal_test_runtime", "password": "A" * 40,
                                 "ca": self.f.ca.read_text()})
        wrong = self.admin.candidate("postgres-runtime", value.replace(b"secpal_test_runtime", b"secpal_wrong_runtime"), host_id=wrong_host,
                                     purposes=["api"])
        good = self.admin.candidate("postgres-runtime", value,
                                    host_id=self.identity["host_id"], purposes=["api"])
        migrate = self.admin.candidate("postgres-migration", value.replace(b"secpal_test_runtime", b"secpal_test_migration"),
                                       host_id=self.identity["host_id"], purposes=["migrate"])
        for ref in [wrong, good, migrate]:
            self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
            self.admin.rotate(ref, validate=lambda *a: None, start=lambda *a: None,
                              ready=lambda *a: None, accept=lambda *a: None,
                              revoke=lambda *a: None, rollback=lambda *a: None)
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        with self.assertRaises(secret.SecretError):
            self.challenge([wrong])
        with self.assertRaises(secret.SecretError):
            self.challenge([migrate])
        with self.assertRaises(secret.SecretError):
            self.challenge([good], purpose="worker-general")
        result = self.redeem(self.challenge([good]))
        self.assertEqual(set(p.name for p in Path(result["directory"]).iterdir()),
                         {"postgres-username", "postgres-password", "postgres-ca.crt"})

    def test_rotation_orders_acceptance_and_revocation_and_preserves_retained_key(self):
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        calls = []
        callbacks = {name: (lambda *args, label=name: calls.append(label))
                     for name in ["validate", "start", "ready", "accept", "revoke", "rollback"]}
        result = self.admin.rotate(candidate, **callbacks)
        self.assertEqual(result["status"], "current")
        self.assertIsNone(result["rotation"])
        self.assertEqual(calls, ["validate", "start", "ready", "accept", "revoke"])
        self.assertEqual(self.admin.metadata(self.app)["status"], "retained")
        self.assertEqual(self.admin.metadata(candidate)["status"], "current")
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        result = self.redeem(self.challenge([candidate]))
        self.assertEqual(len((Path(result["directory"]) / "app-previous-keys").read_bytes()), 51)

    def test_rotation_readiness_failure_rolls_back_and_does_not_revoke_current(self):
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        calls = []
        def not_ready(*args):raise RuntimeError("synthetic service failure")
        with self.assertRaises(secret.SecretError):
            self.admin.rotate(candidate, validate=lambda *a: calls.append("validate"),
                              start=lambda *a: calls.append("start"), ready=not_ready,
                              accept=lambda *a: calls.append("accept"),
                              revoke=lambda *a: calls.append("revoke"),
                              rollback=lambda *a: calls.append("rollback"))
        self.assertEqual(calls, ["validate", "start", "rollback"])
        self.assertEqual(self.admin.metadata(self.app)["status"], "current")
        self.assertEqual(self.admin.metadata(candidate)["status"], "candidate")

    def test_retention_prevents_key_deletion_and_root_rotation_only_rewraps(self):
        owner = str(uuid.uuid4())
        self.admin.retain(self.tenant, owner)
        self.admin.retain(self.bootstrap["root-kek"], owner)
        with self.assertRaises(secret.SecretError):
            self.admin.retire(self.tenant, authorize=lambda m: None)
        before = self.admin.metadata(self.tenant)
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        replacement = self.admin.rewrap_root(self.bootstrap["root-kek"])
        self.assertEqual(self.admin.metadata(self.tenant)["fingerprint"], before["fingerprint"])
        self.assertEqual(self.admin.metadata(replacement)["generation"], 2)
        self.assertEqual(self.admin.metadata(self.bootstrap["root-kek"])["status"], "retained")
        with self.assertRaises(secret.SecretError):
            self.admin.retire(self.bootstrap["root-kek"], authorize=lambda m: None)

    def test_native_postgres_identity_and_server_certificate_contract(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "db.secpal.internal")]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("db.secpal.internal")]), False)
               .sign(key, hashes.SHA256()))
        certificate, ca = self.admin.sign_postgres_csr(
            self.bootstrap["postgres-ca"], csr.public_bytes(serialization.Encoding.PEM))
        parsed = x509.load_pem_x509_certificate(certificate)
        self.assertEqual(parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                         .value.get_values_for_type(x509.DNSName), ["db.secpal.internal"])
        self.assertFalse(parsed.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertFalse(b"PRIVATE" in certificate + ca, "private material returned by issuer")

    def test_database_state_runtime_cannot_read_or_modify_enrollment(self):
        with self.f.connect() as db:
            db.execute("CREATE ROLE secpal_secret_test_runtime NOLOGIN")
            db.execute("GRANT USAGE ON SCHEMA secpal_secrets TO secpal_secret_test_runtime")
            db.execute("GRANT SELECT,UPDATE ON secpal_secrets.state TO secpal_secret_test_runtime")
        try:
            self.store.database = {**self.f.dba_database, "options": "-c role=secpal_secret_test_runtime"}
            result = self.redeem(self.challenge())
            self.assertEqual(result["host_id"], self.identity["host_id"])
            with psycopg.connect(**self.store.database) as db:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    db.execute("SELECT * FROM secpal_enrollment.enrollments")
        finally:
            with self.f.connect() as db:
                db.execute("DROP OWNED BY secpal_secret_test_runtime")
                db.execute("DROP ROLE secpal_secret_test_runtime")

    def test_restored_replay_state_fails_closed_without_repair(self):
        challenge = self.challenge()
        with self.f.connect() as db:
            previous = bytes(db.execute("SELECT ciphertext FROM secpal_secrets.state").fetchone()[0])
        self.redeem(challenge)
        with self.f.connect() as db:
            db.execute("UPDATE secpal_secrets.state SET ciphertext=%s", (previous,))
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge)

    def test_full_authority_loss_restores_crypto_without_old_activation_authority(self):
        pending = self.challenge()
        expected = self.admin.metadata(self.app)["fingerprint"]
        encrypted, key, manifest = self.custody.recover()
        with self.f.connect() as db:
            db.execute("DROP SCHEMA secpal_secrets CASCADE")
        __import__("shutil").rmtree(self.root / "secrets")
        new_key = os.urandom(32)
        with self.assertRaises(secret.SecretError):
            secret.restore_authority(self.root / "restored", self.f.dba_database,
                                     self.f.deployment, encrypted, key,
                                     required=manifest, unseal=lambda: new_key, authorize=None)
        restored = secret.restore_authority(
            self.root / "restored", self.f.dba_database, self.f.deployment,
            encrypted, key, required=manifest, unseal=lambda: new_key,
            authorize=lambda recovered_manifest: None)
        admin = secret.SecretAdministration(restored)
        self.assertEqual(admin.metadata(self.app)["fingerprint"], expected)
        activation = secret.DeploymentActivation(restored, verifier=self.verifier,
                                                  authorize=lambda *args: None)
        with self.assertRaises(secret.SecretError):
            activation.challenge(self.identity, "api", [self.app])
        admin.checkpoint(self.custody, recovery_key=self.custody.key)
        with self.assertRaises(secret.SecretError):
            activation.activate(pending["session_id"], self.identity, "unused",
                                delivery=self.delivery)
        challenge = activation.challenge(self.identity, "api", [self.app])
        proof = self.f.host.prove_identity(self.identity, challenge["challenge"])
        self.assertEqual(activation.activate(challenge["session_id"], self.identity, proof,
                                            delivery=self.delivery)["purpose"], "api")

    def test_retired_candidate_generation_id_is_never_reused(self):
        value = b"base64:" + __import__("base64").b64encode(os.urandom(32))
        candidate = self.admin.candidate("app-key", value, authority_id=self.app["authority_id"])
        self.admin.retire(candidate, authorize=lambda metadata: None)
        next_candidate = self.admin.candidate("app-key", value, authority_id=self.app["authority_id"])
        self.assertGreater(next_candidate["generation"], candidate["generation"])

    def test_native_database_logins_are_host_scoped_scram_and_ddl_separate(self):
        with self.f.connect() as db:
            db.execute("CREATE ROLE secpal_runtime NOLOGIN")
            db.execute("CREATE ROLE secpal_migration NOLOGIN")
            db.execute("CREATE ROLE secpal_owner NOLOGIN")
            db.execute("GRANT secpal_owner TO secpal_migration WITH ADMIN FALSE, INHERIT FALSE, SET TRUE")
        refs = []
        try:
            for purpose in ["api", "migrate"]:
                ref = self.admin.issue_postgres_login(
                    self.f.dba_database, self.identity["host_id"], purpose,
                    self.f.ca.read_bytes())
                refs.append(ref)
            with self.store.transaction() as state:
                bundles = [json.loads(secret._value(state, ref)) for ref in refs]
            self.assertNotEqual(bundles[0]["username"], bundles[1]["username"])
            self.assertFalse(__import__("hmac").compare_digest(bundles[0]["password"], bundles[1]["password"]),
                             "runtime and migration credentials coincide")
            with self.f.connect() as db:
                for index, bundle in enumerate(bundles):
                    row = db.execute("SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolpassword FROM pg_authid WHERE rolname=%s",
                                     (bundle["username"],)).fetchone()
                    self.assertEqual(row[:6], (False, False, False, False, False, False))
                    self.assertTrue(row[6].startswith("SCRAM-SHA-256$"))
                    memberships = db.execute(
                        "SELECT r.rolname,m.admin_option,m.inherit_option,m.set_option FROM pg_auth_members m "
                        "JOIN pg_roles r ON m.roleid=r.oid JOIN pg_roles u ON m.member=u.oid WHERE u.rolname=%s",
                        (bundle["username"],)).fetchall()
                    self.assertEqual(memberships, [(["secpal_runtime", "secpal_migration"][index],
                                                   False, True, bool(index))])
            for index, bundle in enumerate(bundles):
                from psycopg import sql
                with psycopg.connect(**self.f.dba_database, autocommit=True) as scoped:
                    scoped.execute(sql.SQL("SET SESSION AUTHORIZATION {}").format(
                        sql.Identifier(bundle["username"])))
                    if index == 0:
                        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                            scoped.execute("SET ROLE secpal_owner")
                    else:
                        scoped.execute("SET ROLE secpal_owner")
                        self.assertEqual(scoped.execute("SELECT current_user").fetchone()[0],
                                         "secpal_owner")
            log_root = Path(self.f.dba_database["host"]).parent
            for log in log_root.glob("*.log"):
                data = log.read_bytes()
                for bundle in bundles:
                    self.assertFalse(bundle["password"].encode() in data,
                                     "synthetic database secret appeared in native log")
        finally:
            with self.f.connect() as db:
                for bundle in locals().get("bundles", []):
                    from psycopg import sql
                    db.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(bundle["username"])))
                db.execute("DROP ROLE secpal_runtime")
                db.execute("DROP ROLE secpal_migration")
                db.execute("DROP ROLE secpal_owner")

    def test_unsigned_or_wrong_name_database_csr_is_rejected(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker.invalid")]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName("attacker.invalid")]), False)
               .sign(key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
        for bad in [b"not-a-csr", csr, csr + b"trailing"]:
            with self.assertRaises(secret.SecretError):
                self.admin.sign_postgres_csr(self.bootstrap["postgres-ca"], bad)

    def test_failed_old_credential_revocation_survives_restart_and_blocks_new_release(self):
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        def fail(*args):raise RuntimeError("synthetic revoker unavailable")
        with self.assertRaises(secret.SecretError):
            self.admin.rotate(candidate, validate=lambda *a: None, start=lambda *a: None,
                              ready=lambda *a: None, accept=lambda *a: None,
                              revoke=fail, rollback=lambda *a: None)
        self.assertEqual(self.admin.metadata(self.app)["status"], "revocation-pending")
        restarted = secret.PostgresStore(
            self.store.directory, self.f.dba_database, self.f.deployment, unseal=lambda: self.key)
        restarted_admin = secret.SecretAdministration(restarted)
        restarted_admin.checkpoint(self.custody, recovery_key=self.custody.key)
        with self.assertRaises(secret.SecretError):
            self.challenge([candidate])
        restarted_admin.finish_revocation(self.app, revoke=lambda previous: None)
        restarted_admin.checkpoint(self.custody, recovery_key=self.custody.key)
        self.assertEqual(self.admin.metadata(self.app)["status"], "retained")
        self.redeem(self.challenge([candidate]))

    def test_publication_fsync_failure_cleans_only_its_owned_candidate(self):
        challenge = self.challenge()
        sync = enrollment._sync
        def failed(path):
            if Path(path) == self.delivery.root:
                raise enrollment.EnrollmentError("synthetic-directory-fsync")
            return sync(path)
        with patch.object(enrollment, "_sync", failed):
            with self.assertRaises(secret.SecretError):
                self.redeem(challenge)
        self.assertEqual(list(self.delivery.root.iterdir()), [])
        with self.assertRaises(secret.SecretError):
            self.redeem(challenge)

    def test_retention_release_requires_owner_authorization_and_preserves_other_owners(self):
        first, second = str(uuid.uuid4()), str(uuid.uuid4())
        self.admin.retain(self.app, first)
        self.admin.retain(self.app, second)
        with self.assertRaises(secret.SecretError):
            self.admin.release_retention(self.app, first, authorize=None)
        self.assertEqual(self.admin.metadata(self.app)["retained_by"], [first, second])
        self.admin.release_retention(self.app, first, authorize=lambda metadata, owner: None)
        self.assertEqual(self.admin.metadata(self.app)["retained_by"], [second])

    def test_imported_database_material_cannot_deliver_signing_keys_or_stable_roles(self):
        for username, ca in [
            ("secpal_runtime", self.f.ca.read_text()),
            ("secpal_safe_runtime", self.f.ca.read_text() + self.f.key.read_text()),
        ]:
            with self.subTest(username=username):
                value = secret._encode({"username": username, "password": "A" * 40, "ca": ca})
                with self.assertRaises(secret.SecretError):
                    self.admin.candidate("postgres-runtime", value,
                                         host_id=self.identity["host_id"], purposes=["api"])

    def test_rotation_can_stage_candidate_only_with_explicit_rotation_authorization(self):
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        with self.assertRaises(secret.SecretError):
            self.challenge([candidate])
        self.activation.authorize_rotation = lambda identity, purpose, metadata: None
        # Even an authorized rotation cannot release a plain, unclaimed candidate.
        with self.assertRaises(secret.SecretError):
            self.activation.challenge_rotation(self.identity, "api", [candidate],
                                               candidate=candidate)
        delivered = []
        def stage(ref, previous):
            self.activation.authorize_rotation = None
            with self.assertRaises(secret.SecretError):
                self.activation.challenge_rotation(self.identity, "api", [candidate],
                                                   candidate=candidate)
            self.activation.authorize_rotation = lambda identity, purpose, metadata: None
            challenge = self.activation.challenge_rotation(self.identity, "api", [candidate],
                                                            candidate=candidate)
            result = self.redeem(challenge)
            path = Path(result["directory"])
            with self.store.transaction() as state:
                old = secret._value(state, self.app)
            self.assertTrue(__import__("hmac").compare_digest(
                (path / "app-previous-keys").read_bytes(), old),
                "candidate cannot decrypt state written by the accepted current key")
            self.assertEqual(self.admin.metadata(candidate)["status"], "rotation-pending")
            with self.assertRaises(secret.SecretError):
                self.admin.retire(candidate, authorize=lambda metadata: None)
            self.assertEqual(self.admin.metadata(self.app)["status"], "current")
            delivered.append(challenge)
        self.admin.rotate(candidate, validate=stage, start=lambda *a: None,
                          ready=lambda *a: None, accept=lambda *a: None,
                          revoke=lambda *a: None, rollback=lambda *a: None)
        self.assertEqual(self.admin.metadata(candidate)["status"], "current")
        with self.assertRaises(secret.SecretError):
            self.redeem(delivered[0])

    def test_concurrent_rotation_cannot_rollback_a_different_accepted_rotation(self):
        import threading
        import time
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        entered, release = threading.Event(), threading.Event()
        starts, rollbacks = [], []
        def start(*args):
            starts.append(threading.current_thread().name)
            entered.set()
            release.wait(3)
        def rotate():
            try:
                self.admin.rotate(candidate, validate=lambda *a: None, start=start,
                                  ready=lambda *a: None, accept=lambda *a: None,
                                  revoke=lambda *a: None, rollback=lambda *a: rollbacks.append(True))
                return "accepted"
            except secret.SecretError:
                return "rejected"
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first = pool.submit(rotate)
            self.assertTrue(entered.wait(2))
            second = pool.submit(rotate)
            time.sleep(0.1)
            release.set()
            self.assertEqual(sorted([first.result(), second.result()]), ["accepted", "rejected"])
        self.assertEqual(len(starts), 1, "concurrent operation crossed service boundary")
        self.assertEqual(rollbacks, [], "loser rolled back accepted service state")

    def test_lost_rotation_commit_ack_does_not_roll_back_committed_current(self):
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        commit = psycopg.Connection.commit
        injected, rollbacks = [], []
        def lost(db):
            if db.info.get_parameters().get("options") == "-c role=secpal_enrollment_runtime":
                return commit(db)
            row = db.execute("SELECT ciphertext FROM secpal_secrets.state").fetchone()
            blob = bytes(row["ciphertext"] if isinstance(row, dict) else row[0])
            state = secret._open(self.key, blob, self.store._aad)
            current = state["authorities"][candidate["authority_id"]]["current"]
            commit(db)
            if current == candidate["generation"] and not injected:
                injected.append(True)
                raise psycopg.OperationalError("synthetic rotation acknowledgement loss")
        with patch.object(psycopg.Connection, "commit", lost):
            with self.assertRaises(secret.SecretError):
                self.admin.rotate(candidate, validate=lambda *a: None, start=lambda *a: None,
                                  ready=lambda *a: None, accept=lambda *a: None,
                                  revoke=lambda *a: None, rollback=lambda *a: rollbacks.append(True))
        self.assertTrue(injected)
        self.assertEqual(rollbacks, [], "unverified rollback crossed an ambiguous commit boundary")
        self.assertEqual(self.admin.metadata(candidate)["status"], "current")
        self.assertEqual(self.admin.metadata(self.app)["status"], "revocation-pending")

    def test_pending_revocation_cannot_be_deleted_to_bypass_release_guard(self):
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        def fail(*args):raise RuntimeError("synthetic unavailable revoker")
        with self.assertRaises(secret.SecretError):
            self.admin.rotate(candidate, validate=lambda *a: None, start=lambda *a: None,
                              ready=lambda *a: None, accept=lambda *a: None,
                              revoke=fail, rollback=lambda *a: None)
        with self.assertRaises(secret.SecretError):
            self.admin.retire(self.app, authorize=lambda metadata: None)
        self.assertEqual(self.admin.metadata(self.app)["status"], "revocation-pending")

    def test_business_rotation_cannot_create_a_second_unlinked_authority(self):
        value = b"base64:" + __import__("base64").b64encode(os.urandom(32))
        for aid in [None, str(uuid.uuid4())]:
            with self.assertRaises(secret.SecretError):
                self.admin.candidate("app-key", value, authority_id=aid)
        self.assertEqual(self.admin.metadata(self.app)["status"], "current")

    def test_process_termination_retains_rotation_obligation_until_verified_rollback(self):
        class PowerLoss(BaseException):pass
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        def terminate(*args):raise PowerLoss()
        with self.assertRaises(PowerLoss):
            self.admin.rotate(candidate, validate=lambda *a: None, start=terminate,
                              ready=lambda *a: None, accept=lambda *a: None,
                              revoke=lambda *a: None, rollback=lambda *a: None)
        self.assertEqual(self.admin.metadata(candidate)["status"], "rotation-pending")
        self.assertEqual(self.admin.metadata(self.app)["status"], "current")
        with self.assertRaises(secret.SecretError):
            self.challenge()
        with self.assertRaises(secret.SecretError):
            self.admin.rollback_rotation(candidate, rollback=None)
        restarted = secret.SecretAdministration(secret.PostgresStore(
            self.store.directory, self.f.dba_database, self.f.deployment, unseal=lambda: self.key))
        restarted.rollback_rotation(candidate, rollback=lambda ref, previous: None)
        self.assertEqual(self.admin.metadata(candidate)["status"], "candidate")
        self.assertIsNone(self.admin.metadata(candidate)["rotation"])
        self.redeem(self.challenge())

    def test_application_retention_cap_rejects_before_external_side_effects(self):
        current = self.app
        for _ in range(3):
            ref = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                       authority_id=current["authority_id"])
            self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
            self.admin.rotate(ref, validate=lambda *a: None, start=lambda *a: None,
                              ready=lambda *a: None, accept=lambda *a: None,
                              revoke=lambda *a: None, rollback=lambda *a: None)
            current = ref
        ref = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                   authority_id=current["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        calls = []
        with self.assertRaises(secret.SecretError):
            self.admin.rotate(ref, validate=lambda *a: calls.append("validate"),
                              start=lambda *a: calls.append("start"),
                              ready=lambda *a: calls.append("ready"),
                              accept=lambda *a: calls.append("accept"),
                              revoke=lambda *a: calls.append("revoke"),
                              rollback=lambda *a: calls.append("rollback"))
        self.assertEqual(calls, [])
        self.assertEqual(self.admin.metadata(current)["status"], "current")

    def test_database_role_cannot_store_oversized_ciphertext(self):
        with self.f.connect() as db:
            with self.assertRaises(psycopg.errors.CheckViolation):
                db.execute("UPDATE secpal_secrets.state SET ciphertext=%s",
                           (b"x" * (secret.MAX_STATE + 29),))

    def test_rotation_session_cannot_cross_a_verified_rollback_into_another_attempt(self):
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        self.activation.authorize_rotation = lambda *args: None
        held = []
        def prepare(*args):
            held.append(self.activation.challenge_rotation(
                self.identity, "api", [candidate], candidate=candidate))
        def fail(*args):raise RuntimeError("synthetic readiness failure")
        with self.assertRaises(secret.SecretError):
            self.admin.rotate(candidate, validate=prepare, start=lambda *a: None,
                              ready=fail, accept=lambda *a: None, revoke=lambda *a: None,
                              rollback=lambda *a: None)
        outcomes = []
        def retry(*args):
            legacy = self.activation.challenge_rotation(
                self.identity, "api", [candidate], candidate=candidate)
            with self.store.transaction(write=True) as state:
                del state["sessions"][legacy["session_id"]]["operation_id"]
            with self.assertRaisesRegex(secret.SecretError, "rotation-operation-binding"):
                self.redeem(legacy)
            try:
                self.redeem(held[0])
                outcomes.append("accepted-stale-session")
            except secret.SecretError:
                outcomes.append("rejected")
        self.admin.rotate(candidate, validate=retry, start=lambda *a: None,
                          ready=lambda *a: None, accept=lambda *a: None,
                          revoke=lambda *a: None, rollback=lambda *a: None)
        self.assertEqual(outcomes, ["rejected"])
        self.assertEqual(list(self.delivery.root.iterdir()), [])

    def test_pending_publication_finishes_before_verified_rollback(self):
        import threading
        import time
        class PowerLoss(BaseException):pass
        candidate = self.admin.candidate("app-key", b"base64:" + __import__("base64").b64encode(os.urandom(32)),
                                         authority_id=self.app["authority_id"])
        self.admin.checkpoint(self.custody, recovery_key=self.custody.key)
        self.activation.authorize_rotation = lambda *args: None
        held = []
        def prepare(*args):
            held.append(self.activation.challenge_rotation(
                self.identity, "api", [candidate], candidate=candidate))
            raise PowerLoss()
        with self.assertRaises(PowerLoss):
            self.admin.rotate(candidate, validate=prepare, start=lambda *a: None,
                              ready=lambda *a: None, accept=lambda *a: None,
                              revoke=lambda *a: None, rollback=lambda *a: None)
        entered, release, rolling_back = threading.Event(), threading.Event(), threading.Event()
        order = []
        publish = self.delivery.publish
        def delayed(*args):
            entered.set()
            self.assertTrue(release.wait(3))
            result = publish(*args)
            order.append("published")
            return result
        def rollback(*args):
            order.append("rollback")
            # Real owned filesystem cleanup is verified before rollback returns.
            import shutil
            for directory in self.delivery.root.iterdir():
                shutil.rmtree(directory)
            self.assertEqual(list(self.delivery.root.iterdir()), [])
        def run_rollback():
            rolling_back.set()
            self.admin.rollback_rotation(candidate, rollback=rollback)
        with patch.object(self.delivery, "publish", side_effect=delayed):
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                delivery = pool.submit(self.redeem, held[0])
                self.assertTrue(entered.wait(2))
                rollback_result = pool.submit(run_rollback)
                self.assertTrue(rolling_back.wait(2))
                time.sleep(0.15)
                release.set()
                delivery.result()
                rollback_result.result()
        self.assertEqual(order, ["published", "rollback"],
                         "credential publication crossed verified rollback")
        self.assertEqual(list(self.delivery.root.iterdir()), [])


if __name__ == "__main__":
    with fixture.postgres_fixture():
        unittest.main()
