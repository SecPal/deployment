#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native PG18 and durable directory semantics; managed adapter/policy are synthetic."""
import concurrent.futures
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

import psycopg
from psycopg.conninfo import conninfo_to_dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import private_objects as objects

spec = importlib.util.spec_from_file_location("object_pg_fixture", ROOT / "tests/host-enrollment.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class PrivateObjectTests(unittest.TestCase):
    def setUp(self):
        self.database = conninfo_to_dict(os.environ["SECPAL_ENROLLMENT_TEST_DSN"])
        self.temporary = tempfile.TemporaryDirectory(prefix="secpal-object-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "objects").mkdir(mode=0o700)
        self.backend = objects.SelfHostedDirectory(self.root / "objects")
        objects.initialize_catalog(self.database)
        self.addCleanup(self.drop)
        self.deployment, self.tenant = str(uuid.uuid4()), "1"
        self.key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        self.bytes = nonce + AESGCM(self.key).encrypt(nonce, b"synthetic private document", None)
        self.crypto = {"scheme": "synthetic-test-aes256gcm", "generation": 1,
                       "key_reference": str(uuid.uuid4()), "wrapped_dek": "synthetic-public-envelope"}
        self.actions = []
        self.node = self.catalog()
        self.retention = objects.ObjectRetention(
            self.node, authorize=lambda action, row, owner: None)
        self.gc = objects.ObjectGarbageCollector(
            self.node, destroy=self.backend.destroy, authorize=lambda row: None)

    def drop(self):
        with psycopg.connect(**self.database) as db:
            db.execute("DROP SCHEMA secpal_objects CASCADE")

    def policy(self, action, row):
        self.actions.append(action)
        if row["deployment_id"] != self.deployment or row["tenant_id"] != self.tenant:
            raise objects.ObjectError("unauthorized")

    def admit_crypto(self, value, metadata, tenant):
        if metadata != self.crypto or tenant != self.tenant:
            raise objects.ObjectError("crypto")
        AESGCM(self.key).decrypt(value[:12], value[12:], None)

    def catalog(self, **options):
        arguments = dict(database=self.database, deployment_id=self.deployment,
                         tenant_id=self.tenant, purpose="api", backend=self.backend,
                         backend_id="synthetic-directory", mode="self-hosted",
                         authorize=self.policy, admit_backend=lambda backend, mode: None,
                         admit_ciphertext=self.admit_crypto, replication_targets=("test-replica",))
        return objects.ObjectCatalog(**(arguments | options))

    def reserve(self):
        return self.node.reserve(self.bytes, self.crypto)

    def publish(self, object_id=None, **options):
        return self.node.publish(object_id or self.reserve(), self.bytes,
                                 reference_id=str(uuid.uuid4()), **options)

    def test_publish_read_stat_exact_ciphertext_and_atomic_replication_intent(self):
        row = self.publish()
        self.assertEqual(self.node.read(row["object_id"]), self.bytes)
        self.assertEqual(row["storage_sha256"], hashlib.sha256(self.bytes).hexdigest())
        self.assertEqual(row["byte_size"], len(self.bytes))
        self.assertEqual(row["crypto"], self.crypto)
        self.assertEqual(len(row["storage_key"]), 32)
        self.assertNotIn(self.tenant, row["storage_key"])
        with self.node.transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) AS n FROM secpal_objects.business_references").fetchone()["n"], 1)
            self.assertEqual(db.execute("SELECT count(*) AS n FROM secpal_objects.replication_intents").fetchone()["n"], 1)

    def test_wrong_hash_size_missing_and_etag_are_not_integrity_authority(self):
        for failure in ["get", "stat", "missing"]:
            with self.subTest(failure=failure):
                oid = self.reserve()
                if failure == "get":
                    change = patch.object(self.backend, "read", return_value=b"x" * len(self.bytes))
                elif failure == "stat":
                    change = patch.object(self.backend, "stat", return_value=len(self.bytes) + 1)
                else:
                    change = patch.object(self.backend, "read", side_effect=FileNotFoundError())
                with change, self.assertRaises(objects.ObjectError):
                    self.publish(oid)
                self.assertEqual(self.node.inspect(oid)["state"], "PENDING")
        # Even a provider-provided canonical-looking ETag is never consulted.
        self.backend.etag = hashlib.sha256(self.bytes).hexdigest()
        with patch.object(self.backend, "read", return_value=b"x" * len(self.bytes)):
            with self.assertRaises(objects.ObjectError):
                self.publish()


    def test_db_failure_after_put_leaves_only_pending_orphan(self):
        for failure in ["sql-error", "commit", "rollback"]:
            with self.subTest(failure=failure):
                oid = self.reserve()
                def failing_business_write(db, row):
                    if failure == "sql-error":
                        db.execute("SELECT 1/0")
                    elif failure == "commit":
                        db.commit()
                        raise RuntimeError("synthetic callback failure after commit")
                    else:
                        db.rollback()
                with self.assertRaises(objects.ObjectError):
                    self.publish(oid, attach=failing_business_write)
                row = self.node.inspect(oid)
                self.assertEqual(row["state"], "PENDING")
                self.assertEqual(self.backend.read(row["storage_key"], len(self.bytes)), self.bytes)
                with self.node.transaction() as db:
                    for table in ["business_references", "replication_intents"]:
                        self.assertEqual(db.execute(
                            "SELECT count(*) AS n FROM secpal_objects." + table).fetchone()["n"], 0)
                with self.assertRaises(objects.ObjectError):
                    self.node.read(oid)

    def test_collision_and_finalized_overwrite_fail_closed(self):
        oid = self.reserve()
        key = self.node.inspect(oid)["storage_key"]
        self.backend.create(key, b"already-owned")
        with self.assertRaises(objects.ObjectError):
            self.publish(oid)
        self.assertEqual(self.backend.read(key, 100), b"already-owned")
        ready = self.publish()
        with self.assertRaises(objects.ObjectError):
            self.publish(ready["object_id"])
        with self.assertRaises(FileExistsError):
            self.backend.create(ready["storage_key"], b"replace")
        self.assertEqual(self.node.read(ready["object_id"]), self.bytes)

    def test_two_nodes_concurrent_publication_has_one_business_commit(self):
        oid = self.reserve()
        other = self.catalog(purpose="worker")
        def run(node):
            try:
                return node.publish(oid, self.bytes, reference_id=str(uuid.uuid4()))["state"]
            except objects.ObjectError:
                return "rejected"
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            result = list(pool.map(run, [self.node, other]))
        self.assertEqual(sorted(result), ["READY", "rejected"])
        self.assertEqual(other.read(oid), self.bytes)

    def test_tenant_deployment_and_service_scope_fail_before_storage(self):
        row = self.publish()
        for options in [
            {"tenant_id": str(uuid.uuid4())}, {"deployment_id": str(uuid.uuid4())},
            {"purpose": "frontend"}, {"purpose": "haproxy"}, {"authorize": None},
            {"admit_ciphertext": None}, {"admit_backend": None},
        ]:
            with self.subTest(options=list(options)):
                with self.assertRaises(objects.ObjectError):
                    self.catalog(**options).read(row["object_id"])
        denied = self.catalog(authorize=lambda *args: False)
        with self.assertRaises(objects.ObjectError):
            denied.reserve(self.bytes, self.crypto)

    def test_managed_cannot_admit_local_authoritative_directory(self):
        with self.assertRaises(objects.ObjectError):
            self.catalog(mode="managed")
        class SyntheticOffHost:
            locality = "off-host-object"
            create = self.backend.create
            read = self.backend.read
            stat = self.backend.stat
        # This only exercises contract composition; it is NOT Managed qualification.
        managed = self.catalog(backend=SyntheticOffHost(), mode="managed")
        row = managed.publish(managed.reserve(self.bytes, self.crypto), self.bytes,
                              reference_id=str(uuid.uuid4()))
        self.assertEqual(managed.read(row["object_id"]), self.bytes)

    def test_plaintext_missing_crypto_and_modified_reserved_metadata_are_rejected(self):
        for value, metadata in [(b"plaintext", self.crypto), (self.bytes, {}),
                                (self.bytes, self.crypto | {"private_key": "forbidden"})]:
            with self.assertRaises(objects.ObjectError):
                self.node.reserve(value, metadata)
        oid = self.reserve()
        with self.assertRaises(objects.ObjectError):
            self.node.publish(oid, b"other ciphertext", reference_id=str(uuid.uuid4()))
        with self.assertRaises(objects.ObjectError):
            with self.node.transaction() as db:
                db.execute("UPDATE secpal_objects.objects SET storage_sha256=%s WHERE object_id=%s",
                           ("a" * 64, oid))

    def test_business_tombstone_retention_and_replication_block_physical_gc(self):
        row = self.publish()
        oid = row["object_id"]
        owner = str(uuid.uuid4())
        self.retention.hold(oid, owner)
        self.node.tombstone(oid)
        with self.assertRaises(objects.ObjectError):
            self.node.read(oid)
        with self.assertRaises(objects.ObjectError):
            self.gc.collect(oid, older_than=2**62)
        self.assertEqual(self.backend.read(row["storage_key"], len(self.bytes)), self.bytes)
        self.retention.release(oid, owner)
        with self.assertRaises(objects.ObjectError):
            self.gc.collect(oid, older_than=2**62)
        self.retention.replication_accepted(oid, "test-replica")
        self.assertEqual(self.gc.collect(oid, older_than=2**62)["state"], "DELETED")
        with self.assertRaises(FileNotFoundError):
            self.backend.stat(row["storage_key"])

    def test_orphan_gc_requires_age_external_retention_and_no_live_reference(self):
        row = self.publish()
        with self.assertRaises(objects.ObjectError):
            self.gc.collect(row["object_id"], older_than=2**62)
        oid = self.reserve()
        with self.assertRaises(objects.ObjectError):
            self.gc.collect(oid, older_than=0)
        blocked = objects.ObjectGarbageCollector(
            self.node, destroy=self.backend.destroy,
            authorize=lambda row: (_ for _ in ()).throw(PermissionError()))
        with self.assertRaises(objects.ObjectError):
            blocked.collect(oid, older_than=2**62)
        self.assertEqual(self.gc.collect(oid, older_than=2**62)["state"], "DELETED")

    def test_ciphertext_export_for_continuity_preserves_exact_hash_and_metadata(self):
        row = self.publish()
        export = self.catalog(purpose="continuity").export(row["object_id"])
        self.assertEqual(export["bytes"], self.bytes)
        self.assertEqual(hashlib.sha256(export["bytes"]).hexdigest(), row["storage_sha256"])
        self.assertEqual(export["metadata"]["crypto"], self.crypto)
        with self.assertRaises(objects.ObjectError):
            self.node.export(row["object_id"])
        with self.assertRaises(objects.ObjectError):
            self.catalog(purpose="continuity").reserve(self.bytes, self.crypto)

    def test_symlink_path_traversal_and_unsafe_directory_fail_closed(self):
        for key in ["../elsewhere", "/tmp/x", "a/b", "x" * 32, "a" * 31]:
            with self.assertRaises(objects.ObjectError):
                self.backend.create(key, self.bytes)
        outside = self.root / "other"
        outside.write_bytes(b"unrelated")
        key = "a" * 32
        (self.root / "objects" / key).symlink_to(outside)
        for operation in [lambda: self.backend.read(key, 100),
                          lambda: self.backend.destroy(key), lambda: self.backend.stat(key)]:
            with self.assertRaises(objects.ObjectError):
                operation()
        self.assertEqual(outside.read_bytes(), b"unrelated")
        with self.assertRaises(objects.ObjectError):
            objects.SelfHostedDirectory(self.root / "objects/..")

    def test_fsync_failure_prevents_ready_and_preserves_existing_objects(self):
        existing = self.publish()
        oid = self.reserve()
        with patch.object(objects.os, "fsync", side_effect=OSError("synthetic sync failure")):
            with self.assertRaises(objects.ObjectError):
                self.publish(oid)
        self.assertEqual(self.node.inspect(oid)["state"], "PENDING")
        self.assertEqual(self.node.read(existing["object_id"]), self.bytes)

    def test_native_runtime_database_role_cannot_gain_retention_or_destruction_authority(self):
        with psycopg.connect(**self.database) as db:
            if not db.execute("SELECT 1 FROM pg_roles WHERE rolname='secpal_object_runtime_test'").fetchone():
                db.execute("CREATE ROLE secpal_object_runtime_test NOLOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS")
            db.execute("GRANT USAGE ON SCHEMA secpal_objects TO secpal_object_runtime_test")
            db.execute("GRANT SELECT,INSERT ON secpal_objects.objects,"
                       "secpal_objects.business_references,secpal_objects.replication_intents"
                       " TO secpal_object_runtime_test")
            db.execute("GRANT UPDATE(state) ON secpal_objects.objects TO secpal_object_runtime_test")
            db.execute("GRANT UPDATE(tombstoned) ON secpal_objects.business_references"
                       " TO secpal_object_runtime_test")
        runtime = self.catalog(database=self.database | {"options": "-c role=secpal_object_runtime_test"})
        row = runtime.publish(runtime.reserve(self.bytes, self.crypto), self.bytes,
                              reference_id=str(uuid.uuid4()))
        self.assertEqual(runtime.read(row["object_id"]), self.bytes)
        for query in [
            "DELETE FROM secpal_objects.objects",
            "UPDATE secpal_objects.objects SET storage_sha256=repeat('a',64)",
            "INSERT INTO secpal_objects.retention_holds VALUES ('unowned','unowned')",
            "UPDATE secpal_objects.replication_intents SET accepted=true",
            "DROP TABLE secpal_objects.objects",
        ]:
            with self.subTest(query=query.split()[0]):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with psycopg.connect(**runtime.database) as db:
                        db.execute(query)

    def test_lost_final_commit_ack_requires_readback_not_put_retry(self):
        oid = self.reserve()
        commit = psycopg.Connection.commit
        def committed_then_lost(db):
            commit(db)
            raise psycopg.OperationalError("synthetic acknowledgement loss")
        with patch.object(psycopg.Connection, "commit", committed_then_lost):
            with self.assertRaises(objects.ObjectError):
                self.publish(oid)
        self.assertEqual(self.node.inspect(oid)["state"], "READY")
        self.assertEqual(self.node.read(oid), self.bytes)
        with self.assertRaises(objects.ObjectError):
            self.publish(oid)

    def test_external_destruction_failure_keeps_tombstone_and_unrelated_bytes(self):
        row = self.publish()
        self.node.tombstone(row["object_id"])
        self.retention.replication_accepted(row["object_id"], "test-replica")
        gc = objects.ObjectGarbageCollector(
            self.node, destroy=lambda key: None, authorize=lambda row: None)
        with self.assertRaises(objects.ObjectError):
            gc.collect(row["object_id"], older_than=2**62)
        self.assertEqual(self.node.inspect(row["object_id"])["state"], "TOMBSTONED")
        self.assertEqual(self.backend.read(row["storage_key"], len(self.bytes)), self.bytes)


if __name__ == "__main__":
    with fixture.postgres_fixture():
        unittest.main()
