#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Private Object Storage contract (#99), not Secret Authority or an installer.

Adapters and admission callbacks are trusted construction inputs, never request
fields. Managed adapters require independent semantic qualification. This module
ships no Managed provider adapter and cannot turn local files into Managed storage.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import uuid

import host_enrollment as enrollment


class ObjectError(ValueError):
    """Bounded non-secret failure; never include provider payloads or credentials."""


def _admit(callback, *arguments):
    if not callable(callback):
        raise ObjectError("admission-required")
    try:
        if callback(*arguments) is not None:
            raise ObjectError("admission-result")
    except ObjectError:
        raise
    except Exception:
        raise ObjectError("admission-rejected") from None


def _uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise ObjectError("identity") from None
    return value


def _name(value):
    if type(value) is not str or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}", value):
        raise ObjectError("name")
    return value


def _key(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise ObjectError("opaque-key")
    return value


def _crypto(value):
    fields = {"scheme", "generation", "key_reference", "wrapped_dek"}
    if type(value) is not dict or value.keys() != fields:
        raise ObjectError("crypto-metadata")
    _name(value["scheme"])
    _uuid(value["key_reference"])
    if (type(value["generation"]) is not int or not 1 <= value["generation"] < 2**63
            or type(value["wrapped_dek"]) is not str
            or not 1 <= len(value["wrapped_dek"].encode()) <= 8192):
        raise ObjectError("crypto-metadata")
    return deepcopy(value)


@contextmanager
def _transaction(database):
    try:
        # Reuse accepted native PG18 transport, identity, durability, bounded
        # SERIALIZABLE transaction and commit/close handling. No second transport.
        with enrollment.authority_transaction(database) as db:
            # Native transaction ownership rejects commit()/rollback() from
            # trusted application attachment callbacks before either can act.
            with db.transaction():
                yield db
    except ObjectError:
        raise
    except enrollment.EnrollmentError:
        raise ObjectError("catalog-transaction") from None


def initialize_catalog(database):
    """Migration-authority operation only; never called by ordinary runtime."""
    with _transaction(database) as db:
        db.execute("CREATE SCHEMA secpal_objects")
        db.execute("""
            CREATE TABLE secpal_objects.objects (
                object_id text PRIMARY KEY,
                deployment_id text NOT NULL,
                tenant_id text NOT NULL,
                backend_id text NOT NULL,
                storage_key text NOT NULL UNIQUE CHECK (storage_key ~ '^[0-9a-f]{32}$'),
                byte_size bigint NOT NULL CHECK (byte_size > 0),
                storage_sha256 text NOT NULL CHECK (storage_sha256 ~ '^[0-9a-f]{64}$'),
                crypto jsonb NOT NULL,
                state text NOT NULL CHECK (state IN ('PENDING','READY','TOMBSTONED','DELETED')),
                created_at bigint NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE secpal_objects.business_references (
                reference_id text PRIMARY KEY,
                object_id text NOT NULL REFERENCES secpal_objects.objects,
                tombstoned boolean NOT NULL DEFAULT false
            )
        """)
        db.execute("""
            CREATE TABLE secpal_objects.replication_intents (
                object_id text NOT NULL REFERENCES secpal_objects.objects,
                target text NOT NULL,
                accepted boolean NOT NULL DEFAULT false,
                PRIMARY KEY (object_id,target)
            )
        """)
        db.execute("""
            CREATE TABLE secpal_objects.retention_holds (
                object_id text NOT NULL REFERENCES secpal_objects.objects,
                owner text NOT NULL,
                PRIMARY KEY (object_id,owner)
            )
        """)
        db.execute("""
            CREATE FUNCTION secpal_objects.immutable_object() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog AS $$
            BEGIN
                IF (to_jsonb(NEW) - 'state') IS DISTINCT FROM (to_jsonb(OLD) - 'state')
                THEN RAISE EXCEPTION 'immutable-object'; END IF;
                IF NOT ((OLD.state='PENDING' AND NEW.state IN ('READY','DELETED'))
                    OR (OLD.state='READY' AND NEW.state='TOMBSTONED')
                    OR (OLD.state='TOMBSTONED' AND NEW.state='DELETED'))
                THEN RAISE EXCEPTION 'object-lifecycle'; END IF;
                RETURN NEW;
            END
            $$
        """)
        db.execute("""
            CREATE TRIGGER immutable_object BEFORE UPDATE ON secpal_objects.objects
            FOR EACH ROW EXECUTE FUNCTION secpal_objects.immutable_object()
        """)
        # Runtime receives explicit installation-owned column grants; no PUBLIC
        # or implicit runtime/GC/retention authority is installed here.
        db.execute("REVOKE ALL ON SCHEMA secpal_objects FROM PUBLIC")
        db.execute("REVOKE ALL ON ALL TABLES IN SCHEMA secpal_objects FROM PUBLIC")
        db.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA secpal_objects FROM PUBLIC")


class SelfHostedDirectory:
    """Real durable filesystem adapter for explicit Self-Hosted use ONLY.

    No Managed fallback, daemon, path-valued public object API or auto-created
    authority root. Independent recovery admission is required by construction.
    The private root and this adapter belong to storage authority, not frontend.
    """
    locality = "self-hosted-local"

    def __init__(self, directory):
        self.root = Path(directory)
        try:
            enrollment._directory(self.root)
        except enrollment.EnrollmentError:
            raise ObjectError("storage-directory") from None

    def _directory(self):
        try:
            enrollment._directory(self.root)
        except enrollment.EnrollmentError:
            raise ObjectError("storage-directory") from None

    def create(self, key, data):
        _key(key)
        self._directory()
        if type(data) is not bytes or not data:
            raise ObjectError("stored-bytes")
        descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=self.root)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), 0o400)
                os.fsync(stream.fileno())
            # Atomic create-only publication. A collision never overwrites.
            os.link(temporary, self.root / key, follow_symlinks=False)
        finally:
            os.unlink(temporary)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _open(self, key):
        _key(key)
        self._directory()
        try:
            descriptor = os.open(self.root / key, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise
        except OSError:
            raise ObjectError("storage-file") from None
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400):
            os.close(descriptor)
            raise ObjectError("storage-file")
        return descriptor, info

    def read(self, key, limit):
        if type(limit) is not int or limit < 1:
            raise ObjectError("read-bound")
        descriptor, info = self._open(key)
        with os.fdopen(descriptor, "rb") as stream:
            if info.st_size > limit:
                raise ObjectError("read-bound")
            value = stream.read(limit + 1)
        if len(value) > limit:
            raise ObjectError("read-bound")
        return value

    def stat(self, key):
        descriptor, info = self._open(key)
        os.close(descriptor)
        return info.st_size

    def destroy(self, key):
        # Separate GC adapter: never exposed by the runtime catalog API.
        try:
            descriptor, _ = self._open(key)
        except FileNotFoundError:
            return
        os.close(descriptor)
        os.unlink(self.root / key)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class ObjectCatalog:
    """Trusted API/Worker composition over scoped credentials and a qualified port.

    Backend port: create(key, ciphertext) is durable/exclusive on return;
    stat(key) -> exact byte count; read(key, maximum) -> exact stored bytes.
    Callers cannot select a path, provider, mode, credentials or tenant policy.
    """
    def __init__(self, *, database, deployment_id, tenant_id, purpose, backend,
                 backend_id, mode, authorize, admit_backend, admit_ciphertext,
                 replication_targets):
        self.database = deepcopy(database)
        self.deployment_id = _uuid(deployment_id)
        self.tenant_id = _name(tenant_id)
        if purpose not in {"api", "worker", "continuity"}:
            raise ObjectError("service-authority")
        if mode not in {"managed", "self-hosted"}:
            raise ObjectError("storage-mode")
        if mode == "managed" and getattr(backend, "locality", None) != "off-host-object":
            raise ObjectError("managed-off-host-required")
        if not all(callable(getattr(backend, name, None)) for name in ("create", "read", "stat")):
            raise ObjectError("adapter-methods")
        if not callable(authorize) or not callable(admit_ciphertext):
            raise ObjectError("admission-required")
        _admit(admit_backend, backend, mode)
        if (type(replication_targets) is not tuple
                or len(set(replication_targets)) != len(replication_targets)):
            raise ObjectError("replication-policy")
        self.replication_targets = tuple(_name(target) for target in replication_targets)
        self.backend = backend
        self.backend_id = _name(backend_id)
        self.purpose = purpose
        self.authorize = authorize
        self.admit_ciphertext = admit_ciphertext

    def transaction(self):
        return _transaction(self.database)

    def _authorize(self, action, row):
        if (row["deployment_id"] != self.deployment_id or row["tenant_id"] != self.tenant_id
                or row["backend_id"] != self.backend_id):
            raise ObjectError("object-scope")
        if (self.purpose == "continuity") != (action == "export"):
            raise ObjectError("service-authority")
        _admit(self.authorize, action, deepcopy(row))

    def _row(self, db, object_id):
        row = db.execute("SELECT * FROM secpal_objects.objects WHERE object_id=%s FOR UPDATE",
                         (_uuid(object_id),)).fetchone()
        if row is None:
            raise ObjectError("object-missing")
        if (row["deployment_id"] != self.deployment_id or row["tenant_id"] != self.tenant_id
                or row["backend_id"] != self.backend_id):
            raise ObjectError("object-scope")
        return row

    def reserve(self, ciphertext, crypto):
        if type(ciphertext) is not bytes or not ciphertext:
            raise ObjectError("encrypted-bytes-required")
        crypto = _crypto(crypto)
        row = dict(object_id=str(uuid.uuid4()), deployment_id=self.deployment_id,
                   tenant_id=self.tenant_id, backend_id=self.backend_id,
                   storage_key=uuid.uuid4().hex, byte_size=len(ciphertext),
                   storage_sha256=hashlib.sha256(ciphertext).hexdigest(),
                   crypto=crypto, state="PENDING", created_at=int(time.time()))
        self._authorize("reserve", row)
        # This admission must come from the accepted encryption/credential
        # boundary. It cannot be a caller-supplied "already encrypted" flag.
        _admit(self.admit_ciphertext, ciphertext, deepcopy(crypto), self.tenant_id)
        with self.transaction() as db:
            db.execute("""
                INSERT INTO secpal_objects.objects
                (object_id,deployment_id,tenant_id,backend_id,storage_key,byte_size,
                 storage_sha256,crypto,state,created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
            """, tuple(json.dumps(row[key]) if key == "crypto" else row[key] for key in row))
        return row["object_id"]

    def inspect(self, object_id):
        with self.transaction() as db:
            row = self._row(db, object_id)
            self._authorize("inspect", row)
            return row

    def _verified_bytes(self, row):
        try:
            size = self.backend.stat(row["storage_key"])
            if type(size) is not int or size != row["byte_size"]:
                raise ObjectError("object-size")
            value = self.backend.read(row["storage_key"], row["byte_size"])
            if (type(value) is not bytes or len(value) != row["byte_size"]
                    or hashlib.sha256(value).hexdigest() != row["storage_sha256"]):
                raise ObjectError("object-integrity")
            return value
        except ObjectError:
            raise
        except Exception:
            raise ObjectError("object-observation") from None

    def publish(self, object_id, ciphertext, *, reference_id, attach=None):
        _uuid(reference_id)
        if attach is not None and not callable(attach):
            raise ObjectError("business-reference")
        with self.transaction() as db:
            row = self._row(db, object_id)
            self._authorize("publish", row)
            if row["state"] != "PENDING":
                raise ObjectError("object-not-pending")
            if (type(ciphertext) is not bytes or len(ciphertext) != row["byte_size"]
                    or hashlib.sha256(ciphertext).hexdigest() != row["storage_sha256"]):
                raise ObjectError("reserved-ciphertext")
            _admit(self.admit_ciphertext, ciphertext, deepcopy(row["crypto"]), self.tenant_id)
            try:
                self.backend.create(row["storage_key"], ciphertext)
            except Exception:
                # Includes collisions and lost PUT acknowledgements. Never
                # overwrite, retry an ambiguous PUT or infer durability from GET.
                raise ObjectError("object-create") from None
            self._verified_bytes(row)
            db.execute("UPDATE secpal_objects.objects SET state='READY' WHERE object_id=%s",
                       (object_id,))
            db.execute("INSERT INTO secpal_objects.business_references VALUES (%s,%s,false)",
                       (reference_id, object_id))
            for target in self.replication_targets:
                db.execute("INSERT INTO secpal_objects.replication_intents VALUES (%s,%s,false)",
                           (object_id, target))
            if attach is not None:
                _admit(attach, db, deepcopy(row | {"state": "READY"}))
        # Successful commit ACK is required. Uncertain commit returns an error;
        # independent inspect/read-back, never blind PUT/replay, reconciles it.
        return row | {"state": "READY"}

    def read(self, object_id):
        with self.transaction() as db:
            row = self._row(db, object_id)
            self._authorize("read", row)
            if row["state"] != "READY":
                raise ObjectError("object-not-ready")
            return self._verified_bytes(row)

    def export(self, object_id):
        with self.transaction() as db:
            row = self._row(db, object_id)
            self._authorize("export", row)
            if row["state"] not in {"READY", "TOMBSTONED"}:
                raise ObjectError("object-not-exportable")
            return {"metadata": row, "bytes": self._verified_bytes(row)}

    def tombstone(self, object_id):
        with self.transaction() as db:
            row = self._row(db, object_id)
            self._authorize("tombstone", row)
            if row["state"] != "READY":
                raise ObjectError("object-not-ready")
            db.execute("UPDATE secpal_objects.business_references SET tombstoned=true"
                       " WHERE object_id=%s", (object_id,))
            db.execute("UPDATE secpal_objects.objects SET state='TOMBSTONED' WHERE object_id=%s",
                       (object_id,))


class ObjectRetention:
    """Independent #128/#109 retention/completion authority; no runtime deletion port."""
    def __init__(self, catalog, *, authorize):
        if not callable(authorize):
            raise ObjectError("retention-authority")
        self.catalog, self.authorize = catalog, authorize

    def _change(self, object_id, owner, action):
        _uuid(owner)
        with self.catalog.transaction() as db:
            row = self.catalog._row(db, object_id)
            _admit(self.authorize, action, deepcopy(row), owner)
            if row["state"] == "DELETED":
                raise ObjectError("object-deleted")
            if action == "hold":
                db.execute("INSERT INTO secpal_objects.retention_holds VALUES (%s,%s)"
                           " ON CONFLICT DO NOTHING", (object_id, owner))
            else:
                db.execute("DELETE FROM secpal_objects.retention_holds"
                           " WHERE object_id=%s AND owner=%s", (object_id, owner))

    def hold(self, object_id, owner):
        self._change(object_id, owner, "hold")

    def release(self, object_id, owner):
        self._change(object_id, owner, "release")

    def replication_accepted(self, object_id, target):
        _name(target)
        with self.catalog.transaction() as db:
            row = self.catalog._row(db, object_id)
            _admit(self.authorize, "replication-accepted", deepcopy(row), target)
            result = db.execute("UPDATE secpal_objects.replication_intents SET accepted=true"
                                " WHERE object_id=%s AND target=%s RETURNING object_id",
                                (object_id, target)).fetchone()
            if result is None:
                raise ObjectError("replication-intent-missing")


class ObjectGarbageCollector:
    """Exact-key physical destruction, separate from business deletion.

    Authorize must independently admit current RecoverySet/backup horizons and
    orphan grace. No default successful retention decision or runtime GC access.
    """
    def __init__(self, catalog, *, destroy, authorize):
        if not callable(destroy) or not callable(authorize):
            raise ObjectError("destruction-authority")
        self.catalog, self.destroy, self.authorize = catalog, destroy, authorize

    def collect(self, object_id, *, older_than):
        if type(older_than) is not int or older_than < 0:
            raise ObjectError("gc-age")
        with self.catalog.transaction() as db:
            row = self.catalog._row(db, object_id)
            if row["state"] not in {"PENDING", "TOMBSTONED"} or row["created_at"] >= older_than:
                raise ObjectError("gc-lifecycle")
            for query in [
                "SELECT 1 FROM secpal_objects.business_references WHERE object_id=%s AND NOT tombstoned",
                "SELECT 1 FROM secpal_objects.retention_holds WHERE object_id=%s",
                "SELECT 1 FROM secpal_objects.replication_intents WHERE object_id=%s AND NOT accepted",
            ]:
                if db.execute(query, (object_id,)).fetchone() is not None:
                    raise ObjectError("gc-retention")
            _admit(self.authorize, deepcopy(row))
            try:
                self.destroy(row["storage_key"])
                try:
                    self.catalog.backend.stat(row["storage_key"])
                except FileNotFoundError:
                    pass
                else:
                    raise ObjectError("gc-not-absent")
            except ObjectError:
                raise
            except Exception:
                raise ObjectError("gc-destruction") from None
            db.execute("UPDATE secpal_objects.objects SET state='DELETED' WHERE object_id=%s",
                       (object_id,))
        return row | {"state": "DELETED"}
