#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Provider-neutral Secret Authority and purpose-bound Activation.

Trusted control owns policy, custody, native credential adapters and installation.
This module is not a network service, installer, OpenBao replacement or fleet API.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import tempfile
from typing import Protocol
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap, InvalidUnwrap

# The accepted public consumer API, not a second enrollment verifier.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_enrollment as enrollment

MAX_STATE = 4 * 1024 * 1024
MAX_VALUE = 16384
MAX_SESSION_SECONDS = 300
_POSTGRES = json.loads((Path(__file__).resolve().parents[1] / "config/production/postgresql-contract.json").read_text())
_STATE_CONTRACT = json.loads((Path(__file__).resolve().parents[1] / "config/production/state-contract.json").read_text())
CLASSES = frozenset({
    "root-kek", "tenant-kek", "backup-key", "app-key", "postgres-ca",
    "postgres-runtime", "postgres-migration", "postgres-transport",
    "object-runtime", "barman-runtime", "monitoring-runtime", "origin-auth",
})
APPLICATION_CLASSES = frozenset({"app-key", "tenant-kek", "postgres-runtime", "object-runtime"})
PURPOSE_CLASSES = {
    "frontend": frozenset(),
    "api": APPLICATION_CLASSES,
    "worker-general": APPLICATION_CLASSES,
    "worker-hash-chain": APPLICATION_CLASSES,
    "scheduler": APPLICATION_CLASSES,
    "migrate": frozenset({"app-key", "tenant-kek", "postgres-migration"}),
    "haproxy-protected": frozenset({"origin-auth"}),
    "host-postgresql": frozenset({"postgres-transport"}),
    "barman": frozenset({"barman-runtime"}),
    "backup-writer": frozenset({"backup-key"}),
    "backup-recovery": frozenset({"backup-key"}),
    "monitoring": frozenset({"monitoring-runtime"}),
}


class SecretError(ValueError):
    """Bounded semantic failure; never include provider/caller/secret diagnostics."""
    def __init__(self, code):
        if type(code) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", code) is None:
            code = "secret-authority-failed"
        super().__init__(code)


def now():
    return enrollment.now()


def _encode(value):
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError, UnicodeError):
        raise SecretError("invalid-document") from None
    if len(data) > MAX_STATE:
        raise SecretError("document-size")
    return data


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise SecretError("identity-format") from None


def _ref(value):
    if type(value) is not dict or set(value) != {"authority_id", "generation"}:
        raise SecretError("generation-reference")
    _uuid(value["authority_id"])
    if type(value["generation"]) is not int or value["generation"] < 1:
        raise SecretError("generation-reference")
    return dict(value)


def _key(value):
    if type(value) is not bytes or len(value) != 32:
        raise SecretError("authority-key-required")
    return value


def _call(callback, *args):
    """Explicit trusted admission, without accepting a boolean claim."""
    if not callable(callback):
        raise SecretError("independent-authorization-required")
    try:
        result = callback(*args)
    except Exception:
        raise SecretError("independent-authorization-rejected") from None
    if result is not None:
        raise SecretError("independent-authorization-result")


def _seal(key, value, aad):
    nonce = os.urandom(12)
    return nonce + AESGCM(_key(key)).encrypt(nonce, _encode(value), aad)


def _open(key, blob, aad):
    if type(blob) is not bytes or not 28 < len(blob) <= MAX_STATE + 28:
        raise SecretError("encrypted-state-size")
    try:
        plain = AESGCM(_key(key)).decrypt(blob[:12], blob[12:], aad)
        return json.loads(plain)
    except (InvalidTag, ValueError, UnicodeError):
        raise SecretError("encrypted-state-integrity") from None


def _aad(deployment, purpose):
    _uuid(deployment)
    return ("SecPal Secret Authority v1\n" + deployment + "\n" + purpose).encode()


def _database_bundle(value):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        bundle = json.loads(value)
        reserved = {"postgres", *_POSTGRES["roles"].values()}
        if (type(bundle) is not dict or set(bundle) != {"username", "password", "ca"} or
                any(type(v) is not str for v in bundle.values()) or
                re.fullmatch(r"[a-z][a-z0-9_]{0,62}", bundle["username"]) is None or
                bundle["username"] in reserved or
                re.fullmatch(r"[A-Za-z0-9._~!#$%&*+/=?^-]{24,128}", bundle["password"]) is None):
            raise ValueError
        raw = bundle["ca"].encode("ascii")
        certificates = x509.load_pem_x509_certificates(raw)
        if (not certificates or b"".join(cert.public_bytes(serialization.Encoding.PEM)
                                        for cert in certificates) != raw or
                any(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                    for cert in certificates)):
            raise ValueError
        return bundle
    except (ValueError, TypeError, UnicodeError, x509.ExtensionNotFound):
        raise SecretError("database-credential-format") from None


def _record(state, ref):
    ref = _ref(ref)
    try:
        authority = state["authorities"][ref["authority_id"]]
        record = authority["generations"][str(ref["generation"])]
        return authority, record
    except (KeyError, TypeError):
        raise SecretError("required-generation-missing") from None


def _metadata(state, ref):
    authority, record = _record(state, ref)
    return {**_ref(ref), "class": authority["class"], **{
        key: record[key] for key in ("fingerprint", "created_at", "status", "retained_by", "host_id", "purposes", "principal", "rotation")}}


def _value(state, ref):
    authority, record = _record(state, ref)
    try:
        value = base64.b64decode(record["value"], validate=True)
        if authority["class"] == "tenant-kek":
            wrapping = record["wrapping"]
            value = aes_key_unwrap(_value(state, wrapping), value)
        if _sha(value) != record["fingerprint"]:
            raise SecretError("generation-integrity")
        return value
    except (InvalidUnwrap, ValueError, KeyError, TypeError):
        raise SecretError("generation-integrity") from None


def _manifest(state):
    return {
        f"{aid}:{generation}": {"generation": int(generation), "fingerprint": row["fingerprint"]}
        for aid, authority in state["authorities"].items()
        for generation, row in authority["generations"].items()
    }


def _material_changed(state):
    state["material_revision"] = str(uuid.uuid4())
    state["custody"] = None


def _admit_custody(state, *, rotation=None):
    if any(row["status"] == "revocation-pending" for authority in state["authorities"].values()
           for row in authority["generations"].values()):
        raise SecretError("old-credential-revocation-incomplete")
    if any(row["status"] == "rotation-pending" and
           rotation != {"authority_id": aid, "generation": int(generation)}
           for aid, authority in state["authorities"].items()
           for generation, row in authority["generations"].items()):
        raise SecretError("rotation-outcome-unverified")
    if (type(state["custody"]) is not dict or
            state["custody"].get("material_revision") != state["material_revision"]):
        raise SecretError("independent-custody-unproven")


class SecretAuthorityContract(Protocol):
    def challenge(self, identity: dict, purpose: str, refs: list, *, ttl: int = 60) -> dict: ...
    def activate(self, session_id: str, identity: dict, proof: str, *, delivery) -> dict: ...


class RecoveryCustody(Protocol):
    """Separate authority retains encrypted state AND independently recoverable key."""
    def retain(self, encrypted: bytes, manifest: dict) -> None: ...
    def recover(self) -> tuple[bytes, bytes, dict]: ...


class PostgresStore:
    """Small self-hosted reference adapter: PG18 ciphertext, external key and pin.

    Unseal authority and the freshness pin must not share the database restore
    domain. Missing/ambiguous state is never automatically initialized/repaired.
    """
    def __init__(self, directory, database, deployment_id, *, unseal):
        self.directory = Path(directory)
        self.database = dict(database)
        _uuid(deployment_id)
        self.deployment_id = deployment_id
        self.unseal = unseal
        self._aad = _aad(deployment_id, "live-state")
        try:
            enrollment._directory(self.directory)
            enrollment._directory(self.directory / "rotation")
        except enrollment.EnrollmentError:
            raise SecretError("authority-directory") from None

    @classmethod
    def initialize(cls, directory, database, deployment_id, *, unseal, recovered=None):
        directory = Path(directory)
        try:
            enrollment._ancestry(directory.parent)
            directory.mkdir(mode=0o700)
        except (OSError, enrollment.EnrollmentError):
            raise SecretError("authority-already-exists") from None
        (directory / "rotation").mkdir(mode=0o700)
        store = cls(directory, database, deployment_id, unseal=unseal)
        state = {
            "version": 1, "deployment_id": deployment_id, "authorities": {},
            "sessions": {}, "material_revision": str(uuid.uuid4()), "custody": None,
        } if recovered is None else deepcopy(recovered)
        if state["deployment_id"] != deployment_id or state["sessions"]:
            raise SecretError("recovery-state-binding")
        try:
            key = store._unseal()
            blob = _seal(key, state, store._aad)
            with enrollment._lock(directory), enrollment.authority_transaction(database) as db:
                db.execute("CREATE SCHEMA secpal_secrets")
                db.execute(f"""CREATE TABLE secpal_secrets.state(
                    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
                    ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)
                        BETWEEN 29 AND {MAX_STATE + 28}))""")
                db.execute("REVOKE ALL ON SCHEMA secpal_secrets FROM PUBLIC")
                db.execute("REVOKE ALL ON secpal_secrets.state FROM PUBLIC")
                db.execute("INSERT INTO secpal_secrets.state VALUES(true,%s)", (blob,))
                enrollment._publish(directory / "database-sha256.json", _sha(blob))
        except enrollment.EnrollmentError:
            raise SecretError("authority-state") from None
        return store

    def _unseal(self):
        try:
            return _key(self.unseal())
        except Exception:
            raise SecretError("authority-unavailable") from None

    @contextmanager
    def transaction(self, *, write=False):
        try:
            with enrollment._lock(self.directory), enrollment.authority_transaction(self.database) as db:
                row = db.execute(
                    f"SELECT CASE WHEN octet_length(ciphertext) BETWEEN 29 AND {MAX_STATE + 28} "
                    "THEN ciphertext END AS ciphertext FROM secpal_secrets.state "
                    "WHERE singleton=true").fetchone()
                if row is None:
                    raise SecretError("authority-state-missing")
                if row["ciphertext"] is None:
                    raise SecretError("authority-state-size")
                blob = bytes(row["ciphertext"])
                pin = enrollment._json_file(self.directory / "database-sha256.json")
                if pin != _sha(blob):
                    raise SecretError("authority-state-integrity")
                key = self._unseal()
                state = _open(key, blob, self._aad)
                if (type(state) is not dict or set(state) != {
                    "version", "deployment_id", "authorities", "sessions",
                    "material_revision", "custody"
                } or state["version"] != 1 or state["deployment_id"] != self.deployment_id):
                    raise SecretError("authority-state-binding")
                yield state
                if write:
                    blob = _seal(key, state, self._aad)
                    db.execute("UPDATE secpal_secrets.state SET ciphertext=%s WHERE singleton=true", (blob,))
                    # A failed/unknown commit poisons or consumes the operation;
                    # secret release occurs only after an acknowledged commit.
                    enrollment._publish(self.directory / "database-sha256.json", _sha(blob))
        except enrollment.EnrollmentError:
            raise SecretError("authority-state") from None


def recover_authority(encrypted, recovery_key, deployment_id, *, required):
    """Offline inspection only; caller must authorize fresh authority restoration."""
    state = _open(recovery_key, encrypted, _aad(deployment_id, "offline-recovery"))
    if (type(state) is not dict or state.get("deployment_id") != deployment_id or
            state.get("version") != 1 or type(required) is not dict or not required):
        raise SecretError("recovery-state-binding")
    actual = _manifest(state)
    if any(actual.get(k) != v for k, v in required.items()):
        raise SecretError("historical-recovery-generation-missing")
    for aid, authority in state["authorities"].items():
        for generation in authority["generations"]:
            _value(state, {"authority_id": aid, "generation": int(generation)})
        if authority["class"] not in CLASSES:
            raise SecretError("recovery-secret-class")
    # A snapshot does not resurrect challenges, sessions or runtime credentials.
    state["sessions"] = {}
    for authority in state["authorities"].values():
        if authority["class"] not in {
            "root-kek", "tenant-kek", "backup-key", "app-key", "postgres-ca"
        }:
            authority["current"] = None
            for generation in authority["generations"].values():
                generation["status"] = "revoked"
    _material_changed(state)
    return state


def restore_authority(directory, database, deployment_id, encrypted, recovery_key,
                      *, required, unseal, authorize):
    """Fresh authorized authority; old replay state/rotatable credentials stay revoked.

    Independent Recovery Authority supplies the authenticated required-generation
    manifest and fresh unseal authority. The lost authority must be fenced by its
    existing operational owner; this function cannot establish that external fact.
    """
    _call(authorize, deepcopy(required))
    state = recover_authority(encrypted, recovery_key, deployment_id, required=required)
    return PostgresStore.initialize(directory, database, deployment_id,
                                    unseal=unseal, recovered=state)


class SecretAdministration:
    """Separately authorized admin interface, never dispatched from host requests."""
    def __init__(self, store):
        self.store = store

    @staticmethod
    def _put(state, kind, value, *, authority_id=None, wrapping=None, host_id=None, purposes=()):
        if kind not in CLASSES or type(value) is not bytes or not 1 <= len(value) <= MAX_VALUE:
            raise SecretError("secret-value-contract")
        if kind in {"root-kek", "tenant-kek", "backup-key"} and len(value) != 32:
            raise SecretError("key-size")
        if kind == "app-key" and re.fullmatch(rb"base64:[A-Za-z0-9+/]{43}=", value) is None:
            raise SecretError("application-key-format")
        business = {"root-kek", "tenant-kek", "backup-key", "app-key", "postgres-ca"}
        if kind not in business:
            _uuid(host_id)
            if (type(purposes) not in (tuple, list) or not purposes or
                    len(set(purposes)) != len(purposes) or
                    any(p not in PURPOSE_CLASSES or kind not in PURPOSE_CLASSES[p] for p in purposes)):
                raise SecretError("runtime-purpose-binding")
        elif host_id is not None or purposes:
            raise SecretError("business-authority-scope")
        principal = None
        if kind in {"postgres-runtime", "postgres-migration"}:
            principal = _database_bundle(value)["username"]
            if any(row.get("principal") == principal
                   for authority in state["authorities"].values()
                   for row in authority["generations"].values()):
                raise SecretError("database-principal-already-owned")
        if kind in business:
            existing = [aid for aid, record in state["authorities"].items() if record["class"] == kind]
            if existing and authority_id not in existing:
                raise SecretError("existing-business-authority-required")
        aid = str(uuid.uuid4()) if authority_id is None else authority_id
        _uuid(aid)
        authorities = state["authorities"]
        if aid not in authorities:
            authorities[aid] = {"class": kind, "current": None, "generations": {}, "next_generation": 1}
        authority = authorities[aid]
        if authority["class"] != kind:
            raise SecretError("authority-class-binding")
        if any(row["fingerprint"] == _sha(value) for row in authority["generations"].values()):
            raise SecretError("duplicate-key-generation")
        generation = authority["next_generation"]
        authority["next_generation"] += 1
        row = {"value": base64.b64encode(value).decode(), "fingerprint": _sha(value),
               "created_at": now(), "status": "candidate", "retained_by": [],
               "host_id": host_id, "purposes": list(purposes), "principal": principal, "rotation": None}
        if kind == "tenant-kek":
            root, _ = _record(state, wrapping)
            if root["class"] != "root-kek":
                raise SecretError("wrapping-key-class")
            row["value"] = base64.b64encode(aes_key_wrap(_value(state, wrapping), value)).decode()
            row["wrapping"] = _ref(wrapping)
        authority["generations"][str(generation)] = row
        _material_changed(state)
        return {"authority_id": aid, "generation": generation}

    def metadata(self, ref):
        with self.store.transaction() as state:
            return deepcopy(_metadata(state, ref))

    def bootstrap(self, custody, *, recovery_key):
        with self.store.transaction(write=True) as state:
            if state["authorities"]:
                raise SecretError("initial-authorities-already-exist")
            refs = {}
            for kind in ("root-kek", "tenant-kek", "backup-key", "app-key"):
                value = os.urandom(32)
                if kind == "app-key":
                    value = b"base64:" + base64.b64encode(value)
                ref = self._put(state, kind, value,
                                wrapping=refs.get("root-kek") if kind == "tenant-kek" else None)
                authority, record = _record(state, ref)
                authority["current"] = ref["generation"]
                record["status"] = "current"
                refs[kind] = ref
            # Native PKI authority material stays solely inside the encrypted authority.
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.x509.oid import NameOID
            from datetime import datetime, timedelta, timezone
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                               "SecPal deployment " + self.store.deployment_id)])
            instant = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(instant - timedelta(minutes=1))
                    .not_valid_after(instant + timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .add_extension(x509.KeyUsage(False, False, False, False, False,
                                                  True, True, False, False), critical=True)
                    .sign(key, hashes.SHA256()))
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            material = _encode({"key": pem.decode(), "certificate": cert.public_bytes(
                serialization.Encoding.PEM).decode()})
            ref = self._put(state, "postgres-ca", material)
            authority, record = _record(state, ref)
            authority["current"] = ref["generation"]
            record["status"] = "current"
            refs["postgres-ca"] = ref
        self.checkpoint(custody, recovery_key=recovery_key)
        return refs

    def checkpoint(self, custody, *, recovery_key):
        # First-use/updated-material admission stays blocked on any custody failure.
        with self.store.transaction(write=True) as state:
            state["custody"] = None
            snapshot = deepcopy(state)
            snapshot["sessions"] = {}
            manifest = _manifest(state)
            revision = state["material_revision"]
        encrypted = _seal(recovery_key, snapshot, _aad(self.store.deployment_id, "offline-recovery"))
        try:
            _call(custody.retain, encrypted, deepcopy(manifest))
            recovered, independent_key, independently_required = custody.recover()
            if (recovered != encrypted or independently_required != manifest or
                    independent_key != recovery_key):
                raise SecretError("independent-custody-mismatch")
            recover_authority(recovered, independent_key, self.store.deployment_id, required=manifest)
        except Exception:
            raise SecretError("independent-custody-unproven") from None
        with self.store.transaction(write=True) as state:
            if state["material_revision"] != revision or _manifest(state) != manifest:
                raise SecretError("custody-concurrent-material-change")
            state["custody"] = {"material_revision": revision, "snapshot_sha256": _sha(encrypted)}
        return {"snapshot_sha256": _sha(encrypted), "generations": deepcopy(manifest)}

    def candidate(self, kind, value, *, authority_id=None, wrapping=None, host_id=None, purposes=()):
        with self.store.transaction(write=True) as state:
            return self._put(state, kind, value, authority_id=authority_id, wrapping=wrapping,
                             host_id=host_id, purposes=purposes)


    def rewrap_root(self, previous):
        """Atomic internal rewrap; no customer/application ciphertext is touched."""
        with self.store.transaction(write=True) as state:
            _admit_custody(state)
            authority, old = _record(state, previous)
            if authority["class"] != "root-kek" or authority["current"] != previous["generation"]:
                raise SecretError("root-generation-not-current")
            replacement = self._put(state, "root-kek", os.urandom(32),
                                    authority_id=previous["authority_id"])
            key = _value(state, replacement)
            for aid, tenant in state["authorities"].items():
                if tenant["class"] != "tenant-kek":
                    continue
                for generation, row in tenant["generations"].items():
                    if row["wrapping"] == previous:
                        value = _value(state, {"authority_id": aid, "generation": int(generation)})
                        row["value"] = base64.b64encode(aes_key_wrap(key, value)).decode()
                        row["wrapping"] = dict(replacement)
            _, current = _record(state, replacement)
            current["status"] = "current"
            old["status"] = "retained"
            authority["current"] = replacement["generation"]
            return replacement


    def issue_postgres_login(self, database, host_id, purpose, ca):
        """Native PG18 admin only; new logins remain disabled until accepted start.

        Stable NOLOGIN roles and their grants are #81-owned and must already
        exist. This does not initialize a database or give Activation a DBA login.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from psycopg import sql
        _uuid(host_id)
        if purpose not in {"api", "migrate"} or type(ca) is not bytes:
            raise SecretError("database-issuance-scope")
        try:
            parsed = x509.load_pem_x509_certificate(ca)
            if parsed.public_bytes(serialization.Encoding.PEM) != ca:
                raise ValueError
        except ValueError:
            raise SecretError("database-trust-format") from None
        migration = purpose == "migrate"
        kind = "postgres-migration" if migration else "postgres-runtime"
        group = _POSTGRES["roles"]["migration" if migration else "runtime"]
        username = "secpal_" + host_id.replace("-", "")[:24] + "_" + secrets.token_hex(4)
        password = secrets.token_urlsafe(32)
        purposes = ["migrate"] if migration else [
            "api", "worker-general", "worker-hash-chain", "scheduler"]
        ref = self.candidate(
            kind, _encode({"username": username, "password": password, "ca": ca.decode()}),
            host_id=host_id, purposes=purposes)
        try:
            with enrollment.authority_transaction(database) as db:
                # Fail before credential SQL if this administrative session cannot
                # suppress native statement/parameter/error logging or pgaudit.
                for statement in [
                    "SET LOCAL log_statement='none'",
                    "SET LOCAL log_duration=off",
                    "SET LOCAL log_min_duration_statement=-1",
                    "SET LOCAL log_min_duration_sample=-1",
                    "SET LOCAL log_transaction_sample_rate=0",
                    "SET LOCAL log_parameter_max_length=0",
                    "SET LOCAL log_parameter_max_length_on_error=0",
                    "SET LOCAL log_min_error_statement='panic'",
                ]:
                    db.execute(statement)
                audit = db.execute(
                    "SELECT 1 FROM pg_extension WHERE extname='pgaudit'").fetchone()
                if audit or any("pgaudit" in db.execute("SHOW " + setting).fetchone()[setting]
                                for setting in ["shared_preload_libraries", "session_preload_libraries",
                                                "local_preload_libraries"]):
                    raise SecretError("database-audit-boundary-unqualified")
                role = db.execute(
                    "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls "
                    "FROM pg_roles WHERE rolname=%s", (group,)).fetchone()
                if role is None or any(role.values()):
                    raise SecretError("stable-database-role-contract")
                # Native libpq computes SCRAM; plaintext never enters credential SQL.
                verifier = db.pgconn.encrypt_password(password.encode(), username.encode(), b"scram-sha-256")
                db.execute(sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS INHERIT PASSWORD {}"
                ).format(sql.Identifier(username), sql.Literal(verifier.decode())))
                db.execute(sql.SQL("GRANT {} TO {} WITH INHERIT TRUE").format(
                    sql.Identifier(group), sql.Identifier(username)))
                db.execute(sql.SQL("GRANT {} TO {} WITH SET {}").format(
                    sql.Identifier(group), sql.Identifier(username),
                    sql.SQL("TRUE" if migration else "FALSE")))
                member = db.execute(
                    "SELECT m.admin_option,m.inherit_option,m.set_option "
                    "FROM pg_auth_members m JOIN pg_roles r ON m.roleid=r.oid "
                    "JOIN pg_roles u ON m.member=u.oid WHERE r.rolname=%s AND u.rolname=%s",
                    (group, username)).fetchone()
                if member != {"admin_option": False, "inherit_option": True, "set_option": migration}:
                    raise SecretError("database-membership-contract")
        except enrollment.EnrollmentError:
            raise SecretError("database-issuance-incomplete") from None
        return ref

    def sign_postgres_csr(self, ca_ref, csr):
        """CSR comes from the host-local PG key owner; only the leaf cert is returned."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        from datetime import datetime, timedelta, timezone
        if type(csr) is not bytes or not 1 <= len(csr) <= MAX_VALUE:
            raise SecretError("postgres-csr-format")
        try:
            request = x509.load_pem_x509_csr(csr)
            if request.public_bytes(serialization.Encoding.PEM) != csr or not request.is_signature_valid:
                raise ValueError
            public = request.public_key()
            if not ((isinstance(public, ec.EllipticCurvePublicKey) and
                     isinstance(public.curve, ec.SECP256R1)) or
                    (isinstance(public, rsa.RSAPublicKey) and public.key_size >= 2048)):
                raise ValueError
            san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            if (list(san.value) != [x509.DNSName(_POSTGRES["transport"]["server_name"])] or
                    request.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                                    _POSTGRES["transport"]["server_name"])])):
                raise ValueError
            if any(extension.oid != x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                   for extension in request.extensions):
                raise ValueError
        except (ValueError, TypeError, x509.ExtensionNotFound):
            raise SecretError("postgres-csr-admission") from None
        with self.store.transaction() as state:
            _admit_custody(state)
            authority, row = _record(state, ca_ref)
            if authority["class"] != "postgres-ca" or row["status"] != "current":
                raise SecretError("postgres-ca-not-current")
            material = json.loads(_value(state, ca_ref))
        try:
            key = serialization.load_pem_private_key(material["key"].encode(), password=None)
            ca_pem = material["certificate"].encode()
            ca = x509.load_pem_x509_certificate(ca_pem)
            instant = datetime.now(timezone.utc)
            if not ca.not_valid_before_utc <= instant < ca.not_valid_after_utc:
                raise ValueError
            certificate = (x509.CertificateBuilder().subject_name(request.subject)
                           .issuer_name(ca.subject).public_key(public)
                           .serial_number(x509.random_serial_number())
                           .not_valid_before(instant - timedelta(minutes=1))
                           .not_valid_after(min(instant + timedelta(days=30), ca.not_valid_after_utc))
                           .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                           .add_extension(san.value, False)
                           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                           .sign(key, hashes.SHA256()))
            return certificate.public_bytes(serialization.Encoding.PEM), ca_pem
        except (ValueError, KeyError, TypeError):
            raise SecretError("postgres-certificate-issuance") from None

    def retain(self, ref, owner):
        _uuid(owner)  # Existing backup/RecoverySet owner ID, not another registry.
        with self.store.transaction(write=True) as state:
            _, record = _record(state, ref)
            if owner not in record["retained_by"]:
                record["retained_by"].append(owner)
                _material_changed(state)


    def release_retention(self, ref, owner, *, authorize):
        """The existing Backup/RecoverySet owner must authorize its own release."""
        _uuid(owner)
        with self.store.transaction(write=True) as state:
            _, record = _record(state, ref)
            if owner not in record["retained_by"]:
                raise SecretError("retention-owner-missing")
            _call(authorize, deepcopy(_metadata(state, ref)), owner)
            record["retained_by"].remove(owner)
            _material_changed(state)

    def retire(self, ref, *, authorize):
        with self.store.transaction(write=True) as state:
            authority, record = _record(state, ref)
            if (authority["current"] == ref["generation"] or record["retained_by"] or
                    record["status"] in {"revocation-pending", "rotation-pending"}):
                raise SecretError("generation-still-required")
            for other in state["authorities"].values():
                for row in other["generations"].values():
                    if row.get("wrapping") == ref:
                        raise SecretError("wrapping-generation-still-required")
            _call(authorize, deepcopy(_metadata(state, ref)))
            del authority["generations"][str(ref["generation"])]
            _material_changed(state)


    @contextmanager
    def _rotation_lock(self):
        try:
            with enrollment._lock(self.store.directory / "rotation"):
                yield
        except enrollment.EnrollmentError:
            raise SecretError("rotation-lock") from None

    def rotate(self, ref, *, validate, start, ready, accept, revoke, rollback):
        """Serialize external work and persist intent before crossing its boundary."""
        with self._rotation_lock():
            return self._rotate(ref, validate=validate, start=start, ready=ready,
                                accept=accept, revoke=revoke, rollback=rollback)

    def _rotate(self, ref, *, validate, start, ready, accept, revoke, rollback):
        ref = _ref(ref)
        with self.store.transaction(write=True) as state:
            authority, record = _record(state, ref)
            _admit_custody(state)
            if record["status"] != "candidate":
                raise SecretError("rotation-not-candidate")
            previous = ({"authority_id": ref["authority_id"], "generation": authority["current"]}
                        if authority["current"] is not None else None)
            if authority["class"] == "app-key":
                predecessors = sum(row["status"] in {"current", "retained"}
                                   for row in authority["generations"].values())
                if predecessors > _STATE_CONTRACT["secret_policy"]["max_previous_keys"]:
                    raise SecretError("application-previous-key-retention")
            operation = str(uuid.uuid4())
            record["status"] = "rotation-pending"
            record["rotation"] = {"operation_id": operation, "previous": previous, "started_at": now()}
        # An unacknowledged intent commit never reaches service-changing callbacks.
        try:
            for callback in (validate, start, ready, accept):
                _call(callback, ref, previous)
        except Exception:
            # This is only the pre-publication boundary. Rollback must restore AND
            # verify the prior state before returning None; failure leaves intent.
            self._rollback_rotation(ref, rollback=rollback)
            raise SecretError("rotation-not-accepted") from None
        # No rollback may cross this ambiguous commit boundary. Independent
        # pin/state read-back establishes the outcome or fails closed.
        try:
            with self.store.transaction(write=True) as state:
                authority, record = _record(state, ref)
                _admit_custody(state, rotation=ref)
                expected = previous["generation"] if previous else None
                if (authority["current"] != expected or record["status"] != "rotation-pending"
                        or record["rotation"]["operation_id"] != operation):
                    raise SecretError("rotation-concurrent-change")
                if previous:
                    _, old = _record(state, previous)
                    old["status"] = "revocation-pending"
                record["status"] = "current"
                record["rotation"] = None
                authority["current"] = ref["generation"]
                _material_changed(state)
        except SecretError:
            raise SecretError("rotation-outcome-unverified") from None
        if previous:
            self._finish_revocation(previous, revoke=revoke)
        else:
            _call(revoke, None)
        return self.metadata(ref)

    def rollback_rotation(self, ref, *, rollback):
        """Same administrative rollback authority, after actual previous-state read-back."""
        with self._rotation_lock():
            self._rollback_rotation(_ref(ref), rollback=rollback)

    def _rollback_rotation(self, ref, *, rollback):
        with self.store.transaction() as state:
            authority, record = _record(state, ref)
            if record["status"] != "rotation-pending" or record["rotation"] is None:
                raise SecretError("rotation-not-pending")
            intent = deepcopy(record["rotation"])
            previous = intent["previous"]
            expected = previous["generation"] if previous else None
            if authority["current"] != expected:
                raise SecretError("rollback-outcome-unverified")
        _call(rollback, ref, previous)
        with self.store.transaction(write=True) as state:
            authority, record = _record(state, ref)
            if (authority["current"] != expected or record["status"] != "rotation-pending"
                    or record["rotation"] != intent):
                raise SecretError("rollback-outcome-unverified")
            record["status"] = "candidate"
            record["rotation"] = None

    def finish_revocation(self, previous, *, revoke):
        """Complete only this durable crypto-generation obligation; no automatic retry."""
        with self._rotation_lock():
            self._finish_revocation(previous, revoke=revoke)

    def _finish_revocation(self, previous, *, revoke):
        with self.store.transaction() as state:
            _, old = _record(state, previous)
            if old["status"] != "revocation-pending":
                raise SecretError("revocation-not-pending")
        _call(revoke, _ref(previous))
        with self.store.transaction(write=True) as state:
            _, old = _record(state, previous)
            if old["status"] != "revocation-pending":
                raise SecretError("revocation-concurrent-change")
            old["status"] = "retained"
            _material_changed(state)


@dataclass(repr=False)
class ProtectedCredentials:
    """Authority/admin-owned per-purpose files; native service delivery adapter.

    LoadCredential paths may consume these files. Production setup is #92-owned;
    this class never edits units, publishes routes or grants a rootless user
    traversal over another service's credentials.
    """
    root: Path

    def __init__(self, root):
        self.root = Path(root)
        try:
            enrollment._ancestry(self.root.parent)
            if not self.root.exists():
                self.root.mkdir(mode=0o700)
            enrollment._directory(self.root)
        except (enrollment.EnrollmentError, OSError):
            raise SecretError("credential-directory") from None

    def publish(self, session_id, purpose, values):
        _uuid(session_id)
        if purpose not in PURPOSE_CLASSES or not values:
            raise SecretError("credential-purpose")
        staging = Path(tempfile.mkdtemp(prefix=".activation-", dir=self.root))
        target = self.root / session_id
        owned = staging.stat()
        published = False
        try:
            for name, value in values.items():
                if re.fullmatch(r"[a-z][a-z0-9.-]{0,79}", name) is None:
                    raise SecretError("credential-name")
                enrollment._write(staging / name, value)
                (staging / name).chmod(0o600 if name == "tenant-kek" else 0o400)
            enrollment._sync(staging)
            if target.exists() or target.is_symlink():
                raise SecretError("credential-already-published")
            staging.rename(target)
            published = True
            enrollment._sync(self.root)
            return str(target)
        except (OSError, enrollment.EnrollmentError):
            if published:
                try:
                    actual = target.lstat()
                    if (actual.st_dev, actual.st_ino) != (owned.st_dev, owned.st_ino):
                        raise SecretError("credential-cleanup-ownership")
                    shutil.rmtree(target)
                    enrollment._sync(self.root)
                except (OSError, enrollment.EnrollmentError):
                    raise SecretError("credential-cleanup-incomplete") from None
            raise SecretError("credential-publication") from None
        finally:
            if staging.exists():
                shutil.rmtree(staging)


def _delivery_values(state, refs):
    values = {}
    for ref in refs:
        authority, record = _record(state, ref)
        kind = authority["class"]
        value = _value(state, ref)
        if kind in values:
            raise SecretError("duplicate-secret-class")
        if kind in {"postgres-runtime", "postgres-migration"}:
            bundle = _database_bundle(value)
            for name, field in [("postgres-username", "username"), ("postgres-password", "password"),
                                ("postgres-ca.crt", "ca")]:
                values[name] = bundle[field].encode()
        else:
            values[kind] = value
        if kind == "app-key":
            old = [base64.b64decode(row["value"], validate=True)
                   for generation, row in sorted(authority["generations"].items(),
                                                  key=lambda pair: int(pair[0]), reverse=True)
                   if int(generation) != ref["generation"] and row["status"] in {"current", "retained"}]
            if len(old) > _STATE_CONTRACT["secret_policy"]["max_previous_keys"]:
                raise SecretError("application-previous-key-retention")
            values["app-previous-keys"] = b"\n".join(old)
    return values


class DeploymentActivation:
    """No CA signing key, enrollment DB writes or caller-selected authority."""
    def __init__(self, store, *, verifier, authorize, authorize_rotation=None):
        if not isinstance(verifier, enrollment.EnrollmentVerifier) or not callable(authorize):
            raise SecretError("enrollment-verifier-required")
        if verifier.deployment_id != store.deployment_id:
            raise SecretError("deployment-binding")
        self.store, self.verifier, self.authorize = store, verifier, authorize
        self.authorize_rotation = authorize_rotation

    def _policy(self, state, identity, purpose, refs, *, rotation=None):
        if purpose not in PURPOSE_CLASSES or not refs or len(refs) > 16:
            raise SecretError("purpose-not-authorized")
        if identity.get("deployment_id") != self.store.deployment_id:
            raise SecretError("deployment-binding")
        if rotation is not None and rotation not in refs:
            raise SecretError("rotation-candidate-binding")
        metadata = [_metadata(state, r) for r in refs]
        kinds = [m["class"] for m in metadata]
        if len(set(kinds)) != len(kinds) or not set(kinds) <= PURPOSE_CLASSES[purpose]:
            raise SecretError("secret-class-not-authorized")
        for ref in refs:
            authority, row = _record(state, ref)
            if ref == rotation:
                if row["status"] not in {"candidate", "rotation-pending"}:
                    raise SecretError("rotation-not-candidate")
            elif row["status"] != "current" or authority["current"] != ref["generation"]:
                raise SecretError("generation-not-current")
            if row["host_id"] is not None and (row["host_id"] != identity.get("host_id")
                                                or purpose not in row["purposes"]):
                raise SecretError("host-workload-binding")
        _call(self.authorize, deepcopy(identity), purpose, deepcopy(metadata))
        if rotation is not None:
            _call(self.authorize_rotation, deepcopy(identity), purpose, deepcopy(metadata))
        return metadata

    def challenge(self, identity, purpose, refs, *, ttl=60):
        return self._challenge(identity, purpose, refs, ttl=ttl)

    def challenge_rotation(self, identity, purpose, refs, *, candidate, ttl=60):
        """Same single-use boundary, with explicit independent rotation admission."""
        return self._challenge(identity, purpose, refs, ttl=ttl, rotation=_ref(candidate))

    def _challenge(self, identity, purpose, refs, *, ttl, rotation=None):
        if type(ttl) is not int or not 1 <= ttl <= MAX_SESSION_SECONDS:
            raise SecretError("activation-lifetime")
        refs = [_ref(r) for r in refs]
        with self.store.transaction(write=True) as state:
            _admit_custody(state, rotation=rotation)
            self._policy(state, identity, purpose, refs, rotation=rotation)
            instant = now()
            # Expired IDs are unusable even when pruned; never accept an unknown ID.
            state["sessions"] = {k: v for k, v in state["sessions"].items()
                                 if v["expires_at"] > instant}
            sid, challenge = str(uuid.uuid4()), os.urandom(32)
            expires = instant + ttl
            state["sessions"][sid] = {
                "identity": deepcopy(identity), "purpose": purpose, "refs": refs,
                "challenge": base64.b64encode(challenge).decode(),
                "expires_at": expires, "consumed": False, "rotation": rotation,
            }
        return {"session_id": sid, "challenge": challenge, "expires_at": expires}

    def activate(self, session_id, identity, proof, *, delivery):
        _uuid(session_id)
        with self.store.transaction() as state:
            session = deepcopy(state["sessions"].get(session_id))
        if session is None:
            raise SecretError("unknown-activation")
        if _encode(session["identity"]) != _encode(identity):
            raise SecretError("activation-identity-binding")
        challenge = base64.b64decode(session["challenge"], validate=True)
        try:
            actual = self.verifier.authenticate(identity, challenge, proof)
        except enrollment.EnrollmentError:
            raise SecretError("current-host-possession-required") from None
        if _encode(actual) != _encode(identity):
            raise SecretError("activation-identity-binding")
        with self.store.transaction(write=True) as state:
            current = state["sessions"].get(session_id)
            if current != session or current["consumed"] or current["expires_at"] <= now():
                raise SecretError("activation-expired-or-consumed")
            _admit_custody(state, rotation=session["rotation"])
            metadata = self._policy(state, actual, session["purpose"], session["refs"],
                                    rotation=session["rotation"])
            values = _delivery_values(state, session["refs"])
            current["consumed"] = True
        # Commit acknowledgement precedes release. A delivery failure does not
        # resurrect the session or remove/replace any previously accepted delivery.
        try:
            self.verifier.authenticate(identity, challenge, proof)
            directory = delivery.publish(session_id, session["purpose"], values)
        except SecretError:
            raise
        except Exception:
            raise SecretError("activation-not-materialized") from None
        return {"session_id": session_id, "purpose": session["purpose"],
                "host_id": actual["host_id"], "generation": actual["generation"],
                "directory": directory, "secrets": metadata}
