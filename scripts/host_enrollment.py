#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Host-local enrollment client and separately held, bounded Enrollment Authority.

Trusted control supplies #169 inspection and #80/#92 readiness admission as
in-process interfaces. Host requests cannot supply these interfaces. No provider,
installer, secret backend, listener, fleet lookup or credential broker lives here.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import pwd
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from types import ModuleType
import uuid

# Reuse #169's exact runtime types and admission. Compile the fixed sibling
# source instead of executing an adjacent, unadmitted bytecode cache.
_PROVIDER_NAME = "_secpal_enrollment_provider_contract"
_path = Path(__file__).with_name("provider-capability-contract.py")
_module = ModuleType(_PROVIDER_NAME)
_module.__file__ = str(_path)
sys.modules[_PROVIDER_NAME] = _module
exec(compile(_path.read_bytes(), str(_path), "exec"), _module.__dict__)
provider = _module


MAX_DOCUMENT = 65536
MAX_GRANT_SECONDS = 300
MAX_OBSERVATION_AGE = 60
P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004")
REQUEST_FIELDS = {
    "version", "deployment_id", "resource", "role", "host_id", "machine",
    "identity_created_at", "created_at", "public_key_sha256", "csr",
}
GRANT_FIELDS = {
    "version", "grant_id", "deployment_id", "resource", "role", "host_id",
    "machine", "public_key_sha256", "request_sha256", "generation", "purpose",
    "issued_at", "expires_at", "authority_sha256", "incarnation_id",
}


class EnrollmentError(ValueError):
    """A closed, non-secret semantic operation code."""

    def __init__(self, code):
        if type(code) is not str or re.fullmatch("[a-z][a-z0-9-]{0,79}", code) is None:
            code = "contract-failed"
        super().__init__(code)


def now():
    return int(time.time())


def canonical(value):
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise EnrollmentError("invalid-document") from None
    if len(result) > MAX_DOCUMENT:
        raise EnrollmentError("document-size")
    return result


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _closed(value, fields, operation):
    if type(value) is not dict or set(value) != fields:
        raise EnrollmentError(operation)
    canonical(value)


def _uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise EnrollmentError("identity-format") from None


def _hash(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise EnrollmentError("fingerprint-format")


def _integer(value):
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        raise EnrollmentError("integer-format")


def _machine(value):
    _closed(value, {"machine_id", "ssh_host_key"}, "machine-format")
    if (type(value["machine_id"]) is not str
            or re.fullmatch("[0-9a-f]{32}", value["machine_id"]) is None
            or value["machine_id"] == "0" * 32
            or type(value["ssh_host_key"]) is not str
            or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value["ssh_host_key"]) is None):
        raise EnrollmentError("machine-format")


def _resource(value):
    _closed(value, {"provider", "scope", "requested_key", "provider_resource_id",
                    "expected_version"}, "resource-format")
    try:
        target = provider.ResourceTarget(**value)
        if target.provider_resource_id is None:
            raise provider.ContractError("missing exact resource")
    except (TypeError, provider.ContractError):
        raise EnrollmentError("resource-format") from None
    return target


def _provider_target(value):
    # Public #169 dataclasses may have been loaded under another module name.
    # Re-admit their data through the fixed owner's constructors, not class identity.
    try:
        return _resource(asdict(value))
    except TypeError:
        raise EnrollmentError("resource-format") from None


def host_resource(target):
    """Stable #169 resource identity; versions remain inspection preconditions."""
    target = _provider_target(target)
    return provider.ResourceTarget(target.provider, target.scope, target.requested_key,
                                   target.provider_resource_id)


def resource_slot(target):
    """Provider's exact resource, independent of its requested logical alias."""
    return digest({name: getattr(target, name) for name in [
        "provider", "scope", "provider_resource_id"]})


def _role(value):
    if (type(value) is not str
            or re.fullmatch("[a-z0-9]+(?:[._-][a-z0-9]+)*", value) is None
            or len(value) > 128):
        raise EnrollmentError("role-format")


def _scope(deployment, resource, role):
    _uuid(deployment)
    _provider_target(resource)
    _role(role)


def _signature(value):
    try:
        if type(value) is not str or not 8 <= len(value) <= 2048:
            raise ValueError
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise EnrollmentError("signature-format") from None


def openssl(operation, arguments, *, input_bytes=None, cwd="/"):
    """One bounded platform operation; no raw diagnostics or environment escapes."""
    try:
        result = subprocess.run(
            ["/usr/bin/openssl", *map(str, arguments)], input=input_bytes,
            capture_output=True, timeout=15, cwd=cwd,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        if (result.returncode or len(result.stdout) > MAX_DOCUMENT
                or len(result.stderr) > MAX_DOCUMENT):
            raise EnrollmentError(operation)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise EnrollmentError(operation) from None


def _ancestry(path):
    if not path.is_absolute() or ".." in path.parts:
        raise EnrollmentError("state-path")
    try:
        for current in (path, *path.parents):
            info = current.lstat()
            sticky_tmp = (current == Path("/tmp") and info.st_uid == 0
                          and info.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(info.st_mode)
                    or info.st_uid not in {0, os.geteuid()}
                    or (info.st_mode & 0o022 and not sticky_tmp)):
                raise EnrollmentError("state-ancestry")
    except OSError:
        raise EnrollmentError("state-ancestry") from None


def _directory(path):
    _ancestry(path)
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise EnrollmentError("state-directory")


def _file(path, *, private=True):
    _ancestry(path.parent)
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in ({os.geteuid()} if private else {0, os.geteuid()})
                or (private and stat.S_IMODE(info.st_mode) != 0o600)
                or (not private and info.st_mode & 0o022)
                or not 0 < info.st_size <= MAX_DOCUMENT):
            raise EnrollmentError("state-file")
    except OSError:
        raise EnrollmentError("state-file") from None


def _write(path, data):
    try:
        if isinstance(data, str):
            data = data.encode("ascii")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, UnicodeError):
        raise EnrollmentError("state-write") from None


def _sync(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise EnrollmentError("state-sync") from None


def _publish(path, value):
    _directory(path.parent)
    with tempfile.TemporaryDirectory(prefix=".publish-", dir=path.parent) as raw:
        temporary = Path(raw) / "public.json"
        _write(temporary, canonical(value))
        try:
            os.replace(temporary, path)
        except OSError:
            raise EnrollmentError("state-publish") from None
        _sync(path.parent)


@contextmanager
def _lock(directory):
    _directory(directory)
    try:
        fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode)):
                raise EnrollmentError("state-lock")
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise EnrollmentError("state-lock-timeout") from None
                    time.sleep(0.01)
            yield
        finally:
            os.close(fd)
    except OSError:
        raise EnrollmentError("state-lock") from None


def _json_file(path):
    _file(path)
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
    except (OSError, ValueError, UnicodeError):
        raise EnrollmentError("state-document") from None


def _ready(callback, *args):
    if not callable(callback):
        raise EnrollmentError("conformance-required")
    try:
        if callback(*args) is not None:
            raise EnrollmentError("conformance-required")
    except EnrollmentError:
        raise
    except Exception:
        raise EnrollmentError("conformance-rejected") from None


def observe_machine():
    """Local correlation facts, never independent provider authentication."""
    try:
        machine = Path("/etc/machine-id").read_text().strip()
        key = subprocess.run(
            ["/usr/bin/ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256"],
            capture_output=True, text=True, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"}, cwd="/")
        if key.returncode or len(key.stdout) > 512:
            raise EnrollmentError("observe-machine")
        fact = {"machine_id": machine, "ssh_host_key": key.stdout.split()[1]}
        _machine(fact)
        return fact
    except (OSError, subprocess.SubprocessError, IndexError, UnicodeError):
        raise EnrollmentError("observe-machine") from None


def _public(pem, kind):
    if type(pem) is not str or not 1 <= len(pem) <= 8192:
        raise EnrollmentError("public-key-format")
    try:
        data = pem.encode("ascii")
    except UnicodeError:
        raise EnrollmentError("public-key-format") from None
    normalized = openssl("normalize-public-object", [kind, "-outform", "PEM"],
                         input_bytes=data)
    if normalized != data:
        raise EnrollmentError("public-object-framing")
    if kind == "req":
        openssl("verify-csr", ["req", "-verify", "-noout"], input_bytes=data)
    public = openssl("read-public-key", [kind, "-pubkey", "-noout"],
                     input_bytes=data)
    der = openssl("normalize-public-key", ["pkey", "-pubin", "-outform", "DER"],
                  input_bytes=public)
    if len(der) != 91 or not der.startswith(P256_SPKI_PREFIX):
        raise EnrollmentError("host-key-algorithm")
    openssl("validate-public-key", ["pkey", "-pubin", "-pubcheck", "-noout"],
            input_bytes=public)
    return public, hashlib.sha256(der).hexdigest()


def _sign(key, message, directory):
    _file(key)
    with tempfile.TemporaryDirectory(prefix=".signature-", dir=directory) as raw:
        data = Path(raw) / "message"
        _write(data, message)
        return base64.b64encode(openssl(
            "sign-possession", ["dgst", "-sha256", "-sign", key, data])).decode()


def _verify(public, message, signature, directory):
    with tempfile.TemporaryDirectory(prefix=".verify-", dir=directory) as raw:
        root = Path(raw)
        _write(root / "public.pem", public)
        _write(root / "message", message)
        _write(root / "signature", _signature(signature))
        openssl("verify-possession", ["dgst", "-sha256", "-verify", root / "public.pem",
                                     "-signature", root / "signature", root / "message"])


def _ca(certificate):
    _file(certificate, private=False)
    data = certificate.read_bytes()
    normalized = openssl("normalize-authority-certificate",
                         ["x509", "-in", certificate, "-outform", "PEM"])
    if data.count(b"-----BEGIN CERTIFICATE-----") != 1 or normalized != data:
        raise EnrollmentError("authority-certificate")
    der = openssl("read-authority", ["x509", "-in", certificate, "-outform", "DER"])
    public = openssl("read-authority", ["x509", "-in", certificate, "-pubkey", "-noout"])
    return public, hashlib.sha256(der).hexdigest()


def _request(request):
    _closed(request, REQUEST_FIELDS, "request-fields")
    if type(request["version"]) is not int or request["version"] != 1:
        raise EnrollmentError("request-version")
    _scope(request["deployment_id"], _resource(request["resource"]), request["role"])
    _uuid(request["host_id"])
    _machine(request["machine"])
    _hash(request["public_key_sha256"])
    for key in ["created_at", "identity_created_at"]:
        _integer(request[key])
    if (not request["identity_created_at"] <= request["created_at"] <= now()
            or now() - request["created_at"] > MAX_GRANT_SECONDS):
        raise EnrollmentError("request-time")
    public, fingerprint = _public(request["csr"], "req")
    if fingerprint != request["public_key_sha256"]:
        raise EnrollmentError("request-key")
    return public


def _signed_grant(grant, ca, directory):
    _closed(grant, {"payload", "signature"}, "grant-fields")
    p = grant["payload"]
    _closed(p, GRANT_FIELDS, "grant-payload")
    if type(p["version"]) is not int or p["version"] != 1:
        raise EnrollmentError("grant-version")
    for name in ["grant_id", "deployment_id", "host_id", "incarnation_id"]:
        _uuid(p[name])
    _resource(p["resource"])
    _role(p["role"])
    _machine(p["machine"])
    for name in ["public_key_sha256", "request_sha256", "authority_sha256"]:
        _hash(p[name])
    for name in ["generation", "issued_at", "expires_at"]:
        _integer(p[name])
    if (type(p["purpose"]) is not str or p["purpose"] not in {"enroll", "recover"}
            or not 0 < p["expires_at"] - p["issued_at"] <= MAX_GRANT_SECONDS):
        raise EnrollmentError("grant-time-or-purpose")
    public, fingerprint = _ca(ca)
    if fingerprint != p["authority_sha256"]:
        raise EnrollmentError("grant-authority")
    _verify(public, b"SecPal Enrollment Grant v1\n" + canonical(p),
            grant["signature"], directory)
    return p


def _grant(grant, ca, directory):
    payload = _signed_grant(grant, ca, directory)
    if not payload["issued_at"] <= now() < payload["expires_at"]:
        raise EnrollmentError("grant-time-or-purpose")
    return payload


def _proof_message(grant):
    return b"SecPal Host Enrollment Possession v1\n" + canonical(grant)


def _identity(grant, certificate):
    p = grant["payload"]
    return {"state": "ENROLLED", **{name: p[name] for name in [
        "host_id", "deployment_id", "resource", "role", "generation",
        "public_key_sha256", "grant_id", "incarnation_id"]},
        "certificate_sha256": hashlib.sha256(certificate.encode()).hexdigest()}


def _admit_certificate(certificate, grant, ca, directory, *, registered=False):
    if (type(certificate) is not str or not 0 < len(certificate) <= 16384
            or certificate.count("-----BEGIN CERTIFICATE-----") != 1):
        raise EnrollmentError("certificate-format")
    with tempfile.TemporaryDirectory(prefix=".certificate-", dir=directory) as raw:
        path = Path(raw) / "client.pem"
        _write(path, certificate)
        at = now()
        if registered:
            # A completed registration remains authentic after its bootstrap
            # credential expires. Verify its existing CA signature at issuance,
            # never use this path for consuming a grant or live TLS admission.
            try:
                dates = openssl("certificate-registration-time", [
                    "x509", "-in", path, "-noout", "-dates"]).decode("ascii").splitlines()
                fields = dict(line.split("=", 1) for line in dates)
                before = int(ssl.cert_time_to_seconds(fields["notBefore"]))
                after = int(ssl.cert_time_to_seconds(fields["notAfter"]))
                payload = grant["payload"]
                if (set(fields) != {"notBefore", "notAfter"}
                        or not payload["issued_at"] - 1 <= before < after
                        or after != payload["expires_at"] or before > now()
                        or payload["issued_at"] > now()):
                    raise EnrollmentError("registration-certificate-time")
                at = max(before, payload["issued_at"])
            except (ValueError, KeyError, UnicodeError):
                raise EnrollmentError("registration-certificate-time") from None
        openssl("verify-certificate", ["verify", "-CAfile", ca, "-no-CApath",
                                      "-no-CAstore", "-purpose", "sslclient",
                                      "-attime", str(at), path])
        subject = openssl("certificate-binding", ["x509", "-in", path, "-noout",
                                                   "-subject", "-nameopt", "RFC2253"])
        if subject.strip() != ("subject=CN=" + digest(grant["payload"])).encode():
            raise EnrollmentError("certificate-binding")
        _, fingerprint = _public(certificate, "x509")
        if fingerprint != grant["payload"]["public_key_sha256"]:
            raise EnrollmentError("certificate-key")
    return _identity(grant, certificate)


def admit_registration(record, ca, directory):
    """Authenticate stored completion using the existing CA-issued certificate."""
    _closed(record, {"identity", "csr", "machine", "credential"}, "registration-fields")
    credential = record["credential"]
    _closed(credential, {"grant", "certificate"}, "credential-fields")
    grant = credential["grant"]
    payload = _signed_grant(grant, ca, directory)
    identity = _admit_certificate(credential["certificate"], grant, ca, directory,
                                  registered=True)
    if (canonical(record["identity"]) != canonical(identity)
            or canonical(record["machine"]) != canonical(payload["machine"])):
        raise EnrollmentError("registration-binding")
    public, fingerprint = _public(record["csr"], "req")
    if fingerprint != payload["public_key_sha256"]:
        raise EnrollmentError("registered-key-binding")
    return identity, public




class LocalHost:
    """Administrator-side local storage. No method returns the private key."""

    def __init__(self, directory):
        self.directory = Path(directory)
        _directory(self.directory)

    @classmethod
    def create(cls, directory, deployment_id, resource, role, *, ready):
        _scope(deployment_id, resource, role)
        _ready(ready)  # Existing admitted Conformance/Phase-1 boundary first.
        machine = observe_machine()
        _machine(machine)
        path = Path(directory)
        _ancestry(path.parent)
        try:
            path.mkdir(mode=0o700)  # Exclusive; never overwrite or regenerate.
        except OSError:
            raise EnrollmentError("identity-already-exists") from None
        _directory(path)
        key = path / "host-key.pem"
        _write(key, b"")
        openssl("generate-host-key", ["genpkey", "-algorithm", "EC", "-pkeyopt",
                                     "ec_paramgen_curve:P-256", "-out", key])
        _file(key)
        try:
            fd = os.open(key, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            raise EnrollmentError("identity-key-sync") from None
        public = openssl("read-host-public-key", ["pkey", "-in", key,
                                                 "-pubout", "-outform", "DER"])
        identity = {"version": 1, "deployment_id": deployment_id,
                    "resource": asdict(host_resource(resource)), "role": role,
                    "host_id": str(uuid.uuid4()), "machine": machine,
                    "identity_created_at": now(),
                    "public_key_sha256": hashlib.sha256(public).hexdigest()}
        _write(path / "identity.json", canonical(identity))
        _sync(path)
        _sync(path.parent)
        return cls(path)

    def _metadata(self):
        _directory(self.directory)
        document = _json_file(self.directory / "identity.json")
        _closed(document, REQUEST_FIELDS - {"created_at", "csr"}, "identity-fields")
        _scope(document["deployment_id"], _resource(document["resource"]), document["role"])
        _uuid(document["host_id"])
        _machine(document["machine"])
        _hash(document["public_key_sha256"])
        _integer(document["identity_created_at"])
        if (type(document["version"]) is not int or document["version"] != 1
                or document["identity_created_at"] > now()):
            raise EnrollmentError("identity-metadata")
        if document["machine"] != observe_machine():
            raise EnrollmentError("copied-host-identity")
        _file(self.directory / "host-key.pem")
        actual = openssl("read-host-public-key", [
            "pkey", "-in", self.directory / "host-key.pem", "-pubout", "-outform", "DER"])
        if hashlib.sha256(actual).hexdigest() != document["public_key_sha256"]:
            raise EnrollmentError("host-key-mismatch")
        return document

    def request(self):
        with _lock(self.directory):
            metadata = self._metadata()
            csr = openssl("create-csr", ["req", "-new", "-sha256",
                                        "-key", self.directory / "host-key.pem",
                                        "-subj", "/CN=" + metadata["host_id"]]).decode()
            request = {**metadata, "created_at": now(), "csr": csr}
            _request(request)
            return request

    def prove(self, grant, authority_certificate):
        with _lock(self.directory):
            metadata = self._metadata()
            payload = _grant(grant, Path(authority_certificate), self.directory)
            for name in ["deployment_id", "resource", "role", "host_id", "machine",
                         "public_key_sha256"]:
                if metadata[name] != payload[name]:
                    raise EnrollmentError("host-grant-binding")
            return _sign(self.directory / "host-key.pem", _proof_message(grant), self.directory)

    def accept(self, credential, authority_certificate):
        with _lock(self.directory):
            _closed(credential, {"grant", "certificate"}, "credential-fields")
            metadata = self._metadata()
            grant = credential["grant"]
            payload = _grant(grant, Path(authority_certificate), self.directory)
            for name in ["deployment_id", "resource", "role", "host_id", "machine",
                         "public_key_sha256"]:
                if metadata[name] != payload[name]:
                    raise EnrollmentError("host-credential-binding")
            result = _admit_certificate(credential["certificate"], grant,
                                        Path(authority_certificate), self.directory)
            path = self.directory / "enrollment.json"
            if path.exists() or path.is_symlink():
                previous = _json_file(path)
                if (payload["purpose"] != "recover"
                        or result["generation"] <= previous["identity"]["generation"]):
                    raise EnrollmentError("duplicate-enrollment")
            _publish(path, {"identity": result, "credential": credential})
            return result

    def prove_identity(self, identity, challenge):
        if type(challenge) is not bytes or len(challenge) != 32:
            raise EnrollmentError("challenge-format")
        if type(identity) is not dict or identity.get("state") != "ENROLLED":
            raise EnrollmentError("identity-proof-binding")
        with _lock(self.directory):
            metadata = self._metadata()
            for key in ["host_id", "deployment_id", "resource", "role", "public_key_sha256"]:
                if identity.get(key) != metadata[key]:
                    raise EnrollmentError("identity-proof-binding")
            message = b"SecPal Enrolled Host Possession v1\n" + canonical(identity) + challenge
            return _sign(self.directory / "host-key.pem", message, self.directory)


@dataclass(frozen=True, slots=True)
class TrustedHost:
    """Trusted adapter return, never an accepted host-supplied wire document."""
    request: object
    authority: object
    result: object
    machine: dict
    request_digest: str
    observed_at: int
    incarnation_id: str


def admit_database_target(host, sslmode, *, port=5432):
    """Admit the configured endpoint before libpq can send credentials."""
    if type(host) is not str or not host or host.startswith("@") or "," in host:
        raise EnrollmentError("authority-database-transport")
    if type(host) is str and host.startswith("/"):
        directory = Path(host)
        try:
            if ".." in directory.parts or directory.resolve(strict=True) != directory:
                raise EnrollmentError("authority-database-socket")
            owners = {0, os.geteuid()}
            try:
                owners.add(pwd.getpwnam("postgres").pw_uid)
            except KeyError:
                pass
            for path in (directory, *directory.parents):
                info = path.lstat()
                sticky_parent = (path != directory and path == Path("/tmp")
                                 and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                        or (info.st_mode & 0o022 and not sticky_parent)):
                    raise EnrollmentError("authority-database-socket")
            if str(int(port)) != str(port) or not 1 <= int(port) <= 65535:
                raise EnrollmentError("authority-database-socket")
            info = (directory / (".s.PGSQL." + str(port))).lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in owners or info.st_nlink != 1:
                raise EnrollmentError("authority-database-socket")
        except (OSError, ValueError):
            raise EnrollmentError("authority-database-socket") from None
        return
    if sslmode != "verify-full":
        raise EnrollmentError("authority-database-transport")


def admit_database_transport(host, sslmode, encrypted, *, port=5432):
    """Re-admit actual transport after connection, including observed TLS."""
    admit_database_target(host, sslmode, port=port)
    if not host.startswith("/") and encrypted is not True:
        raise EnrollmentError("authority-database-transport")


@contextmanager
def authority_transaction(database):
    """Native PG18 connection parameters/credentials belong to trusted control."""
    try:
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.conninfo import conninfo_to_dict
    except ImportError:
        raise EnrollmentError("authority-client-unavailable") from None
    db = None
    try:
        # Native libpq keywords, not an opaque callable that can connect before
        # endpoint admission. No service/hostaddr indirection may bypass it.
        if (type(database) is not dict or "service" in database or "hostaddr" in database
                or os.environ.get("PGSERVICE") or os.environ.get("PGHOSTADDR")):
            raise EnrollmentError("authority-database-parameters")
        parameters = conninfo_to_dict("", **database)
        parameters.setdefault("port", "5432")
        parameters.setdefault("connect_timeout", "5")
        try:
            port, timeout = int(parameters["port"]), int(parameters["connect_timeout"])
        except (ValueError, TypeError):
            raise EnrollmentError("authority-database-parameters") from None
        if not 1 <= port <= 65535 or not 1 <= timeout <= 10:
            raise EnrollmentError("authority-database-parameters")
        host = parameters.get("host")
        admit_database_target(host, parameters.get("sslmode"), port=port)
        db = psycopg.connect(**parameters)
        if db.info.host != host or db.info.port != port:
            raise EnrollmentError("authority-database-transport")
        if db.autocommit or not 180000 <= db.info.server_version < 190000:
            raise EnrollmentError("authority-database-contract")
        db.row_factory = dict_row
        with db:
            db.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            encrypted = False
            if not db.info.host.startswith("/"):
                encrypted = db.execute(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()["ssl"]
            admit_database_transport(db.info.host,
                                     db.info.get_parameters().get("sslmode"), encrypted,
                                     port=db.info.port)
            for setting in ["fsync", "full_page_writes"]:
                if db.execute("SHOW " + setting).fetchone()[setting] != "on":
                    raise EnrollmentError("authority-database-durability")
            db.execute("SET LOCAL synchronous_commit = on")
            db.execute("SET LOCAL statement_timeout = '15s'")
            db.execute("SET LOCAL lock_timeout = '5s'")
            # One authority lock covers duplicate keys across resource scopes,
            # not merely competing consumes for the same grant.
            db.execute("SELECT pg_advisory_xact_lock(8316457291241)")
            yield db
    except EnrollmentError:
        raise
    except (psycopg.Error, OSError):
        raise EnrollmentError("authority-state") from None
    finally:
        if db is not None and not db.closed:
            try:
                db.close()
            except psycopg.Error:
                raise EnrollmentError("authority-state-close") from None


def database_digest(db):
    """Stream a stable native transaction snapshot, never private host material."""
    result = hashlib.sha256(b"SecPal Enrollment Authority Database v1\n")
    for table, order in [("authority", "singleton"), ("grants", "grant_id"),
                         ("enrollments", "grant_id")]:
        result.update(table.encode() + b"\0")
        with db.cursor(name="secpal_integrity_" + table) as rows:
            rows.execute("SELECT * FROM secpal_enrollment." + table + " ORDER BY " + order)
            for row in rows:
                result.update(canonical(row) + b"\n")
    return result.hexdigest()


def initialize_authority_store(database, authority_certificate, *, directory):
    """Explicit one-time DBA operation; never called by enrollment runtime."""
    _, fingerprint = _ca(Path(authority_certificate))
    directory = Path(directory)
    _ancestry(directory.parent)
    try:
        directory.mkdir(mode=0o700)
    except OSError:
        raise EnrollmentError("authority-already-exists") from None
    with _lock(directory), authority_transaction(database) as db:
        db.execute("CREATE SCHEMA secpal_enrollment")
        db.execute("""CREATE TABLE secpal_enrollment.authority(
            singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
            version integer NOT NULL CHECK(version=1),
            authority_sha256 text NOT NULL)""")
        db.execute("""INSERT INTO secpal_enrollment.authority
            (version,authority_sha256) VALUES(1,%s)""", (fingerprint,))
        db.execute("""CREATE TABLE secpal_enrollment.grants(
            grant_id text PRIMARY KEY, envelope text NOT NULL,
            consumed boolean NOT NULL DEFAULT false)""")
        db.execute("""CREATE TABLE secpal_enrollment.enrollments(
            grant_id text PRIMARY KEY REFERENCES secpal_enrollment.grants(grant_id),
            resource text NOT NULL, generation integer NOT NULL CHECK(generation>0),
            host_id text NOT NULL, fingerprint text NOT NULL, request text NOT NULL,
            certificate text NOT NULL, identity text NOT NULL,
            UNIQUE(resource,generation))""")
        db.execute("REVOKE ALL ON SCHEMA secpal_enrollment FROM PUBLIC")
        db.execute("REVOKE ALL ON ALL TABLES IN SCHEMA secpal_enrollment FROM PUBLIC")
        # The pin is deliberately outside the database restoration domain.
        # Persist before commit: ambiguity poisons admission rather than
        # silently trusting potentially restored or partially committed state.
        _publish(directory / "database-sha256.json", database_digest(db))


class EnrollmentAuthority:
    """One explicit deployment/resource/role scope, separate from Secret Authority."""

    def __init__(self, directory, certificate, key, deployment_id, resource, role,
                 *, observe, ready, database, recovery=None):
        _scope(deployment_id, resource, role)
        self.directory = Path(directory)
        self.certificate, self.key = Path(certificate), Path(key)
        _file(self.key)
        ca_public, self.ca_fingerprint = _ca(self.certificate)
        own = openssl("authority-key-binding", ["pkey", "-in", self.key, "-pubout"])
        if own != ca_public:
            raise EnrollmentError("authority-key-binding")
        _directory(self.directory)
        self.inspection_target = resource
        self.deployment_id, self.resource, self.role = deployment_id, host_resource(resource), role
        self.observe, self.ready, self.recovery = observe, ready, recovery
        if type(database) is not dict:
            raise EnrollmentError("authority-database-parameters")
        self.database = dict(database)
        # Runtime authority cannot initialize or silently replace replay state.
        with self._transaction():
            pass

    @contextmanager
    def _transaction(self, *, write=False):
        # All instances of this authority share this existing private root.
        with _lock(self.directory), authority_transaction(self.database) as db:
            row = db.execute(
                "SELECT version, authority_sha256 FROM secpal_enrollment.authority"
                " WHERE singleton=true").fetchone()
            if row is None or row["version"] != 1 or row["authority_sha256"] != self.ca_fingerprint:
                raise EnrollmentError("authority-state-binding")
            pin = self.directory / "database-sha256.json"
            expected = _json_file(pin)
            _hash(expected)
            if database_digest(db) != expected:
                raise EnrollmentError("authority-state-integrity")
            yield db
            if write:
                # No automatic pin repair after a failed/ambiguous commit.
                # The existing Recovery Authority must establish fresh trust.
                _publish(pin, database_digest(db))

    def _observe(self, request, *, possession=None):
        _request(request)
        document = request if possession is None else {**request, "possession": possession}
        observation = _observe_control(self.observe, document, self.deployment_id,
                                       self.resource, self.role,
                                       inspection_target=self.inspection_target)
        _ready(self.ready, observation)
        return document, observation

    def _previous(self, db):
        return db.execute(
            "SELECT * FROM secpal_enrollment.enrollments WHERE resource=%s ORDER BY generation DESC LIMIT 1",
            (resource_slot(self.resource),)).fetchone()

    def _generation(self, db, request, purpose, incarnation_id):
        previous = self._previous(db)
        previous_record = None if previous is None else self._record(db, previous)
        if purpose == "enroll":
            if previous is not None:
                raise EnrollmentError("duplicate-enrollment")
        elif purpose == "recover":
            if previous is None or not callable(self.recovery):
                raise EnrollmentError("recovery-authorization-required")
            _ready(self.recovery, request, previous_record["identity"])
        else:
            raise EnrollmentError("grant-purpose")
        # A known key cannot migrate to another resource/machine/host identity.
        for row in db.execute("SELECT * FROM secpal_enrollment.enrollments WHERE fingerprint=%s OR host_id=%s",
                              (request["public_key_sha256"], request["host_id"])):
            old_record = self._record(db, row)
            old = json.loads(row["request"])
            if (old_record["identity"]["incarnation_id"] != incarnation_id
                    or any(old[key] != request[key] for key in [
                        "host_id", "deployment_id", "resource", "machine", "role", "public_key_sha256"])):
                raise EnrollmentError("copied-enrollment-key")
        return 1 if previous is None else previous["generation"] + 1

    def grant(self, request, *, purpose="enroll", ttl=MAX_GRANT_SECONDS):
        request = json.loads(canonical(request))
        document, observation = self._observe(request)
        if type(ttl) is not int or not 1 <= ttl <= MAX_GRANT_SECONDS:
            raise EnrollmentError("grant-lifetime")
        with self._transaction(write=True) as db:
            generation = self._generation(db, request, purpose, observation.incarnation_id)
            admit_management(document, observation, self.deployment_id,
                             self.resource, self.role, now(),
                             inspection_target=self.inspection_target)
            issued_at = now()
            payload = {"version": 1, "grant_id": str(uuid.uuid4()),
                       "deployment_id": self.deployment_id, "resource": asdict(self.resource),
                       "role": self.role, "host_id": request["host_id"],
                       "machine": request["machine"],
                       "public_key_sha256": request["public_key_sha256"],
                       "request_sha256": digest(request), "generation": generation,
                       "incarnation_id": observation.incarnation_id,
                       "purpose": purpose, "issued_at": issued_at, "expires_at": issued_at + ttl,
                       "authority_sha256": self.ca_fingerprint}
            signature = _sign(self.key, b"SecPal Enrollment Grant v1\n" + canonical(payload),
                              self.directory)
            grant = {"payload": payload, "signature": signature}
            db.execute("INSERT INTO secpal_enrollment.grants(grant_id,envelope) VALUES(%s,%s)",
                       (payload["grant_id"], canonical(grant).decode()))
        return grant

    def _certificate(self, request, grant):
        p = grant["payload"]
        with tempfile.TemporaryDirectory(prefix=".issue-", dir=self.directory) as raw:
            root = Path(raw)
            _write(root / "csr.pem", request["csr"])
            _write(root / "index", b"")
            _write(root / "serial", "01\n")
            # OpenSSL's transient one-certificate index is not another authority
            # database. Only the enclosing PostgreSQL transaction commits issuance.
            configuration = (
                "[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index\nnew_certs_dir=.\n"
                "serial=serial\ndefault_md=sha256\npolicy=subject\nunique_subject=no\n"
                "copy_extensions=none\nx509_extensions=client\n"
                "[subject]\ncommonName=supplied\n[client]\n"
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=critical,clientAuth\n"
                "subjectAltName=URI:urn:secpal:enrollment:" + digest(p) + "\n")
            _write(root / "openssl.cnf", configuration)
            stamp = lambda value: datetime.fromtimestamp(
                value, timezone.utc).strftime("%Y%m%d%H%M%SZ")
            # CA config uses fixed relative scratch paths; execute in that
            # private directory, without exposing credentials in argv.
            args = ["ca", "-batch", "-notext", "-rand_serial",
                    "-config", "openssl.cnf", "-cert", str(self.certificate),
                    "-keyfile", str(self.key), "-in", "csr.pem", "-out", "client.pem",
                    "-subj", "/CN=" + digest(p), "-startdate", stamp(now() - 1),
                    "-enddate", stamp(p["expires_at"])]
            openssl("issue-certificate", args, cwd=root)
            _file(root / "client.pem", private=False)
            certificate = (root / "client.pem").read_text()
            _admit_certificate(certificate, grant, self.certificate, self.directory)
            return certificate

    def consume(self, request, grant, proof):
        request, grant = json.loads(canonical(request)), json.loads(canonical(grant))
        payload = _grant(grant, self.certificate, self.directory)
        if (payload["request_sha256"] != digest(request)
                or any(payload[k] != request[k] for k in [
                    "deployment_id", "resource", "role", "host_id", "machine",
                    "public_key_sha256"])):
            raise EnrollmentError("grant-request-binding")
        public = _request(request)
        _verify(public, _proof_message(grant), proof, self.directory)
        document, observation = self._observe(
            request, possession={"grant_sha256": digest(grant), "proof": proof})
        if payload["incarnation_id"] != observation.incarnation_id:
            raise EnrollmentError("host-incarnation-binding")
        with self._transaction(write=True) as db:
            row = db.execute("SELECT * FROM secpal_enrollment.grants WHERE grant_id=%s",
                             (payload["grant_id"],)).fetchone()
            if row is None or row["envelope"] != canonical(grant).decode():
                raise EnrollmentError("unissued-grant")
            if row["consumed"]:
                raise EnrollmentError("replayed-grant")
            if self._generation(db, request, payload["purpose"], observation.incarnation_id) != payload["generation"]:
                raise EnrollmentError("grant-generation")
            admit_management(document, observation, self.deployment_id,
                             self.resource, self.role, now(),
                             inspection_target=self.inspection_target)
            if not payload["issued_at"] <= now() < payload["expires_at"]:
                raise EnrollmentError("grant-expired")
            certificate = self._certificate(request, grant)
            if now() >= payload["expires_at"]:
                raise EnrollmentError("grant-expired")
            admit_management(document, observation, self.deployment_id,
                             self.resource, self.role, now(),
                             inspection_target=self.inspection_target)
            _ready(self.ready, observation)
            identity = _identity(grant, certificate)
            db.execute("INSERT INTO secpal_enrollment.enrollments VALUES(%s,%s,%s,%s,%s,%s,%s,%s)", (
                payload["grant_id"], resource_slot(self.resource), payload["generation"],
                payload["host_id"], payload["public_key_sha256"], canonical(request).decode(),
                certificate, canonical(identity).decode()))
            db.execute("UPDATE secpal_enrollment.grants SET consumed=true WHERE grant_id=%s",
                       (payload["grant_id"],))
        return {"grant": grant, "certificate": certificate}

    def _record(self, db, row):
        """One authenticated persisted-record boundary, including recovery inputs."""
        try:
            grant_row = db.execute(
                "SELECT envelope,consumed FROM secpal_enrollment.grants WHERE grant_id=%s",
                (row["grant_id"],)).fetchone()
            if grant_row is None or grant_row["consumed"] is not True:
                raise EnrollmentError("authority-record")
            grant = json.loads(grant_row["envelope"])
            request = json.loads(row["request"])
            _closed(request, REQUEST_FIELDS, "authority-record")
            record = {"identity": json.loads(row["identity"]),
                      "csr": request["csr"], "machine": request["machine"],
                      "credential": {"grant": grant, "certificate": row["certificate"]}}
            admit_registration(record, self.certificate, self.directory)
            payload = grant["payload"]
            if (row["grant_id"] != payload["grant_id"]
                    or digest(request) != payload["request_sha256"]
                    or any(request[k] != payload[k] for k in [
                        "deployment_id", "resource", "role", "host_id",
                        "machine", "public_key_sha256"])
                    or row["resource"] != resource_slot(_resource(payload["resource"]))
                    or row["generation"] != payload["generation"]
                    or row["host_id"] != payload["host_id"]
                    or row["fingerprint"] != payload["public_key_sha256"]):
                raise EnrollmentError("authority-record")
            return record
        except EnrollmentError:
            raise
        except (ValueError, KeyError, TypeError):
            raise EnrollmentError("authority-record") from None

    def current_identity(self):
        """Exact signed public registration for #100; no secret or fleet listing."""
        with self._transaction() as db:
            row = self._previous(db)
            if row is None:
                raise EnrollmentError("not-enrolled")
            record = self._record(db, row)
            identity = record["identity"]
            if (identity["resource"] != asdict(self.resource)
                    or identity["deployment_id"] != self.deployment_id
                    or identity["role"] != self.role):
                raise EnrollmentError("enrollment-scope")
            return record

    def authenticate(self, identity, challenge, proof):
        """Public verification path; Secret Authority never needs our signing key."""
        verifier = EnrollmentVerifier(
            self.directory, self.certificate, self.deployment_id, self.resource,
            self.role, observe=self.observe,
            current=lambda host_id: self.current_identity())
        return verifier.authenticate(identity, challenge, proof)


def _provider_input(value, model):
    """Normalize public contract data; #169 still owns every admission rule."""
    try:
        data = asdict(value)
        data["target"] = _resource(data["target"])
        if model is provider.ExecutionAuthority:
            if type(data["operations"]) is not frozenset:
                raise EnrollmentError("provider-binding")
            data["operations"] = frozenset(provider.Operation(x) for x in data["operations"])
        else:
            data["operation"] = provider.Operation(data["operation"])
        if model is provider.CapabilityResult:
            data["outcome"] = provider.Outcome(data["outcome"])
            data["cleanup"] = provider.CleanupOutcome(data["cleanup"])
        return model(**data)
    except (TypeError, ValueError, KeyError):
        raise EnrollmentError("provider-binding") from None


def admit_management(document, observation, deployment_id, resource, role, at,
                     *, inspection_target=None):
    """Pure correlation admission; #169 owns provider request/result invariants."""
    if (document["deployment_id"] != deployment_id
            or document["resource"] != asdict(resource) or document["role"] != role):
        raise EnrollmentError("enrollment-scope")
    if type(observation) is not TrustedHost:
        raise EnrollmentError("authenticated-observation-required")
    try:
        request = _provider_input(observation.request, provider.CapabilityRequest)
        authority = _provider_input(observation.authority, provider.ExecutionAuthority)
        result = _provider_input(observation.result, provider.CapabilityResult)
        provider.admit_request(request, authority, frozenset({provider.Operation.INSPECT}))
        provider.admit_result(request, result)
        if (request.operation is not provider.Operation.INSPECT
                or host_resource(request.target) != resource
                or result.outcome is not provider.Outcome.OBSERVED):
            raise EnrollmentError("provider-binding")
    except provider.ContractError:
        raise EnrollmentError("provider-binding") from None
    if inspection_target is not None:
        inspection_target = _provider_target(inspection_target)
        if (inspection_target.expected_version is not None
                and request.target != inspection_target):
            raise EnrollmentError("provider-inspection-precondition")
    _machine(observation.machine)
    _uuid(observation.incarnation_id)
    if ("incarnation_id" in document
            and document["incarnation_id"] != observation.incarnation_id):
        raise EnrollmentError("host-incarnation-binding")
    if (observation.machine != document["machine"]
            or observation.request_digest != digest(document)
            or type(observation.observed_at) is not int
            or not 0 <= at - observation.observed_at <= MAX_OBSERVATION_AGE):
        raise EnrollmentError("management-binding")


def _observe_control(callback, document, deployment_id, resource, role,
                     *, inspection_target=None):
    if not callable(callback):
        raise EnrollmentError("authenticated-observation-required")
    try:
        observation = callback(document)
    except Exception:
        raise EnrollmentError("observe-provider-management") from None
    admit_management(document, observation, deployment_id, resource, role, now(),
                     inspection_target=inspection_target)
    return observation


class EnrollmentVerifier:
    """Public trust only. Caller owns fresh challenge and bounded Activation authority."""

    def __init__(self, directory, certificate, deployment_id, resource, role,
                 *, observe, current):
        _scope(deployment_id, resource, role)
        self.directory = Path(directory)
        if not self.directory.exists():
            _ancestry(self.directory.parent)
            try:
                self.directory.mkdir(mode=0o700)
            except OSError:
                raise EnrollmentError("verifier-directory") from None
        _directory(self.directory)
        self.certificate = Path(certificate)
        _ca(self.certificate)
        self.inspection_target = resource
        self.deployment_id, self.resource, self.role = deployment_id, host_resource(resource), role
        self.observe, self.current = observe, current

    def verify(self, credential, challenge, proof):
        if type(challenge) is not bytes or len(challenge) != 32:
            raise EnrollmentError("challenge-format")
        _closed(credential, {"grant", "certificate"}, "credential-fields")
        grant = credential["grant"]
        payload = _grant(grant, self.certificate, self.directory)
        identity = _admit_certificate(credential["certificate"], grant,
                                      self.certificate, self.directory)
        return self.authenticate(identity, challenge, proof)

    def authenticate(self, identity, challenge, proof):
        """Fresh possession of a registered key; bootstrap certificate may expire."""
        if type(challenge) is not bytes or len(challenge) != 32:
            raise EnrollmentError("challenge-format")
        _closed(identity, {"state", "host_id", "deployment_id", "resource", "role",
                           "generation", "public_key_sha256", "grant_id",
                           "certificate_sha256", "incarnation_id"}, "identity-format")
        if identity["state"] != "ENROLLED":
            raise EnrollmentError("not-enrolled")
        _uuid(identity["host_id"])
        if not callable(self.current):
            raise EnrollmentError("current-enrollment-required")
        try:
            current = self.current(identity["host_id"])
        except Exception:
            raise EnrollmentError("observe-current-enrollment") from None
        registered, public = admit_registration(current, self.certificate, self.directory)
        if canonical(registered) != canonical(identity):
            raise EnrollmentError("identity-not-current")
        message = b"SecPal Enrolled Host Possession v1\n" + canonical(identity) + challenge
        _verify(public, message, proof, self.directory)
        document = {**identity, "machine": current["machine"],
                    "challenge": base64.b64encode(challenge).decode(), "proof": proof}
        _observe_control(self.observe, document, self.deployment_id, self.resource, self.role,
                                       inspection_target=self.inspection_target)
        return identity
