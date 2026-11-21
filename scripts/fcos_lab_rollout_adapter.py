#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Authenticated adapter for FCOS lab frontend and backend rollouts."""

import ast
import base64
from dataclasses import asdict, dataclass
import hashlib
import http.client
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
from platform import machine
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import unquote
from urllib.request import (
    HTTPRedirectHandler, HTTPSHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener,
)
from uuid import UUID

# The coordinator invokes the installed script in Python isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fcos_lab_rollout import HOSTS, Release, RolloutError, git, source_release
from image_attestation_runtime import EXPECTED_GH_VERSION

DIGEST = r"sha256:[0-9a-f]{64}"
IMAGE = "ghcr.io/secpal/frontend"
API_IMAGE = "ghcr.io/secpal/api"
OPERATIONS = {"observe", "prepare", "activate", "accept", "rollback"}
RUNTIME_SOURCE = "scripts/integration_runtime_contract.py"
PRIVATE = Path.home() / ".config/secpal-fcos-lab-rollout"
TOOLS = Path(__file__).resolve().parent
ED25519_WIRE_PREFIX = b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
PRIVATE_IPV4 = tuple(map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


@dataclass(frozen=True)
class Frontend:
    index: str
    source: str

    @classmethod
    def from_source(cls, text):
        prefix = "LAB_" if re.search(r"^LAB_FRONTEND_(DIGEST|SOURCE_COMMIT)[ \t]*=", text, re.MULTILINE) else ""
        index, = re.findall(rf'^{prefix}FRONTEND_DIGEST = "({DIGEST})"$', text, re.MULTILINE)
        source, = re.findall(rf'^{prefix}FRONTEND_SOURCE_COMMIT = "([a-f0-9]{{40}})"$', text, re.MULTILINE)
        return cls(index, source)


@dataclass(frozen=True)
class Backend:
    source: str
    nginx: str
    fpm: str
    pair: str
    expires: str
    compatibility: str | None

    @classmethod
    def from_source(cls, text):
        fields = {"API_SOURCE_COMMIT": "[a-f0-9]{40}", "API_DIGEST": DIGEST,
                  "PHP_FPM_DIGEST": DIGEST, "API_PAIR_DIGEST": DIGEST,
                  "API_VEX_EXPIRES_AT": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z"}
        overlay = any(re.search(rf"^LAB_{name}[ \t]*=", text, re.MULTILINE) for name in fields)
        values = []
        for name, pattern in fields.items():
            identifier = ("LAB_" if overlay else "") + name
            value, = re.findall(rf'^{identifier} = "({pattern})"$', text, re.MULTILINE)
            values.append(value)
        if len(set(values[1:4])) != 3:
            raise ValueError("backend pair and indexes must be distinct")
        records = re.findall(r"^LAB_API_COMPATIBILITY_SHA256[ \t]*=.*$", text, re.MULTILINE)
        compatibility = None
        if records:
            record, = records
            compatibility, = re.findall(r'^LAB_API_COMPATIBILITY_SHA256 = "([a-f0-9]{64})"$', record)
        return cls(*values, compatibility)


def native_children(data):
    children = {}
    allowed = {"image": "application/vnd.oci.image.manifest.v1+json",
               "docker": "application/vnd.docker.distribution.manifest.v2+json"}
    for entry in json.loads(data)["manifests"]:
        platform = entry.get("platform", {})
        name = f'{platform.get("os")}/{platform.get("architecture")}'
        if name not in HOSTS.values():
            continue
        digest = entry["digest"]
        if (name in children or entry["mediaType"] not in allowed.values()
                or re.fullmatch(DIGEST, digest) is None):
            raise ValueError("invalid native OCI child")
        children[name] = digest
    if set(children) != set(HOSTS.values()) or len(set(children.values())) != 2:
        raise ValueError("both native OCI children are required")
    return children


def ssh_arguments(host, address, directory):
    if host not in HOSTS or not any(ipaddress.IPv4Address(address) in block for block in PRIVATE_IPV4):
        raise ValueError("not a lab guest")
    return [
        "/usr/bin/ssh", "-F", "/dev/null", "-T",
        "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
        "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "BatchMode=yes",
        "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
        "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
        "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
        "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"UserKnownHostsFile={directory / (host + '.known_hosts')}",
        "-o", f"HostKeyAlias={host}", "-i", str(directory / "rollout_ed25519"),
        f"secpal-lab-rollout@{address}",
    ]


def check_host_pin(host, contents):
    if host not in HOSTS:
        raise ValueError("unknown SSH host alias")
    row = re.fullmatch(host.encode("ascii") + rb" ssh-ed25519 ([A-Za-z0-9+/]{68})\n", contents)
    if row is None or not base64.b64decode(row[1], validate=True).startswith(ED25519_WIRE_PREFIX):
        raise ValueError("expected one exact ED25519 host pin")


def request_line(operation, host, platform, candidate, previous, child=None):
    if operation not in OPERATIONS or HOSTS.get(host) != platform:
        raise ValueError("invalid guest operation or identity")
    if (operation == "prepare" and (not child or re.fullmatch(DIGEST, child) is None)
            or operation != "prepare" and child is not None):
        raise ValueError("invalid native child parameter")
    return (" ".join((operation, host, platform, candidate.revision, candidate.fingerprint,
                      previous.revision, previous.fingerprint, child or "-")) + "\n").encode("ascii")


def prepare_request(host, platform, candidate, previous, proof):
    children, index, bundle = proof
    message = (request_line("prepare", host, platform, candidate, previous, children[platform])
               + base64.b64encode(index) + b"\n" + base64.b64encode(bundle) + b"\n")
    if len(message) > 2 * 1024 * 1024:
        raise ValueError("publisher evidence is too large")
    return message


def backend_request(host, platform, candidate, previous, pair, proof):
    message = request_line("prepare", host, platform, candidate, previous, pair)
    if len(proof) != 7 or not all(proof):
        raise ValueError("incomplete backend pair proof")
    message += b"".join(base64.b64encode(document) + b"\n" for document in proof)
    if len(message) > 2 * 1024 * 1024:
        raise ValueError("publisher evidence is too large")
    return message


def private_file(directory, name):
    path = directory / name
    parent = directory.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077
            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or info.st_size > 65536):
        raise ValueError("invalid private adapter input")
    return path


def admit_source_text(repo, release):
    git(repo, "merge-base", "--is-ancestor", release.revision, "refs/remotes/release/main")
    if source_release(repo, release.revision) != release:
        raise ValueError("release fingerprint differs from protected source")
    return git(repo, "show", f"{release.revision}:{RUNTIME_SOURCE}").decode()


def backend_declaration(declaration, helper):
    stages = set(re.findall(r"\bbackend_step ([a-z][a-z-]+) ", helper))
    required = {"pair-proof", "native-image", "fpm-migrations", "fpm-config", "nginx-config",
                "compatibility-evidence", "rollback-compatibility",
                "database-snapshot", "quadlet-validation", "stop-http", "stop-backend",
                "install-images", "reload-units", "start-fpm", "start-http", "start-background",
                "running-identities", "guest-health", "helper-identity"}
    if stages != required:
        raise ValueError("backend diagnostic coverage differs from the closed operation set")
    if any(entry["id"].startswith("fcos-lab-backend.") for entry in declaration["external_operations"]):
        raise ValueError("backend diagnostic scope is already declared")
    for stage in sorted(stages | {"controller-dispatch", "publisher-read", "guest-transport", "https-health"}):
        identifier = "fcos-lab-backend." + stage
        declaration["external_operations"].append({
            "id": identifier, "reachable": True, "fallible": True, "trusted": True,
            "diagnostic_identity": {"id": identifier, "kind": "semantic"},
        })
    return declaration


def verify_dispatch_authority(validator, renderer):
    try:
        source_tree = ast.parse(renderer)
    except SyntaxError as error:
        raise ValueError("invalid canonical dispatch source record") from error
    definitions = [
        node.value for node in source_tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "VALIDATOR_SOURCE" for target in node.targets)
    ]
    record, = definitions
    pins = ast.literal_eval(record)
    if not isinstance(pins, dict) or "scripts/secpal-evidence-architecture.py" not in pins:
        raise ValueError("canonical dispatch source pins are missing")
    checkout = validator.parent.parent
    for name, digest in pins.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or not re.fullmatch("[a-f0-9]{64}", digest):
            raise ValueError("invalid canonical dispatch source pin")
        path = checkout / relative
        if not path.is_file() or path.resolve(strict=True) != path:
            raise ValueError("canonical dispatch source path differs")
        with path.open("rb") as source:
            content = source.read(65537)
        if len(content) > 65536 or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("canonical dispatch source differs from the accepted pin")


def admit_backend_dispatch(repo, release):
    validator = TOOLS / "evidence-architecture/scripts/secpal-evidence-architecture.py"
    if not validator.is_file() or validator.is_symlink():
        raise ValueError("installed backend dispatch validator is unavailable")
    validator = validator.resolve(strict=True)
    verify_dispatch_authority(
        validator, git(repo, "show", f"{release.revision}:scripts/render-fcos-application-poc.py"),
    )
    with tempfile.TemporaryDirectory(prefix="fcos-lab-dispatch-") as directory:
        root = Path(directory)
        (root / "AGENTS.md").write_bytes(git(repo, "show", f"{release.revision}:AGENTS.md"))
        declaration_path = ".secpal/evidence-architecture.json"
        declaration = backend_declaration(
            json.loads(git(repo, "show", f"{release.revision}:{declaration_path}")),
            git(repo, "show", f"{release.revision}:scripts/fcos-lab-rollout-guest.sh").decode(),
        )
        (root / ".secpal").mkdir()
        (root / declaration_path).write_text(json.dumps(declaration), encoding="utf-8")
        subprocess.run([sys.executable, "-I", "-S", validator, "--repository-root", root,
                        "--repository", "SecPal/deployment", "--dispatch"],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=60)


def backend_diagnostic(stage):
    print(f"FCOS lab backend operation failed: fcos-lab-backend.{stage}", file=sys.stderr)


def verify_attestation(gh, subject, bundle, source, environment, product):
    subprocess.run(
        [gh, "attestation", "verify", subject, "--bundle", bundle, "--repo", f"SecPal/{product}",
         "--signer-workflow", f"SecPal/{product}/.github/workflows/publish-container.yml",
         "--source-ref", "refs/heads/main", "--source-digest", source,
         "--signer-digest", source, "--deny-self-hosted-runners", "--hostname", "github.com"],
        env=environment, check=True, timeout=120, stdout=subprocess.DEVNULL,
    )

def verify_frontend_attestation(gh, subject, bundle, source, environment):
    verify_attestation(gh, subject, bundle, source, environment, "frontend")


def verified_gh(gh, environment):
    local_platform = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}[machine()]
    expected, = (
        line.split()[1] for line in
        Path(__file__).with_name("fcos-lab-gh-binary-sha256.txt").read_text(encoding="ascii").splitlines()
        if line.startswith(local_platform + " ")
    )
    with gh.open("rb") as executable:
        if hashlib.file_digest(executable, "sha256").hexdigest() != expected:
            raise ValueError("wrong GitHub CLI executable digest")
    version = subprocess.check_output([gh, "--version"], timeout=15, env=environment).splitlines()[0]
    if not version.startswith(f"gh version {EXPECTED_GH_VERSION} ".encode()):
        raise ValueError("wrong GitHub CLI version")


def publisher_children(frontend, *, gh=None):
    environment = {"PATH": "/usr/bin:/bin"}
    with tempfile.TemporaryDirectory(prefix="fcos-lab-image-") as temporary:
        path = Path(temporary)
        environment.update(
            HOME=temporary, GH_CONFIG_DIR=temporary, GH_PROMPT_DISABLED="1",
            GH_NO_UPDATE_NOTIFIER="1", GH_NO_EXTENSION_UPDATE_NOTIFIER="1", GH_TELEMETRY="false",
        )
        gh = Path(gh) if gh else TOOLS / "gh"
        verified_gh(gh, environment)
        index, bundle = path / "index.json", path / "bundle.json"
        subprocess.run(
            [sys.executable, "-I", str(TOOLS / "fetch-oci-attestation.py"), index, bundle,
             IMAGE, frontend.index, "secpal/frontend"],
            env=environment, check=True, timeout=150, stdout=subprocess.DEVNULL,
        )
        verify_frontend_attestation(gh, index, bundle, frontend.source, environment)
        subject = index.read_bytes()
        return native_children(subject), subject, bundle.read_bytes()


def backend_proof(backend, *, gh=None):
    with tempfile.TemporaryDirectory(prefix="fcos-lab-pair-") as temporary:
        root = Path(temporary)
        environment = {"PATH": "/usr/bin:/bin", "HOME": temporary, "GH_CONFIG_DIR": temporary,
                       "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_TELEMETRY": "false"}
        gh = Path(gh) if gh else TOOLS / "gh"
        verified_gh(gh, environment)

        def fetch(role, digest, *options):
            subject, bundle = root / (role + ".json"), root / (role + ".bundle.json")
            subprocess.run([sys.executable, "-I", str(TOOLS / "fetch-oci-attestation.py"), subject, bundle,
                            API_IMAGE, digest, "secpal/api", *options], env=environment, check=True,
                           timeout=150, stdout=subprocess.DEVNULL)
            verify_attestation(gh, subject, bundle, backend.source, environment, "api")
            return subject.read_bytes(), bundle.read_bytes()

        document_path = root / "runtime-pair.json"
        binding = asdict(backend)
        del binding["pair"]
        pair = fetch("pair", backend.pair, "--runtime-pair-output", document_path,
                     "--reviewed-lab-runtime-pair", json.dumps(binding))
        document = document_path.read_bytes()
        images = json.loads(document)["images"]
        fpm = fetch("php-fpm", backend.fpm)
        nginx = fetch("nginx", backend.nginx)
        for role, subject in (("php-fpm", fpm[0]), ("nginx", nginx[0])):
            subjects = images[role]["platforms"]
            if len(subjects) != 2 or {p["platform"]: p["manifest_digest"] for p in subjects} != native_children(subject):
                raise ValueError("native indexes do not match the signed runtime pair")
        return (*pair, document, *fpm, *nginx)


class Network(HTTPSHandler):
    def __init__(self, address):
        super().__init__(context=ssl.create_default_context())
        self.address = address

    def https_open(self, req):
        address = self.address

        class Connection(http.client.HTTPSConnection):
            def connect(self):
                with_socket = socket.create_connection((address, 443), self.timeout)
                try:
                    self.sock = self._context.wrap_socket(with_socket, server_hostname=self.host)
                except BaseException:
                    with_socket.close()
                    raise

        return self.do_open(Connection, req, context=self._context)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def release_witness(request, api, record, fingerprint):
    collection = "/v1/organizational-units"
    path = f"{collection}/{record}"
    parent = json.loads(request(api, path, 200))["data"]
    if parent["id"] != record or parent["name"] != "FCOS lab rollout witness":
        raise ValueError("organisation is not the designated synthetic witness")
    name = f"FCOS rollout receipt {fingerprint}"

    def descendants():
        values = json.loads(request(api, path + "/descendants", 200))["data"]
        present = [item for item in values if item["name"] == name]
        if len(present) > 1 or (present and present[0]["type"] != "company"):
            raise ValueError("ambiguous synthetic rollout receipt")
        return str(UUID(present[0]["id"])) if present else None

    if descendants() is None:
        request(api, "/sanctum/csrf-cookie", 204)
        response = json.loads(request(api, collection, 201, method="POST",
                                      data={"type": "company", "name": name, "parent_id": record}))
        created = str(UUID(response["data"]["id"]))
        if descendants() != created:
            raise ValueError("synthetic rollout receipt did not persist under the witness")


def health(domain, address, settings, release):
    if set(settings) != {"email", "password", "organisation"}:
        raise ValueError("invalid synthetic witness configuration")
    record = str(UUID(settings["organisation"]))
    app = f"https://app.{domain}"
    api = f"https://api.{domain}"
    cookies = http.cookiejar.CookieJar()
    client = build_opener(ProxyHandler({}), NoRedirect(), Network(address), HTTPCookieProcessor(cookies))

    def request(site, path, status, *, method="GET", data=None):
        headers = {"Accept": "application/json", "Origin": app, "Referer": app + "/"}
        if data is not None:
            headers["Content-Type"] = "application/json"
            headers["X-XSRF-TOKEN"] = next(unquote(c.value) for c in cookies if c.name == "XSRF-TOKEN")
        outgoing = Request(site + path, headers=headers, method=method,
                           data=None if data is None else json.dumps(data).encode())
        try:
            response = client.open(outgoing, timeout=12)
        except HTTPError as error:
            response = error
        with response:
            body = response.read(524289)
            if response.status != status or len(body) > 524288:
                raise ValueError("unexpected HTTPS response")
            return body

    for attempt in range(4):
        try:
            request(app, "/login", 200)
            request(api, "/health/ready", 200)
            break
        except (OSError, ValueError):
            if attempt == 3:
                raise
            time.sleep(3)

    # A fixed inert marker exercises CRS inspection. A healthy API alone
    # cannot satisfy this check.
    request(api, "/health/ready?q=%3Cscript%3Esecpal-rollout-probe%3C%2Fscript%3E", 403)
    request(api, "/v1/me", 401)
    request(api, "/sanctum/csrf-cookie", 204)
    request(api, "/v1/auth/login", 200, method="POST",
            data={"email": settings["email"], "password": settings["password"]})
    request(api, "/v1/me", 200)
    release_witness(request, api, record, release.fingerprint)


def main():
    try:
        operation, host, platform, revision, fingerprint, old_revision, old_fingerprint = sys.argv[1:]
        release = Release(revision, fingerprint)
        previous = Release(old_revision, old_fingerprint)
        if operation not in OPERATIONS or host not in HOSTS or platform != HOSTS[host]:
            return 1
        config = json.loads(private_file(PRIVATE, "hosts.json").read_text(encoding="utf-8"))
        if set(config) != set(HOSTS) or any(set(item) != {"address", "domain"} for item in config.values()):
            return 1
        if len({item["address"] for item in config.values()}) != len(HOSTS):
            return 1
        address, domain = config[host]["address"], config[host]["domain"]
        if not re.fullmatch(rf"{host}(?:\.[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?){{2,4}}", domain):
            return 1
        check_host_pin(host, private_file(PRIVATE, host + ".known_hosts").read_bytes())
        private_file(PRIVATE, "rollout_ed25519")
        ssh = ssh_arguments(host, address, PRIVATE)
        backend_change = False
        if operation != "observe":
            repo = Path(os.environ["SECPAL_ROLLOUT_STATE"]) / "release.git"
            source = admit_source_text(repo, release)
            prior = admit_source_text(repo, previous)
            backend, old_backend = Backend.from_source(source), Backend.from_source(prior)
            backend_change = backend != old_backend
            if backend_change:
                try:
                    if backend.compatibility is None:
                        raise ValueError("backend compatibility record is required")
                    admit_backend_dispatch(repo, release)
                except (OSError, ValueError, KeyError, TypeError, RolloutError, subprocess.SubprocessError):
                    backend_diagnostic("controller-dispatch")
                    return 1
        if operation == "prepare":
            frontend, old_frontend = Frontend.from_source(source), Frontend.from_source(prior)
            if backend != old_backend and frontend == old_frontend:
                if backend.pair == old_backend.pair or (backend.fpm, backend.nginx) == (old_backend.fpm, old_backend.nginx):
                    return 1
                try:
                    message = backend_request(host, platform, release, previous, backend.pair, backend_proof(backend))
                except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                    backend_diagnostic("publisher-read")
                    return 1
            elif backend == old_backend and frontend.index != old_frontend.index:
                message = prepare_request(host, platform, release, previous, publisher_children(frontend))
            else:
                return 1
        else:
            message = request_line(operation, host, platform, release, previous)
        if operation in {"accept", "rollback"}:
            settings = json.loads(private_file(PRIVATE, host + ".health.json").read_text(encoding="utf-8"))
        if operation == "accept":
            checked = subprocess.run(
                ssh, input=request_line("observe", host, platform, release, previous),
                stdout=subprocess.PIPE, timeout=30, check=False,
            )
            if checked.returncode or checked.stdout != (release.fingerprint + "\n").encode():
                if backend_change:
                    backend_diagnostic("guest-transport")
                return 1
            try:
                health(domain, address, settings, release)
            except (OSError, ValueError, KeyError, StopIteration, http.client.HTTPException):
                if backend_change:
                    backend_diagnostic("https-health")
                return 10
        result = subprocess.run(ssh, input=message, timeout=840, check=False)
        if operation == "rollback" and result.returncode == 0:
            try:
                health(domain, address, settings, previous)
            except (OSError, ValueError, KeyError, StopIteration, http.client.HTTPException):
                if backend_change:
                    backend_diagnostic("https-health")
                return 1
        if backend_change and result.returncode:
            backend_diagnostic("guest-transport")
        return result.returncode
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RolloutError,
            http.client.HTTPException, subprocess.SubprocessError):
        print("FCOS lab adapter failed closed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.umask(0o077)
    sys.exit(main())
