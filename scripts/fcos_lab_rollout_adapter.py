#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Authenticated adapter for the initial frontend-only FCOS lab rollout."""

import base64
from dataclasses import dataclass
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
        index, = re.findall(rf'^FRONTEND_DIGEST = "({DIGEST})"$', text, re.MULTILINE)
        source, = re.findall(r'^FRONTEND_SOURCE_COMMIT = "([a-f0-9]{40})"$', text, re.MULTILINE)
        return cls(index, source)


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


def private_file(directory, name):
    path = directory / name
    parent = directory.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077
            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or info.st_size > 65536):
        raise ValueError("invalid private adapter input")
    return path


def admit_source(repo, release):
    git(repo, "merge-base", "--is-ancestor", release.revision, "refs/remotes/release/main")
    if source_release(repo, release.revision) != release:
        raise ValueError("release fingerprint differs from protected source")
    return Frontend.from_source(git(repo, "show", f"{release.revision}:{RUNTIME_SOURCE}").decode())


def publisher_children(frontend):
    environment = {"PATH": "/usr/bin:/bin"}
    with tempfile.TemporaryDirectory(prefix="fcos-lab-image-") as temporary:
        path = Path(temporary)
        environment.update(
            HOME=temporary, GH_CONFIG_DIR=temporary, GH_PROMPT_DISABLED="1",
            GH_NO_UPDATE_NOTIFIER="1", GH_NO_EXTENSION_UPDATE_NOTIFIER="1", GH_TELEMETRY="false",
        )
        gh = TOOLS / "gh"
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
        index, bundle = path / "index.json", path / "bundle.json"
        subprocess.run(
            [sys.executable, "-I", str(TOOLS / "fetch-oci-attestation.py"), index, bundle,
             IMAGE, frontend.index, "secpal/frontend"],
            env=environment, check=True, timeout=150, stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [gh, "attestation", "verify", index, "--bundle", bundle, "--repo", "SecPal/frontend",
             "--signer-workflow", "SecPal/frontend/.github/workflows/publish-container.yml",
             "--source-ref", "refs/heads/main", "--source-digest", frontend.source,
             "--signer-digest", frontend.source, "--deny-self-hosted-runners", "--hostname", "github.com"],
            env=environment, check=True, timeout=120, stdout=subprocess.DEVNULL,
        )
        subject = index.read_bytes()
        return native_children(subject), subject, bundle.read_bytes()


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
        if operation == "prepare":
            repo = Path(os.environ["SECPAL_ROLLOUT_STATE"]) / "release.git"
            frontend = admit_source(repo, release)
            prior = admit_source(repo, previous)
            if frontend.index == prior.index:
                return 1
            message = prepare_request(host, platform, release, previous, publisher_children(frontend))
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
                return 1
            try:
                health(domain, address, settings, release)
            except (OSError, ValueError, KeyError, StopIteration, http.client.HTTPException):
                return 10
        result = subprocess.run(ssh, input=message, timeout=840, check=False)
        if operation == "rollback" and result.returncode == 0:
            health(domain, address, settings, previous)
        return result.returncode
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RolloutError,
            http.client.HTTPException, subprocess.SubprocessError):
        print("FCOS lab adapter failed closed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.umask(0o077)
    sys.exit(main())
