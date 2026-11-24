#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Authenticated adapter for FCOS lab frontend and backend rollouts."""

import ast
import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import http.client
import http.cookiejar
import ipaddress
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
from platform import machine
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import unquote
from urllib.request import (
    HTTPRedirectHandler, HTTPSHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener,
)
from uuid import UUID
from zipfile import BadZipFile, ZipFile

# The coordinator invokes the installed script in Python isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fcos_lab_rollout import HOSTS, RUNTIME_SOURCE, Release, RolloutError, git, source_release
from image_attestation_runtime import EXPECTED_GH_VERSION

DIGEST = r"sha256:[0-9a-f]{64}"
IMAGE = "ghcr.io/secpal/frontend"
API_IMAGE = "ghcr.io/secpal/api"
API_ARCHIVE = "oci-archive-v1"
FRONTEND_ARCHIVE = "oci-archive-v1 frontend"
ARCHIVE_MAX = 150_000_000
OPERATIONS = {"observe", "prepare", "activate", "accept", "rollback"}
PRIVATE = Path.home() / ".config/secpal-fcos-lab-rollout"
TOOLS = Path(__file__).resolve().parent
ED25519_WIRE_PREFIX = b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
PRIVATE_IPV4 = tuple(map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


@dataclass(frozen=True)
class Frontend:
    index: str
    source: str
    transport: str = "registry"

    @classmethod
    def from_source(cls, text):
        prefix = "LAB_" if re.search(r"^LAB_FRONTEND_(DIGEST|SOURCE_COMMIT)[ \t]*=", text, re.MULTILINE) else ""
        index, = re.findall(rf'^{prefix}FRONTEND_DIGEST = "({DIGEST})"$', text, re.MULTILINE)
        source, = re.findall(rf'^{prefix}FRONTEND_SOURCE_COMMIT = "([a-f0-9]{{40}})"$', text, re.MULTILINE)
        modes = re.findall(r"^LAB_FRONTEND_TRANSPORT[ \t]*=.*$", text, re.MULTILINE)
        if modes and (not prefix or modes != ['LAB_FRONTEND_TRANSPORT = "oci-archive-v1"']):
            raise ValueError("invalid archived frontend transport pin")
        return cls(index, source, FRONTEND_ARCHIVE if modes else "registry")


@dataclass(frozen=True)
class Backend:
    source: str
    nginx: str
    fpm: str
    pair: str
    expires: str
    compatibility: str | None = field(compare=False)
    transport: str = "registry"

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
        modes = re.findall(r"^LAB_API_TRANSPORT[ \t]*=.*$", text, re.MULTILINE)
        if modes and (not overlay or modes != [f'LAB_API_TRANSPORT = "{API_ARCHIVE}"']):
            raise ValueError("invalid archived API transport pin")
        return cls(*values, compatibility, API_ARCHIVE if modes else "registry")


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
    protected = source_release(repo, release.revision)
    if (protected.revision, protected.fingerprint) != (release.revision, release.fingerprint):
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


def verify_attestation(gh, subject, bundle, source, environment, product, *, report=False):
    output = ["--format", "json"] if report else []
    result = subprocess.run(
        [gh, "attestation", "verify", subject, "--bundle", bundle, "--repo", f"SecPal/{product}",
         "--signer-workflow", f"SecPal/{product}/.github/workflows/publish-container.yml",
         "--source-ref", "refs/heads/main", "--source-digest", source,
         "--signer-digest", source, "--deny-self-hosted-runners", "--hostname", "github.com", *output],
        env=environment, check=True, timeout=120, stdout=subprocess.PIPE if report else subprocess.DEVNULL,
    )
    if report:
        return json.loads(result.stdout)


def require_source_security(report, product, source):
    database = report["database"]
    now = datetime.now(timezone.utc)
    if (report.get("schema_version") != "secpal-trivy-repository-scan-v5"
            or report["subject"] != {"repository": f"SecPal/{product}", "commit": source}
            or report["operation"] != {"name": "TRIVY_REPOSITORY_SCAN", "status": "SUCCEEDED"}
            or report["gate_state"] != "CLEAN" or database["status"] != "FRESH"
            or not datetime.fromisoformat(database["updated_at"]) <= now < datetime.fromisoformat(database["next_update"])):
        raise ValueError(f"{product} candidate source security is unavailable or stale")


def verify_frontend_candidate(directory, source, run, attempt, gh, environment, *, current=True):
    publisher = directory / "publisher"
    receipt = publisher / "pre-registry.json"
    bundle = publisher / "pre-registry.bundle.json"
    signer = verify_attestation(gh, receipt, bundle, source, environment, "frontend", report=True)
    result, = signer
    certificate = result["verificationResult"]["signature"]["certificate"]
    if certificate["runInvocationURI"] != f"https://github.com/SecPal/frontend/actions/runs/{run}/attempts/{attempt}":
        raise ValueError("frontend candidate belongs to another publisher invocation")

    def verify_json(path, expected, label):
        raw = path.read_bytes()
        if expected != "sha256:" + hashlib.sha256(raw).hexdigest():
            raise ValueError(f"frontend candidate {label} digest differs")
        return json.loads(raw)

    binding = json.loads(receipt.read_bytes())
    prepared = verify_json(publisher / "prepared.json", binding["candidate_sha256"], "prepared manifest")
    index = verify_json(publisher / "index.json", prepared["index_digest"], "OCI index")
    if current:
        require_source_security(json.loads((publisher / "source-security.json").read_bytes()), "frontend", source)
    records, inventories, results = prepared["records"], prepared["inventories"], binding["results"]
    if len(records) != len(set(HOSTS.values())) or index["schemaVersion"] != 2:
        raise ValueError("frontend candidate has an incomplete OCI index")
    children, evidence = {}, {}
    for descriptor, record, inventory, reported in zip(index["manifests"], records, inventories, results, strict=True):
        record_subject = record["subject"]
        platform = record_subject["platform"]
        arch = platform.removeprefix("linux/")
        digest = record_subject["manifest_digest"]
        key = "frontend", platform
        subject = {"platform": platform, "oci_digest": digest}
        if (platform not in HOSTS.values() or key in children or re.fullmatch(DIGEST, digest) is None
                or descriptor["platform"] != {"os": "linux", "architecture": arch}
                or descriptor["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
                or descriptor["digest"] != digest or record["runner_architecture"] != arch
                or record["source"]["repository"] != "https://github.com/SecPal/frontend"
                or record["source"]["commit"] != source or record["workflow_run_id"] != str(run)
                or record["workflow_run_attempt"] != str(attempt)
                or inventory["platform"] != platform or reported["subject"] != subject):
            raise ValueError("frontend candidate does not bind to an exact native runtime")
        scan = directory / "scan" / arch
        evaluation = verify_json(scan / "evaluation.json", reported["evaluation_sha256"], "evaluation")
        policy = verify_json(scan / "policy-result.json", reported["policy_sha256"], "policy result")
        if (evaluation["subject"] != subject or policy["subject"] != subject
                or policy["syft"] != evaluation["syft"] or evaluation["syft"]["spdx_digest"] != inventory["spdx_sha256"]
                or policy["evidence_health"]["state"] != "HEALTHY"
                or policy["gate_state"] not in {"CLEAN", "REVIEW_REQUIRED", "ACTIONABLE"}):
            raise ValueError("frontend candidate scan evidence differs from the qualified OCI subject")
        children[key], evidence[key] = digest, evaluation
    return children, evidence


def verify_api_candidate(directory, source, gh, environment, *, current=True, selected=None):
    """Verify the existing Actions qualification and evaluation subjects."""
    if re.fullmatch(r"[a-f0-9]{40}", source) is None:
        raise ValueError("invalid candidate source")
    receipt = directory / "unpublished-runtime-pair.json"
    bundle = directory / "bundle.jsonl"
    if not bundle.is_file() or bundle.is_symlink():
        raise ValueError("missing signed API candidate bundle")
    report = verify_attestation(gh, receipt, bundle, source, environment, "api", report=True)
    pair = json.loads(receipt.read_bytes())
    workflow = pair["workflow"]
    run, attempt = workflow["run_id"], workflow["run_attempt"]
    if (pair["source"]["repository"] != "https://github.com/SecPal/api" or pair["source"]["commit"] != source
            or pair["published"] is not False or pair["qualification"] != "SUCCEEDED"
            or workflow["repository"] != "SecPal/api" or workflow["path"] != ".github/workflows/container-image.yml"
            or any(re.fullmatch(r"[1-9][0-9]*", value) is None for value in (run, attempt))):
        raise ValueError("API candidate identity differs from the qualified source")
    def publisher_invocation(results):
        found = {entry["verificationResult"]["signature"]["certificate"]["runInvocationURI"] for entry in results}
        if len(found) != 1:
            raise ValueError("ambiguous API candidate attestation attempt")
        return found.pop()

    invocation = publisher_invocation(report)
    signed = re.fullmatch(rf"https://github.com/SecPal/api/actions/runs/{run}/attempts/([1-9][0-9]*)", invocation)
    if signed is None or int(signed[1]) < int(attempt):
        raise ValueError("API candidate evidence belongs to another publisher attempt")
    if selected is not None and (int(run), int(signed[1])) != selected:
        raise ValueError("API candidate evidence differs from the selected Actions run and attempt")

    def read_signed(name):
        path = directory / name
        observed = verify_attestation(gh, path, bundle, source, environment, "api", report=True)
        if publisher_invocation(observed) != invocation:
            raise ValueError("API candidate evidence belongs to another publisher attempt")
        return json.loads(path.read_bytes())

    source_security = read_signed("source-security.json")
    if current:
        require_source_security(source_security, "api", source)
    if set(pair["images"]) != {"php-fpm", "nginx"}:
        raise ValueError("incomplete qualified API runtime pair")
    children, evidence = {}, {}
    for role, image in pair["images"].items():
        platforms = image["platforms"]
        if len(platforms) != 2 or {item["subject"]["platform"] for item in platforms} != set(HOSTS.values()):
            raise ValueError("incomplete API candidate platforms")
        for item in platforms:
            platform, digest = item["subject"]["platform"], item["subject"]["manifest_digest"]
            key = role, platform
            evaluation = read_signed(f"{role}/{platform.split('/')[1]}/evaluation.json")
            if (re.fullmatch(DIGEST, digest) is None
                    or evaluation["subject"] != {"platform": platform, "oci_digest": digest}
                    or evaluation["syft"]["spdx_digest"] != item["sbom_sha256"]
                    or item["smoke"]["result"] != "SUCCEEDED"
                    or item["smoke"]["digest"] != digest or item["smoke"]["workflow_run_id"] != run):
                raise ValueError("API candidate evidence differs from the qualified OCI subject")
            children[key], evidence[key] = digest, evaluation
    return children, evidence


def github_json(gh, endpoint):
    return json.loads(subprocess.check_output(
        [gh, "api", "--hostname", "github.com", "--method", "GET", endpoint],
        stdin=subprocess.DEVNULL, timeout=30,
    ))


def download_publisher_artifact(gh, product, run, source, name, output, limit):
    if product not in {"api", "frontend"}:
        raise ValueError("unknown OCI publisher")
    prefix = f"repos/SecPal/{product}/actions"
    data = github_json(gh, f"{prefix}/runs/{run}/artifacts?name={name}&per_page=2")
    artifact, = data["artifacts"]
    artifact_id, advertised = artifact["id"], artifact["size_in_bytes"]
    if (artifact["name"] != name or artifact["expired"] is not False
            or artifact["workflow_run"]["id"] != run or artifact["workflow_run"]["head_sha"] != source
            or artifact["workflow_run"]["head_branch"] != "main"
            or type(artifact_id) is not int or artifact_id <= 0
            or type(advertised) is not int or not 0 < advertised <= limit
            or re.fullmatch(DIGEST, artifact["digest"]) is None):
        raise ValueError("candidate archive metadata differs")
    archive = output.with_suffix(".zip")
    with archive.open("xb") as target:
        subprocess.run([gh, "api", "--hostname", "github.com", "--method", "GET",
                        f"{prefix}/artifacts/{artifact_id}/zip"], stdin=subprocess.DEVNULL,
                       stdout=target, check=True, timeout=220)
    with archive.open("rb") as sealed:
        observed = "sha256:" + hashlib.file_digest(sealed, "sha256").hexdigest()
    if archive.stat().st_size > limit or observed != artifact["digest"]:
        raise ValueError("candidate archive digest differs")
    with ZipFile(archive) as contents:
        members = contents.infolist()
        if len(members) > 1024 or sum(entry.file_size for entry in members) > 3 * limit:
            raise ValueError("candidate archive too large")
        names = set()
        for entry in members:
            path = PurePosixPath(entry.filename)
            if (not path.parts or path.is_absolute() or ".." in path.parts
                    or str(path) != entry.filename.rstrip("/")
                    or stat.S_ISLNK(entry.external_attr >> 16) or path in names):
                raise ValueError("ambiguous candidate archive entry")
            names.add(path)
        output.mkdir(mode=0o700)
        contents.extractall(output)
    archive.unlink()


def api_archive_identity(backend, qualification):
    raw = (qualification / "unpublished-runtime-pair.json").read_bytes()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != backend.pair:
        raise ValueError("archived API pair differs from protected pins")
    pair = json.loads(raw)
    for role, index in (("nginx", backend.nginx), ("php-fpm", backend.fpm)):
        if pair["images"][role]["candidate_index_digest"] != index:
            raise ValueError("archived API index differs from protected pins")
    deadline = datetime.fromisoformat(
        json.loads((qualification / "source-security.json").read_bytes())["database"]["next_update"])
    if datetime.fromisoformat(backend.expires) > deadline:
        raise ValueError("archived API expiry exceeds signed source evidence")
    return pair


def make_oci_archive(layout, child, path):
    manifest = layout / "blobs" / "sha256" / child.removeprefix("sha256:")
    if "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest() != child:
        raise ValueError("archive lacks the approved OCI manifest")
    index = json.loads((layout / "index.json").read_bytes())
    descriptor, = index["manifests"]
    if descriptor["digest"] != child:
        raise ValueError("archive OCI descriptor differs from the signed native subject")
    with tarfile.open(path, "w") as packaged:
        for name in ("oci-layout", "index.json", "blobs"):
            packaged.add(layout / name, arcname=name)
    if not 0 < path.stat().st_size <= ARCHIVE_MAX:
        raise ValueError("native transport exceeds the guest limit")


def write_archive_request(output, transport, request, paths, images):
    proof = b"".join(base64.b64encode(path.read_bytes()) + b"\n" for path in paths)
    sizes = tuple(path.stat().st_size for path in images)
    expected = {API_ARCHIVE: (3, 2), FRONTEND_ARCHIVE: (4, 1)}
    if (expected.get(transport) != (len(paths), len(sizes)) or len(proof) > 2097152
            or not all(0 < size <= ARCHIVE_MAX for size in sizes)):
        raise ValueError("archived component input exceeds the guest limit")
    output.write(transport.encode() + b"\n")
    output.write(request)
    output.write(proof)
    output.write((" ".join(map(str, sizes)) + "\n").encode())
    for path in images:
        with path.open("rb") as image:
            shutil.copyfileobj(image, output)
    output.seek(0)


def write_backend_archive_request(output, host, platform, release, previous, backend, qualification, images):
    paths = tuple(qualification / name for name in (
        "unpublished-runtime-pair.json", "bundle.jsonl", "source-security.json"))
    request = request_line("prepare", host, platform, release, previous, backend.pair)
    write_archive_request(output, API_ARCHIVE, request, paths, images)


@contextmanager
def qualified_frontend_source(source, gh, *, current=True):
    if re.fullmatch(r"[a-f0-9]{40}", source) is None:
        raise ValueError("invalid protected frontend source")
    with tempfile.TemporaryDirectory(prefix="fcos-lab-archive-") as temporary:
        root = Path(temporary)
        environment = {"PATH": "/usr/bin:/bin", "HOME": temporary, "GH_CONFIG_DIR": temporary,
                       "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}
        verified_gh(gh, environment)
        prefix = "repos/SecPal/frontend/actions"
        workflow = ".github/workflows/publish-container.yml"
        listing = github_json(gh, f"{prefix}/workflows/publish-container.yml/runs"
                                 f"?branch=main&head_sha={source}&status=completed&per_page=20")
        for run in listing["workflow_runs"]:
            run_id, attempt = run["id"], run["run_attempt"]
            if (run["head_sha"] != source or run["head_branch"] != "main"
                    or run["head_repository"]["full_name"] != "SecPal/frontend"
                    or run["event"] not in {"push", "workflow_dispatch"} or run["path"] != workflow
                    or any(type(value) is not int or value < 1 for value in (run_id, attempt))):
                raise ValueError("archived frontend producer is outside protected main")
            invocation = f"{prefix}/runs/{run_id}"
            jobs = github_json(gh, f"{invocation}/attempts/{attempt}/jobs?per_page=100")
            required = {"Repository Security / Repository Security", "Validate Frontend Image",
                        "Authenticate protected-main publication or qualification",
                        "Qualify both exact unpublished OCI subjects",
                        "Build native Frontend candidates / Native frontend (amd64)",
                        "Build native Frontend candidates / Native frontend (arm64)",
                        "Build native Frontend candidates / Container Contract"}
            succeeded = {job["name"] for job in jobs["jobs"] if job["conclusion"] == "success"}
            failed = {job["name"] for job in jobs["jobs"] if job["conclusion"] not in {"success", "skipped"}}
            registry_jobs = {"Prepare exact digest subjects", "Attest candidate index platforms and Syft artifacts",
                             "Accept verified Frontend publication", "Published native runtime (amd64)",
                             "Published native runtime (arm64)", "Artifact security (amd64)", "Artifact security (arm64)"}
            registry_failure = run["event"] == "push" and run["conclusion"] == "failure" and bool(failed) and failed <= registry_jobs
            if required <= succeeded and (run["conclusion"] == "success" or registry_failure):
                break
        else:
            raise ValueError("no qualified frontend candidate for the protected source")
        qualification = root / "qualification"
        download_publisher_artifact(gh, "frontend", run_id, source,
                                    f"frontend-pre-registry-{run_id}-{attempt}", qualification, 8 * 1024**2)
        children, _ = verify_frontend_candidate(
            qualification, source, run_id, attempt, gh, environment, current=current,
        )
        publisher = qualification / "publisher"
        artifacts = github_json(gh, f"{invocation}/artifacts?per_page=100")["artifacts"]
        evidence_name, = (artifact["name"] for artifact in artifacts
                          if artifact["name"].startswith(f"trivy-repository-evidence-{run_id}-{attempt}-")
                          and artifact["expired"] is False)
        security = root / "repository-security"
        download_publisher_artifact(gh, "frontend", run_id, source,
                                    evidence_name, security, 8 * 1024**2)
        source_report = json.loads((security / "result.json").read_bytes())
        if source_report != json.loads((publisher / "source-security.json").read_bytes()):
            raise ValueError("frontend candidate source security differs from the independent job")
        proof = tuple(publisher / name for name in (
            "pre-registry.json", "pre-registry.bundle.json", "prepared.json", "index.json"))
        yield gh, run_id, attempt, children, proof, root



@contextmanager
def verified_frontend_archive(frontend, *, current=True):
    with qualified_frontend_source(frontend.source, TOOLS / "gh", current=current) as result:
        if "sha256:" + hashlib.sha256(result[4][-1].read_bytes()).hexdigest() != frontend.index:
            raise ValueError("archived frontend differs from the protected OCI pin")
        yield result

def prepare_archived_frontend(ssh, host, platform, release, previous, frontend):
    with verified_frontend_archive(frontend) as (gh, run_id, attempt, children, proof, root):
        native = root / "native"
        arch = platform.removeprefix("linux/")
        download_publisher_artifact(gh, "frontend", run_id, frontend.source,
                                    f"frontend-native-{arch}-{run_id}-{attempt}", native, ARCHIVE_MAX)
        archive = root / "frontend.tar"
        child = children["frontend", platform]
        make_oci_archive(native / "image", child, archive)
        with tempfile.TemporaryFile() as wire:
            request = request_line("prepare", host, platform, release, previous, child)
            write_archive_request(wire, FRONTEND_ARCHIVE, request, proof, [archive])
            return subprocess.run(ssh, stdin=wire, timeout=810, check=False).returncode


def archived_frontend_evidence(repo, release, previous, evidence_revision):
    candidate = Frontend.from_source(admit_source_text(repo, release))
    installed = Frontend.from_source(admit_source_text(repo, previous))
    if candidate.transport != FRONTEND_ARCHIVE:
        raise ValueError("frontend candidate transport was not selected by protected main")
    with verified_frontend_archive(candidate) as (_, _, _, proposed, _, _):
        pass
    if installed.transport == "registry":
        previous_children, _, _ = publisher_children(installed)
        active = {("frontend", platform): digest for platform, digest in previous_children.items()}
    else:
        with verified_frontend_archive(installed, current=False) as (_, _, _, active, _, _):
            pass

    return protected_comparison(repo, evidence_revision, "frontend", active, proposed)


def protected_comparison(repo, release, component, active, proposed):
    def evaluations(side):
        evidence = {}
        for role, platform in sorted(proposed):
            arch = platform.removeprefix("linux/")
            leaf = f"{arch}-{side}.json" if component == "frontend" else f"{role}-{arch}-{side}.json"
            path = f"config/quadlet/fcos-lab-rollout/{component}-security/{leaf}"
            entry = git(repo, "ls-tree", release.revision, "--", path)
            if not entry.startswith(b"100644 blob "):
                raise ValueError(f"missing protected {component} comparison evidence")
            size = int(git(repo, "cat-file", "-s", f"{release.revision}:{path}"))
            if not 0 < size <= 1024**2:
                raise ValueError(f"{component} comparison evidence exceeds the supported limit")
            evidence[role, platform] = json.loads(git(repo, "show", f"{release.revision}:{path}"))
        return evidence

    return {"installed": active, "proposed": proposed, "previous": evaluations("installed"),
            "candidate": evaluations("candidate"), "exposure_unchanged": True}


def archived_component_evidence(repo, release, previous, protected_main):
    source = admit_source_text(repo, release)
    earlier = admit_source_text(repo, previous)
    evidence_revision = release
    if release.fingerprint == protected_main.fingerprint:
        git(repo, "merge-base", "--is-ancestor", release.revision, protected_main.revision)
        admit_source_text(repo, protected_main)
        evidence_revision = protected_main
    candidate, installed = Backend.from_source(source), Backend.from_source(earlier)
    frontend, old_frontend = Frontend.from_source(source), Frontend.from_source(earlier)
    if candidate != installed and candidate.transport == API_ARCHIVE:
        if frontend != old_frontend or not candidate.compatibility:
            raise ValueError("archived API must preserve frontend and provide compatibility evidence")
        with verified_backend_archive(candidate) as (_, _, _, proposed, _, _, _):
            pass
        if installed.transport == "registry":
            active = installed_backend_children(installed)
        else:
            with verified_backend_archive(installed, current=False) as (_, _, _, active, _, _, _):
                pass
        return protected_comparison(repo, evidence_revision, "api", active, proposed)
    if frontend != old_frontend and frontend.transport == FRONTEND_ARCHIVE:
        if candidate != installed:
            raise ValueError("archived frontend cannot switch the API")
        return archived_frontend_evidence(repo, release, previous, evidence_revision)
    return None


@contextmanager
def qualified_backend_source(source, gh, *, current=True):
    if re.fullmatch(r"[a-f0-9]{40}", source) is None:
        raise ValueError("invalid protected API source")
    prefix = "repos/SecPal/api/actions/workflows/publish-container.yml/runs"
    with tempfile.TemporaryDirectory(prefix="fcos-lab-archive-") as temporary:
        root = Path(temporary)
        verification_env = {"PATH": "/usr/bin:/bin", "HOME": temporary, "GH_CONFIG_DIR": temporary,
                            "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1",
                            "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1", "GH_TELEMETRY": "false"}
        verified_gh(gh, verification_env)
        listing = github_json(gh, f"{prefix}?branch=main&head_sha={source}&event=push&status=success&per_page=2")
        run, = listing["workflow_runs"]
        run_id, attempt = run["id"], run["run_attempt"]
        if (run["head_sha"] != source or run["head_branch"] != "main"
                or run["head_repository"]["full_name"] != "SecPal/api" or run["event"] != "push"
                or run["path"] != ".github/workflows/publish-container.yml" or run["conclusion"] != "success"
                or any(type(value) is not int or value < 1 for value in (run_id, attempt))):
            raise ValueError("archived API producer is outside protected main")
        qualification = root / "qualification"
        download_publisher_artifact(gh, "api", run_id, source, f"api-candidate-{run_id}-{attempt}", qualification, 8 * 1024**2)
        children, _ = verify_api_candidate(
            qualification, source, gh, verification_env, current=current, selected=(run_id, attempt),
        )
        yield gh, run_id, attempt, children, qualification, root



@contextmanager
def verified_backend_archive(backend, *, current=True):
    with qualified_backend_source(backend.source, TOOLS / "gh", current=current) as result:
        gh, run_id, attempt, children, qualification, root = result
        pair = api_archive_identity(backend, qualification)
        yield gh, run_id, attempt, children, pair, qualification, root

def prepare_archived_backend(ssh, host, platform, release, previous, backend):
    with verified_backend_archive(backend) as (gh, run_id, attempt, children, pair, qualification, root):
        arch = platform.removeprefix("linux/")
        roles = ("nginx", "php-fpm")
        attempts = {p["smoke"]["workflow_run_attempt"] for role in roles
                    for p in pair["images"][role]["platforms"] if p["subject"]["platform"] == platform}
        producing_attempt, = attempts
        if re.fullmatch(r"[1-9][0-9]*", producing_attempt) is None or int(producing_attempt) > attempt:
            raise ValueError("invalid native archive attempt")
        native = root / "native"
        download_publisher_artifact(gh, "api", run_id, backend.source, f"api-native-{arch}-{run_id}-{producing_attempt}", native, ARCHIVE_MAX)
        archives = [root / (role + ".tar") for role in roles]
        for role, archive in zip(roles, archives, strict=True):
            make_oci_archive(native / role / "image", children[role, platform], archive)
        with tempfile.TemporaryFile() as wire:
            write_backend_archive_request(wire, host, platform, release, previous, backend, qualification, archives)
            return subprocess.run(ssh, stdin=wire, timeout=810, check=False).returncode


def compare_component_risk(previous, candidate, *, observed_at):
    # This checkout is installed with the controller's trusted tools.
    governance = TOOLS / "governance"
    if git(governance, "rev-parse", "HEAD").strip() != b"56c9ccc92c206edfaaf64c4b7ba99d02e4a64189":
        raise ValueError("component-update policy is unavailable")
    if git(governance, "status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("component-update policy checkout differs")
    spec = importlib.util.spec_from_file_location(
        "secpal_component_policy", governance / "scripts/secpal-vulnerability-policy.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    policy = module.load_policy(governance / "policies/vulnerability-triage-v1.json")
    reviewed = [module.load_reviewed_vex(path) for path in sorted((governance / "reviewed-vex").glob("*.json"))]
    return module.compare_component_risk(previous, candidate, policy, observed_at=observed_at, reviewed_vex=reviewed)


def admit_component_update(installed, proposed, previous, candidate, *, exposure_unchanged, observed_at):
    """Compare authenticated evidence bound to the observed predecessor."""
    if exposure_unchanged is not True:
        raise ValueError("component update changes the deployment exposure")
    lane = {role for role, _ in installed}
    if lane not in ({"frontend"}, {"php-fpm", "nginx"}):
        raise ValueError("unsupported or mixed update lane")
    required = {(role, platform) for role in lane for platform in HOSTS.values()}
    if any(set(values) != required for values in (installed, proposed, previous, candidate)):
        raise ValueError("incomplete platform evidence for the update lane")
    report = {}
    for key in sorted(required):
        platform = key[1]
        if previous[key]["subject"] != {"oci_digest": installed[key], "platform": platform}:
            raise ValueError("component evidence differs from the installed predecessor")
        if candidate[key]["subject"] != {"oci_digest": proposed[key], "platform": platform}:
            raise ValueError("component evidence differs from the proposed platform subject")
        result = compare_component_risk(previous[key], candidate[key], observed_at=observed_at)
        if result["review_required"]:
            raise ValueError("component comparison requires review")
        report[key] = result
    return report


def verify_frontend_attestation(gh, subject, bundle, source, environment):
    verify_attestation(gh, subject, bundle, source, environment, "frontend")


def frontend_actions_json(path):
    opener = build_opener(ProxyHandler({}), NoRedirect())
    request = Request("https://api.github.com/repos/SecPal/frontend/actions/runs/" + path,
                      headers={"Accept": "application/vnd.github+json",
                               "User-Agent": "SecPal-FCOS-lab-rollout"})
    limit = 2 * 1024 * 1024
    with opener.open(request, timeout=20) as response:
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("oversized publisher response")
    return json.loads(payload)


def frontend_acceptance(verified, source):
    # The existing publisher owns the clean scanner, SBOM, smoke and signature
    # admission. Bind its final result to the index's verified signer invocation.
    result, = verified
    certificate = result["verificationResult"]["signature"]["certificate"]
    invocation = re.fullmatch(r"https://github\.com/SecPal/frontend/actions/runs/([1-9][0-9]{0,19})"
                              r"/attempts/([1-9][0-9]{0,9})", certificate["runInvocationURI"])
    if invocation is None:
        raise ValueError("missing exact publisher invocation")
    run_id, attempt = map(int, invocation.groups())
    path = f"{run_id}/attempts/{attempt}"
    run = frontend_actions_json(path)
    if (run["id"] != run_id or run["run_attempt"] != attempt
            or run["head_sha"] != source or run["head_branch"] != "main"
            or run["head_repository"]["full_name"] != "SecPal/frontend"
            or run["path"] != ".github/workflows/publish-container.yml"
            or run["event"] not in {"push", "workflow_dispatch"}
            or run["status"] != "completed" or run["conclusion"] != "success"):
        raise ValueError("publisher attempt did not pass")

    listing = frontend_actions_json(path + "/jobs?per_page=100")
    if listing["total_count"] != len(listing["jobs"]):
        raise ValueError("incomplete publisher jobs")
    job, = [job for job in listing["jobs"] if job["name"] == "Accept verified Frontend publication"]
    step, = [step for step in job["steps"]
             if step["name"] == "Verify all subjects and publish only unique discovery tag"]
    if (job["run_id"] != run_id or job["run_attempt"] != attempt
            or job["conclusion"] != "success" or step["conclusion"] != "success"):
        raise ValueError("publisher acceptance did not pass")


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


def publisher_children(frontend, *, gh=None, require_acceptance=False):
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
        if require_acceptance:
            verified = verify_attestation(gh, index, bundle, frontend.source, environment, "frontend", report=True)
            frontend_acceptance(verified, frontend.source)
        else:
            verify_frontend_attestation(gh, index, bundle, frontend.source, environment)
        subject = index.read_bytes()
        return native_children(subject), subject, bundle.read_bytes()


@contextmanager
def api_registry_subjects(backend, gh):
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

        yield root, fetch


def installed_backend_children(backend, *, gh=None):
    """Authenticate the installed indexes without making them eligible for activation."""
    with api_registry_subjects(backend, gh) as (_, fetch):
        return {(role, platform): digest
                for role, index in (("php-fpm", backend.fpm), ("nginx", backend.nginx))
                for platform, digest in native_children(fetch(role, index)[0]).items()}


def backend_proof(backend, *, gh=None):
    with api_registry_subjects(backend, gh) as (root, fetch):
        document_path = root / "runtime-pair.json"
        binding = {"source": backend.source, "nginx": backend.nginx,
                   "fpm": backend.fpm, "expires": backend.expires}
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
                    if backend.transport == API_ARCHIVE:
                        result = prepare_archived_backend(ssh, host, platform, release, previous, backend)
                        if result:
                            backend_diagnostic("guest-transport")
                        return result
                    message = backend_request(host, platform, release, previous, backend.pair, backend_proof(backend))
                except (BadZipFile, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                    backend_diagnostic("publisher-read")
                    return 1
            elif backend == old_backend and frontend.index != old_frontend.index:
                if frontend.transport == FRONTEND_ARCHIVE:
                    return prepare_archived_frontend(ssh, host, platform, release, previous, frontend)
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
    except (BadZipFile, OSError, ValueError, KeyError, TypeError, StopIteration, RolloutError,
            http.client.HTTPException, subprocess.SubprocessError):
        print("FCOS lab adapter failed closed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.umask(0o077)
    sys.exit(main())
