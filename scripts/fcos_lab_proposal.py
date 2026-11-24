#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Verify publisher evidence and prepare an FCOS lab release draft."""

import base64
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from zipfile import BadZipFile, ZipFile

from fcos_lab_discovery import get, product_candidate, protected_source, qualified_candidate, registry_publications, source_relationship
from fcos_lab_rollout_adapter import API_ARCHIVE, API_IMAGE, DIGEST, FRONTEND_ARCHIVE, IMAGE, RUNTIME_SOURCE as FILE, Backend, Frontend
from fcos_lab_rollout import LAB_API_PINS, git
from fcos_lab_rollout_adapter import ProposalFailure, QualificationUnavailable, admit_source_text, github_json, proposal_stage
from fcos_lab_rollout_adapter import backend_proof, publisher_children, verify_frontend_attestation
from image_attestation_runtime import CLOUD_GH_RELEASES, stage_gh_cli

UPSTREAM = "SecPal/frontend"
API = "SecPal/api"
REPO = "SecPal/deployment"
WORKFLOW = ".github/workflows/publish-container.yml"
BRANCH = "fcos-lab-frontend-"
BACKEND_BRANCH = "fcos-lab-backend-"
BACKEND_DRAFT_FILE = "docs/fcos-lab-backend-proposal.md"
SHA = "[a-f0-9]{40}"
MAX_ARCHIVE = 8 * 1024 * 1024


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Proposal:
    index: str
    source: str
    run_id: int
    run_attempt: int
    amd64: str
    arm64: str
    evidence: str

    def __post_init__(self):
        if (re.fullmatch(SHA, self.source) is None
                or any(re.fullmatch(DIGEST, d) is None for d in (self.index, self.amd64, self.arm64, self.evidence))
                or len({self.index, self.amd64, self.arm64}) != 3
                or any(type(n) is not int or n <= 0 for n in (self.run_id, self.run_attempt))):
            raise ValueError("malformed frontend proposal")

    @property
    def publication(self):
        return {"source_commit": self.source, "run_id": self.run_id, "run_attempt": self.run_attempt}


@dataclass(frozen=True)
class BackendProposal:
    index: str  # The signed pair artifact is the proposal's identity.
    source: str
    run_id: int
    run_attempt: int
    nginx: str
    fpm: str
    nginx_amd64: str
    nginx_arm64: str
    fpm_amd64: str
    fpm_arm64: str
    expires: str

    def __post_init__(self):
        if (re.fullmatch(SHA, self.source) is None
                or len(set((self.index, self.nginx, self.fpm, self.nginx_amd64, self.nginx_arm64,
                            self.fpm_amd64, self.fpm_arm64))) != 7
                or any(re.fullmatch(DIGEST, d) is None for d in (self.index, self.nginx, self.fpm,
                       self.nginx_amd64, self.nginx_arm64, self.fpm_amd64, self.fpm_arm64))
                or any(type(n) is not int or n <= 0 for n in (self.run_id, self.run_attempt))
                or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z", self.expires)):
            raise ValueError("malformed backend proposal")

    @property
    def publication(self):
        return {"source_commit": self.source, "run_id": self.run_id, "run_attempt": self.run_attempt}

    def draft_body(self):
        return (
            "Refs #93. **Compatibility evidence is outstanding.**\n\n"
            f"- [API publisher run {self.run_id}, attempt {self.run_attempt}]"
            f"(https://github.com/{API}/actions/runs/{self.run_id}/attempts/{self.run_attempt})\n"
            f"- Source `{self.source}`\n"
            f"- Signed pair `{self.index}`\n"
            f"- Nginx index `{self.nginx}`\n"
            f"  - amd64 `{self.nginx_amd64}`\n"
            f"  - arm64 `{self.nginx_arm64}`\n"
            f"- PHP-FPM index `{self.fpm}`\n"
            f"  - amd64 `{self.fpm_amd64}`\n"
            f"  - arm64 `{self.fpm_arm64}`\n"
            f"- Signed security evidence deadline `{self.expires}`\n\n"
            "Before adding the lab pins, complete the isolated PostgreSQL, API, data and queue "
            "rehearsals on both native architectures. Supply the reviewed pair-bound compatibility "
            "record and add separate predecessor evidence only if automatic rollback is safe. "
            "Confirm current security qualification and follow the normal protected-main review.\n"
        )


def publisher_archive(gh, run_id, attempt):
    name = f"frontend-accepted-{run_id}-{attempt}"
    listing = get(f"repos/{UPSTREAM}/actions/runs/{run_id}/artifacts?name={name}&per_page=2", gh=gh)
    artifact, = listing["artifacts"]
    size, artifact_id = artifact["size_in_bytes"], artifact["id"]
    if (artifact["name"] != name or artifact["expired"] is not False
            or type(size) is not int or not 0 < size <= MAX_ARCHIVE
            or type(artifact_id) is not int or artifact_id <= 0):
        raise ValueError("the accepted publisher artifact is unavailable")
    environment = dict(os.environ)
    token = environment.pop("FCOS_FRONTEND_ACTIONS_READ_TOKEN", "")
    if token:
        environment["GH_TOKEN"] = token
    elif environment.get("GITHUB_ACTIONS") == "true":
        raise ValueError("the publisher artifact requires scoped frontend Actions read authorization")
    archive = subprocess.run(
        [gh, "api", "--method", "GET", f"repos/{UPSTREAM}/actions/artifacts/{artifact_id}/zip"],
        capture_output=True, stdin=subprocess.DEVNULL, check=True, timeout=45, env=environment,
    ).stdout
    if len(archive) > MAX_ARCHIVE or sha256(archive) != artifact["digest"]:
        raise ValueError("publisher artifact archive identity differs")
    with ZipFile(BytesIO(archive)) as contents:
        names = ("build-evidence.json", "source-security.json", "build-evidence.bundle.json")
        for name in names:
            info, = (entry for entry in contents.infolist() if entry.filename == name)
            if not 0 < info.file_size <= MAX_ARCHIVE:
                raise ValueError("publisher artifact entry is oversized")
        return tuple(contents.read(name) for name in names)


def evidence_agrees(build, source_scan, proposal, *, upstream=UPSTREAM, image=IMAGE, user="101:101"):
    native = {"linux/amd64": proposal.amd64, "linux/arm64": proposal.arm64}
    ref = f"https://github.com/{upstream}"
    workflow = {"repository": upstream, "path": WORKFLOW, "commit": proposal.source,
                "run_id": str(proposal.run_id), "run_attempt": str(proposal.run_attempt)}
    subject = build["subject"]
    platforms = subject["platforms"]
    # The signed publisher acceptance owns full schema and database-deadline
    # admission. Recheck the closed scan result consumed by this proposal.
    scan_bytes = json.dumps(source_scan, sort_keys=True, separators=(",", ":")).encode()
    if (build["schema_version"] != "1.0.0" or build["workflow"] != workflow
            or build["source"]["repository"] != ref or build["source"]["commit"] != proposal.source
            or subject["repository"] != image or subject["index_digest"] != proposal.index
            or len(platforms) != len(native)
            or {p["platform"]: p["manifest_digest"] for p in platforms} != native
            or any(p["user"] != user for p in platforms)
            or source_scan["schema_version"] != "secpal-trivy-repository-scan-v5"
            or source_scan["operation"] != {"name": "TRIVY_REPOSITORY_SCAN", "status": "SUCCEEDED"}
            or source_scan["database"]["status"] != "FRESH"
            or source_scan["gate_state"] != "CLEAN"
            or source_scan["subject"] != {"repository": upstream, "commit": proposal.source}
            or build["extensions"][ref]["source_security_sha256"] != sha256(scan_bytes)):
        raise ValueError("publisher evidence is not bound to the admitted release")

    scans, smokes, sboms = build["scans"], build["smoke_tests"], build["sboms"]
    if (len(scans) != 4 or len(smokes) != 2 or len(sboms) != 2
            or {item["platform"] for item in sboms} != set(native)
            or {item["platform"] for item in smokes} != set(native)):
        raise ValueError("incomplete platform security or smoke evidence")
    for arch, digest in native.items():
        sbom, = (item for item in sboms if item["platform"] == arch)
        smoke, = (item for item in smokes if item["platform"] == arch)
        if (sbom["subject_digest"] != digest or re.fullmatch(DIGEST, sbom["spdx_sha256"]) is None
                or smoke["digest"] != digest or smoke["result"] != "SUCCEEDED"
                or smoke["runner_architecture"] != arch.split("/")[1]
                or smoke["workflow_run_id"] != workflow["run_id"]
                or smoke["workflow_run_attempt"] != workflow["run_attempt"]):
            raise ValueError("platform evidence identity differs")
        for scanner, target in (("grype", sbom["spdx_sha256"]), ("trivy", digest)):
            scan, = (item for item in scans if item["platform"] == arch and item["scanner"] == scanner)
            if (scan["subject_digest"], scan["status"], scan["policy_result"]) != (target, "SUCCEEDED", "CLEAN"):
                raise ValueError("publisher did not admit a clean native artifact")


def verify_publication(report):
    source, run_id, attempt = (report[k] for k in ("source_commit", "run_id", "run_attempt"))
    if re.fullmatch(SHA, source) is None or any(type(n) is not int or n <= 0 for n in (run_id, attempt)):
        raise ValueError("invalid publisher identity")
    if source_relationship(get(f"repos/{UPSTREAM}/compare/{source}...main")) not in {"identical", "ahead"}:
        raise ValueError("publisher source has left upstream main")

    with tempfile.TemporaryDirectory(prefix="fcos-lab-proposal-") as directory:
        root = Path(directory)
        environment = {"PATH": "/usr/bin:/bin", "HOME": directory, "GH_CONFIG_DIR": directory,
                       "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_TELEMETRY": "false"}

        def run(argv, environment):
            subprocess.run(argv, env=environment, check=True, timeout=190)

        gh = stage_gh_cli(root, CLOUD_GH_RELEASES[platform.machine()], run, environment)
        build_bytes, source_scan, bundle = publisher_archive(gh, run_id, attempt)
        build = json.loads(build_bytes)
        index = build["subject"]["index_digest"]
        if re.fullmatch(DIGEST, index) is None:
            raise ValueError("invalid OCI index")
        children, _, _ = publisher_children(Frontend(index, source), gh=gh)
        evidence, signature = root / "build-evidence.json", root / "bundle.json"
        for path, content in ((evidence, build_bytes), (signature, bundle)):
            path.touch(mode=0o600, exist_ok=False)
            path.write_bytes(content)
        verify_frontend_attestation(gh, evidence, signature, source, environment)
    proposal = Proposal(index, source, run_id, attempt, children["linux/amd64"],
                        children["linux/arm64"], sha256(build_bytes))
    evidence_agrees(build, json.loads(source_scan), proposal)
    return proposal


def candidate(report, current):
    if report["source_relationship"] != "ahead" or report["source_commit"] == current.source:
        return None
    proposal = verify_publication(report)
    return None if proposal.index == current.index else proposal


def verify_backend_publication(report):
    source, run_id, attempt = (report[k] for k in ("source_commit", "run_id", "run_attempt"))
    spec = spec_from_file_location("oci_evidence_reader", Path(__file__).with_name("fetch-oci-attestation.py"))
    reader = module_from_spec(spec)
    spec.loader.exec_module(reader)
    discovery = reader.api_publication_evidence(source, run_id, attempt)
    if discovery is None:
        return None
    pair_digest, original_attempt, files = discovery
    ref = f"https://github.com/{API}"
    pair = json.loads(files["runtime-pair.json"])
    expected = {"repository": API, "path": WORKFLOW, "commit": source,
                "run_id": str(run_id), "run_attempt": str(original_attempt)}
    if (pair["schema_version"] != "1.0.0" or pair["source"] != {"repository": ref, "commit": source}
            or pair["workflow"] != expected or set(pair["images"]) != {"nginx", "php-fpm"}):
        raise ValueError("API discovery record does not match the publisher run")
    bindings, scans = {}, []
    for role, key in (("nginx", "nginx"), ("php-fpm", "fpm")):
        component = pair["images"][role]
        index = component["reference"].removeprefix(API_IMAGE + "@")
        manifest, source_scan = (json.loads(files[f"{role}/{name}.json"])
                                 for name in ("build-evidence", "source-security"))
        evidence = sha256(files[f"{role}/build-evidence.json"])
        native = {entry["platform"]: entry["manifest_digest"] for entry in component["platforms"]}
        proof = Proposal(index, source, run_id, original_attempt,
                         native["linux/amd64"], native["linux/arm64"], evidence)
        original = {"commit": source, "run_id": str(run_id), "run_attempt": str(original_attempt)}
        accepted = {"commit": source, "run_id": str(run_id), "run_attempt": str(attempt)}
        acceptance = manifest["extensions"][ref].get("acceptance_execution", original)
        if (component["build_evidence_sha256"] != evidence
                or manifest["subject"]["platforms"] != component["platforms"]
                or manifest["source"].get("runtime") != role
                or acceptance != accepted
                or any(p["labels"].get("secpal.dev/runtime-component") != role for p in component["platforms"])):
            raise ValueError("API component evidence does not bind the signed pair and acceptance attempt")
        evidence_agrees(manifest, source_scan, proof, upstream=API, image=API_IMAGE, user="secpal")
        bindings[key] = proof
        scans.append(source_scan)
    deadline = min(datetime.fromisoformat(scan["database"]["next_update"]) for scan in scans)
    expires = deadline.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if deadline <= datetime.now(timezone.utc):
        return None
    if source_relationship(get(f"repos/{API}/compare/{source}...main")) not in {"identical", "ahead"}:
        return None
    nginx, fpm = bindings["nginx"], bindings["fpm"]
    with tempfile.TemporaryDirectory(prefix="fcos-lab-api-proposal-") as directory:
        environment = {"PATH": "/usr/bin:/bin", "HOME": directory, "GH_CONFIG_DIR": directory,
                       "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_TELEMETRY": "false"}

        def run(argv, environment):
            subprocess.run(argv, env=environment, check=True, timeout=190)

        gh = stage_gh_cli(Path(directory), CLOUD_GH_RELEASES[platform.machine()], run, environment)
        verified = backend_proof(Backend(source, nginx.index, fpm.index, pair_digest, expires, None), gh=gh)
        if verified[2] != files["runtime-pair.json"]:
            raise ValueError("API discovery document differs from the signed pair")
    return BackendProposal(pair_digest, source, run_id, attempt, nginx.index, fpm.index,
                           nginx.amd64, nginx.arm64, fpm.amd64, fpm.arm64, expires)


def backend_candidate(report, current):
    if report["source_relationship"] != "ahead" or report["source_commit"] == current.source:
        return None
    proposal = verify_backend_publication(report)
    if proposal is not None and (proposal.index == current.pair
                                or (proposal.nginx, proposal.fpm) == (current.nginx, current.fpm)):
        return None
    return proposal


def archived_selection(product, installed, gh):
    """Select the signed main identity. The caller still has to admit an update."""
    report = qualified_candidate(product, gh, current=False)
    source = report["source_commit"]
    if product == "frontend":
        selected = Frontend(report["index"], source, FRONTEND_ARCHIVE)
    else:
        selected = Backend(source, report["indexes"]["nginx"], report["indexes"]["php-fpm"],
                           report["receipt"], report["source_security_expires"], None, API_ARCHIVE)
    if isinstance(selected, Backend):
        # Renewal of evidence alone cannot change the installed image.
        installed = replace(installed, expires=selected.expires)
    if selected == installed:
        return None
    relationship = github_json(gh, f"repos/SecPal/{product}/compare/{installed.source}...{source}")
    if source_relationship(relationship) != "ahead":
        raise ValueError("the qualified source does not advance the installed source")
    return selected


def proposed_file(text, proposal):
    for key, value in (("DIGEST", proposal.index), ("SOURCE_COMMIT", proposal.source)):
        text, count = re.subn(rf'^LAB_FRONTEND_{key} = "[^"\n]+"$', f'LAB_FRONTEND_{key} = "{value}"',
                              text, flags=re.MULTILINE)
        if count != 1:
            raise ValueError("expected exactly one existing lab pin")
    return text


def write(method, endpoint, payload, *, token, gh="gh"):
    output = subprocess.run(
        [gh, "api", "--hostname", "github.com", "--method", method, endpoint, "--input", "-"],
        input=json.dumps(payload), text=True, capture_output=True, check=True, timeout=45,
        env=dict(os.environ, GH_TOKEN=token) if token else None,
    ).stdout
    return json.loads(output)


def publish(proposal, base, text, *, token):
    if re.fullmatch(SHA, base) is None:
        raise ValueError("invalid deployment base")
    if get(f"repos/{REPO}/git/ref/heads/main")["object"]["sha"] != base:
        return "base changed"
    backend = isinstance(proposal, BackendProposal)
    upstream, prefix_name, lane = (API, BACKEND_BRANCH, "backend") if backend else (UPSTREAM, BRANCH, "frontend")
    current = Backend.from_source(text) if backend else Frontend.from_source(text)
    current_index = current.pair if backend else current.index
    if (proposal.index == current_index or proposal.source == current.source
            or backend and (proposal.nginx, proposal.fpm) == (current.nginx, current.fpm)):
        return "already accepted"
    if backend and datetime.fromisoformat(proposal.expires) <= datetime.now(timezone.utc):
        return "backend publisher security evidence expired"

    candidate_branch = prefix_name + proposal.index.removeprefix("sha256:") + "-"
    branch = candidate_branch + base
    prefix = f"repos/{REPO}"
    known = get(f"{prefix}/pulls?state=all&base=main&per_page=100", paginate=True)
    proposals = [pr for pr in known if pr["head"]["ref"].startswith(prefix_name)
                 and (not backend or re.fullmatch(r"fcos-lab-backend-[a-f0-9]{64}-[a-f0-9]{40}",
                                                  pr["head"]["ref"]))
                 and (pr["head"]["repo"] or {}).get("full_name") == REPO]
    for pr in proposals:
        if pr["head"]["ref"].startswith(candidate_branch):
            return f"proposal #{int(pr['number'])} already exists"
    if any(pr["state"] == "open" for pr in proposals):
        return f"another {lane} proposal is open"

    candidate_run = product_candidate(get(registry_publications(upstream)), upstream)
    if (candidate_run != proposal.publication
            or source_relationship(get(f"repos/{upstream}/compare/{current.source}...{proposal.source}")) != "ahead"):
        return "publisher candidate changed"

    path = BACKEND_DRAFT_FILE if backend else FILE
    expected = ("<!--\n" + "SPDX-" + "FileCopyrightText: 2026 SecPal Contributors\n"
                + "SPDX-" + "License-Identifier: AGPL-3.0-or-later\n-->\n\n"
                + "# FCOS lab backend proposal\n\n" + proposal.draft_body()) if backend else proposed_file(text, proposal)
    body = proposal.draft_body() if backend else (
            f"Refs #93. Frontend lab pin only.\n\n"
            f"- [Publisher run {proposal.run_id}, attempt {proposal.run_attempt}]"
            f"(https://github.com/{UPSTREAM}/actions/runs/{proposal.run_id}/attempts/{proposal.run_attempt})\n"
            f"- Source `{proposal.source}` and OCI index `{proposal.index}`\n"
            f"- Native amd64 `{proposal.amd64}` and arm64 `{proposal.arm64}`\n"
            f"- Signed build evidence SHA-256 `{proposal.evidence}`\n\n"
            "The publisher attestation and both native subjects, CLEAN Grype/Trivy evidence and smoke results passed. "
            "Review current compatibility and approve the native required checks before merging. "
            "The existing timer handles activation after an accepted merge."
        )
    result, _, _ = open_proposal(branch, base, lane, proposal.source, {path: expected}, body, token=token, draft=True)
    return result


def open_proposal(branch, base, lane, source, files, body, *, token, draft, gh="gh"):
    """Use the existing GitHub-signed branch transaction for either transport."""
    prefix = f"repos/{REPO}"
    ref = f"refs/heads/{branch}"
    refs = [record for record in get(f"{prefix}/git/matching-refs/heads/{branch}", gh=gh) if record["ref"] == ref]
    if refs:
        entry, = refs
        tip = entry["object"]["sha"]
    else:
        tip = write("POST", f"{prefix}/git/refs", {"ref": ref, "sha": base}, token=token, gh=gh)["object"]["sha"]
        if tip != base:
            raise ValueError("new proposal ref differs from the admitted base")

    if tip == base:
        payload = {"branch": {"repositoryNameWithOwner": REPO, "branchName": branch},
                   "message": {"headline": f"Propose the verified FCOS lab {lane} release"},
                   "expectedHeadOid": base, "fileChanges": {"additions": [
                       {"path": path, "contents": base64.b64encode(contents.encode()).decode("ascii")}
                       for path, contents in sorted(files.items())
                   ]}}
        reply = write("POST", "graphql", {
            "query": "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}",
            "variables": {"input": payload},
        }, token=token, gh=gh)
        tip = reply["data"]["createCommitOnBranch"]["commit"]["oid"]
    if re.fullmatch(SHA, tip) is None:
        raise ValueError("invalid proposal commit")
    commit = get(f"{prefix}/commits/{tip}", gh=gh)
    if ([item["sha"] for item in commit["parents"]] != [base]
            or sorted(file["filename"] for file in commit["files"]) != sorted(files)
            or commit["commit"]["verification"]["verified"] is not True
            or any(get(f"{prefix}/contents/{path}?ref={tip}", raw=True, gh=gh) != contents
                   for path, contents in files.items())):
        raise ValueError("the proposal branch differs from the verified proposal")
    if get(f"{prefix}/git/ref/heads/main", gh=gh)["object"]["sha"] != base:
        return "base changed before opening the proposal", None, None

    result = write("POST", f"{prefix}/pulls", {
        "title": f"Propose FCOS lab {lane} {source[:12]}",
        "head": branch, "base": "main", "draft": draft, "body": body,
    }, token=token, gh=gh)
    number = int(result["number"])
    return f"{'draft ' if draft else ''}proposal #{number} created", number, tip


def archived_files(product, text, selected, evidence, *, compatibility=None):
    if product == "frontend":
        updated = proposed_file(text, selected)
    else:
        if not compatibility:
            raise ValueError("native API compatibility record is unavailable")
        values = {"API_SOURCE_COMMIT": selected.source, "API_DIGEST": selected.nginx,
                  "PHP_FPM_DIGEST": selected.fpm, "API_PAIR_DIGEST": selected.pair,
                  "API_VEX_EXPIRES_AT": selected.expires,
                  "API_COMPATIBILITY_SHA256": hashlib.sha256(compatibility).hexdigest(),
                  "API_TRANSPORT": API_ARCHIVE}
        updated = LAB_API_PINS.sub(b"", text.encode()).decode()
        updated += "".join(f'LAB_{name} = "{value}"\n' for name, value in values.items())
    files = {FILE: updated}
    for side, key in (("installed", "previous"), ("candidate", "candidate")):
        for (role, platform), evaluation in sorted(evidence[key].items()):
            arch = platform.removeprefix("linux/")
            leaf = f"{arch}-{side}.json" if product == "frontend" else f"{role}-{arch}-{side}.json"
            rendered = json.dumps(evaluation, sort_keys=True, separators=(",", ":")) + "\n"
            if len(rendered.encode()) > 1024**2:
                raise ValueError("comparison evidence exceeds the repository limit")
            files[f"config/quadlet/fcos-lab-rollout/{product}-security/{leaf}"] = rendered
    return files


def proposed_files_digest(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def comparison_payload(content):
    report = json.loads(content)
    del report["evaluated_at"]
    for run in report["scanner_runs"]:
        del run["completed_at"], run["run_id"]
    for observation in report["observations"]:
        del observation["observed_at"], observation["scanner_run_id"]
    return report


def existing_archive_proposal(pr, prefix, base, files, gh):
    """Read back an interrupted signed proposal before resuming its auto-merge."""
    head = pr["head"]
    if pr["draft"] or re.fullmatch(re.escape(prefix) + r"[a-f0-9]{64}", head["ref"]) is None:
        return None
    tip, number = head["sha"], int(pr["number"])
    if re.fullmatch(SHA, tip) is None:
        raise ValueError("invalid interrupted proposal commit")
    endpoint = f"repos/{REPO}"
    commit = get(f"{endpoint}/commits/{tip}", gh=gh)
    if ([parent["sha"] for parent in commit["parents"]] != [base]
            or sorted(item["filename"] for item in commit["files"]) != sorted(files)
            or commit["commit"]["verification"]["verified"] is not True):
        raise ValueError("interrupted proposal differs from the admitted base and scope")
    stored = {path: get(f"{endpoint}/contents/{path}?ref={tip}", raw=True, gh=gh) for path in files}
    if head["ref"] != prefix + proposed_files_digest(stored) or stored[FILE] != files[FILE]:
        raise ValueError("interrupted proposal identity differs from its signed evidence")
    scheduled = json.loads(subprocess.check_output(
        [gh, "pr", "view", str(number), "--repo", REPO, "--json", "autoMergeRequest,headRefOid"],
        stdin=subprocess.DEVNULL, timeout=45,
    ))
    if scheduled["headRefOid"] != tip:
        raise ValueError("interrupted proposal head changed")
    if scheduled["autoMergeRequest"] is not None:
        return ("scheduled", number, tip)
    actor = github_json(gh, "user")["login"]
    if pr["user"]["login"] != actor:
        raise ValueError("a different actor owns the older proposal")
    if all(comparison_payload(stored[path]) == comparison_payload(files[path]) for path in files if path != FILE):
        return ("resume", number, tip)
    write("PATCH", f"{endpoint}/pulls/{number}", {"state": "closed"}, token=None, gh=gh)
    return ("refresh", number, tip)


def publish_archive(product, base, selected, files, gh):
    lane = "frontend" if product == "frontend" else "backend"
    index = selected.index if product == "frontend" else selected.pair
    prefix = BRANCH if product == "frontend" else BACKEND_BRANCH
    # Interrupted writes can retry the same bytes. A fresh comparison can use
    # a different branch without rewriting an existing signed commit.
    branch_prefix = prefix + index.removeprefix("sha256:") + "-" + base + "-"
    branch = branch_prefix + proposed_files_digest(files)
    endpoint = f"repos/{REPO}"
    if github_json(gh, f"{endpoint}/git/ref/heads/main")["object"]["sha"] != base:
        return "deployment base changed"
    if protected_source(product, gh) != selected.source:
        return "protected product main changed during qualification"
    proposals = get(f"{endpoint}/pulls?state=open&base=main&per_page=100", paginate=True, gh=gh)
    resume = None
    for pr in proposals:
        head = pr["head"]
        if (head["repo"] or {}).get("full_name") != REPO or not head["ref"].startswith((BRANCH, BACKEND_BRANCH)):
            continue
        existing = existing_archive_proposal(pr, branch_prefix, base, files, gh)
        if existing is None:
            return f"deployment proposal #{int(pr['number'])} is already open"
        action, number, tip = existing
        if action == "scheduled":
            return f"deployment proposal #{number} already has auto-merge enabled"
        if action == "resume":
            resume = number, tip
    if resume:
        number, tip = resume
        message = f"deployment proposal #{number} resumed"
    else:
        body = (f"Refs #93. Propose the exact archived {lane} subject `{index}` from `{selected.source}`. "
                "Current comparative evidence is bound to the observed Lab predecessor. "
                "The existing controller rechecks the protected candidate and evaluates this evidence before activation.")
        message, number, tip = open_proposal(branch, base, lane, selected.source, files, body, token=None, draft=False, gh=gh)
    if tip is not None:
        if protected_source(product, gh) != selected.source:
            write("PATCH", f"{endpoint}/pulls/{number}", {"state": "closed"}, token=None, gh=gh)
            return f"proposal #{number} closed because protected product main advanced"
        subprocess.run([gh, "pr", "merge", str(number), "--repo", REPO, "--auto", "--squash",
                        "--match-head-commit", tip], check=True, timeout=60,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return message


def propose_archives(repo, release, gh, archives, *, baseline=None):
    """Reconcile one component against the accepted release; leave activation to its timer."""
    from fcos_lab_scan import compare_archives

    text = admit_source_text(repo, release)
    observed = admit_source_text(repo, baseline) if baseline is not None else text
    for product, parse in (("frontend", Frontend), ("api", Backend)):
        installed = parse.from_source(observed)
        if baseline is not None and installed == parse.from_source(text):
            continue
        print(f"FCOS Lab {product}: selecting archived candidate", flush=True)
        try:
            with proposal_stage("publisher-read"):
                selected = archived_selection(product, installed, gh)
            if selected is None or (baseline is not None and selected == parse.from_source(text)):
                print(f"FCOS Lab {product}: already current")
                continue
            compatibility = None
            if product == "api":
                path = "config/quadlet/fcos-lab-rollout/backend-compatibility.json"
                with proposal_stage("security-comparison"):
                    compatibility = git(repo, "show", f"{release.revision}:{path}")
                    record = json.loads(compatibility)
                    if (record["previous_pair"], record["candidate_pair"]) != (installed.pair, selected.pair):
                        print("FCOS Lab API deferred: native compatibility evidence for this pair is outstanding")
                        continue
            evidence = compare_archives(product, installed, selected, gh, archives)
            with proposal_stage("proposal-write"):
                files = archived_files(product, text, selected, evidence, compatibility=compatibility)
                print(publish_archive(product, release.revision, selected, files, gh))
            return
        except QualificationUnavailable as error:
            print(f"FCOS Lab {product} deferred: {error}")
        except ProposalFailure as error:
            print(f"FCOS Lab {product} deferred: {error}", file=sys.stderr)


def main():
    try:
        mode, *args = sys.argv[1:]
        text = Path(FILE).read_text(encoding="utf-8")
        if mode == "archive-select":
            product, executable = args
            if product not in {"frontend", "api"}:
                raise ValueError("unknown product")
            installed = (Frontend if product == "frontend" else Backend).from_source(text)
            try:
                plan = archived_selection(product, installed, Path(executable).absolute())
            except QualificationUnavailable as error:
                print(json.dumps({"status": "deferred", "reason": str(error)}, sort_keys=True))
                return 0
            print(json.dumps({"status": "already-current"} if plan is None else
                             {"status": "selected", "candidate": asdict(plan)}, sort_keys=True))
            return 0
        if args:
            raise ValueError("unsupported proposal arguments")
        value = json.load(sys.stdin)
        if mode in {"verify", "backend-verify"}:
            plan = (backend_candidate(value, Backend.from_source(text)) if mode == "backend-verify"
                    else candidate(value, Frontend.from_source(text)))
            if plan is not None:
                print(json.dumps(asdict(plan), separators=(",", ":")))
        elif mode in {"publish", "backend-publish"}:
            token = os.environ.pop("FCOS_FRONTEND_PROPOSAL_WRITE_TOKEN", "")
            if not token:
                print("FCOS proposal write credential is missing", file=sys.stderr)
                return 1
            plan_type = BackendProposal if mode == "backend-publish" else Proposal
            print(publish(plan_type(**value), os.environ["GITHUB_SHA"], text, token=token))
        else:
            raise ValueError("unsupported proposal operation")
    except (BadZipFile, KeyError, OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
        print("FCOS release proposal did not pass admission", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
