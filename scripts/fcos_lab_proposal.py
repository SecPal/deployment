#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Verify and prepare a draft proposal for the already qualified frontend lane."""

import base64
from dataclasses import asdict, dataclass
import hashlib
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

from fcos_lab_discovery import get, product_candidate, source_relationship
from fcos_lab_rollout_adapter import DIGEST, IMAGE, RUNTIME_SOURCE as FILE, Frontend
from fcos_lab_rollout_adapter import publisher_children, verify_frontend_attestation
from image_attestation_runtime import CLOUD_GH_RELEASES, stage_gh_cli

UPSTREAM = "SecPal/frontend"
REPO = "SecPal/deployment"
WORKFLOW = ".github/workflows/publish-container.yml"
PUBLICATIONS = f"repos/{UPSTREAM}/actions/workflows/publish-container.yml/runs?branch=main&status=success&per_page=1"
BRANCH = "fcos-lab-frontend-"
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


def publisher_archive(run_id, attempt):
    name = f"frontend-accepted-{run_id}-{attempt}"
    listing = get(f"repos/{UPSTREAM}/actions/runs/{run_id}/artifacts?name={name}&per_page=2")
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
        ["gh", "api", "--method", "GET", f"repos/{UPSTREAM}/actions/artifacts/{artifact_id}/zip"],
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


def evidence_agrees(build, source_scan, proposal):
    native = {"linux/amd64": proposal.amd64, "linux/arm64": proposal.arm64}
    ref = f"https://github.com/{UPSTREAM}"
    workflow = {"repository": UPSTREAM, "path": WORKFLOW, "commit": proposal.source,
                "run_id": str(proposal.run_id), "run_attempt": str(proposal.run_attempt)}
    subject = build["subject"]
    platforms = subject["platforms"]
    scan_bytes = json.dumps(source_scan, sort_keys=True, separators=(",", ":")).encode()
    if (build["schema_version"] != "1.0.0" or build["workflow"] != workflow
            or build["source"]["repository"] != ref or build["source"]["commit"] != proposal.source
            or subject["repository"] != IMAGE or subject["index_digest"] != proposal.index
            or len(platforms) != len(native)
            or {p["platform"]: p["manifest_digest"] for p in platforms} != native
            or any(p["user"] != "101:101" for p in platforms)
            or source_scan["gate_state"] != "CLEAN"
            or source_scan["subject"] != {"repository": UPSTREAM, "commit": proposal.source}
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
    build_bytes, source_scan, bundle = publisher_archive(run_id, attempt)
    build = json.loads(build_bytes)
    index = build["subject"]["index_digest"]
    if re.fullmatch(DIGEST, index) is None:
        raise ValueError("invalid OCI index")

    with tempfile.TemporaryDirectory(prefix="fcos-lab-proposal-") as directory:
        root = Path(directory)
        environment = {"PATH": "/usr/bin:/bin", "HOME": directory, "GH_CONFIG_DIR": directory,
                       "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_TELEMETRY": "false"}

        def run(argv, environment):
            subprocess.run(argv, env=environment, check=True, timeout=190)

        gh = stage_gh_cli(root, CLOUD_GH_RELEASES[platform.machine()], run, environment)
        children, _, _ = publisher_children(Frontend(index, source), gh=gh)
        evidence, signature = root / "build-evidence.json", root / "bundle.json"
        evidence.write_bytes(build_bytes)
        signature.write_bytes(bundle)
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


def proposed_file(text, proposal):
    for key, value in (("DIGEST", proposal.index), ("SOURCE_COMMIT", proposal.source)):
        text, count = re.subn(rf'^LAB_FRONTEND_{key} = "[^"\n]+"$', f'LAB_FRONTEND_{key} = "{value}"',
                              text, flags=re.MULTILINE)
        if count != 1:
            raise ValueError("expected exactly one existing lab pin")
    return text


def write(method, endpoint, payload):
    output = subprocess.run(
        ["gh", "api", "--method", method, endpoint, "--input", "-"],
        input=json.dumps(payload), text=True, capture_output=True, check=True, timeout=45,
    ).stdout
    return json.loads(output)


def publish(proposal, base, text):
    if re.fullmatch(SHA, base) is None:
        raise ValueError("invalid deployment base")
    if get(f"repos/{REPO}/git/ref/heads/main")["object"]["sha"] != base:
        return "base changed"
    current = Frontend.from_source(text)
    if proposal.index == current.index or proposal.source == current.source:
        return "already accepted"

    candidate_branch = BRANCH + proposal.index.removeprefix("sha256:") + "-"
    branch = candidate_branch + base
    prefix = f"repos/{REPO}"
    known = get(f"{prefix}/pulls?state=all&base=main&per_page=100", paginate=True)
    proposals = [pr for pr in known if pr["head"]["ref"].startswith(BRANCH)
                 and (pr["head"]["repo"] or {}).get("full_name") == REPO]
    for pr in proposals:
        if pr["head"]["ref"].startswith(candidate_branch):
            return f"proposal #{int(pr['number'])} already exists"
    if any(pr["state"] == "open" for pr in proposals):
        return "another frontend proposal is open"

    candidate_run = product_candidate(get(PUBLICATIONS), UPSTREAM)
    if (candidate_run != proposal.publication
            or source_relationship(get(f"repos/{UPSTREAM}/compare/{current.source}...{proposal.source}")) != "ahead"):
        return "publisher candidate changed"

    expected = proposed_file(text, proposal)
    ref = f"refs/heads/{branch}"
    refs = [record for record in get(f"{prefix}/git/matching-refs/heads/{branch}") if record["ref"] == ref]
    if refs:
        entry, = refs
        tip = entry["object"]["sha"]
    else:
        tip = write("POST", f"{prefix}/git/refs", {"ref": ref, "sha": base})["object"]["sha"]
        if tip != base:
            raise ValueError("new proposal ref differs from the admitted base")

    if tip == base:
        payload = {"branch": {"repositoryNameWithOwner": REPO, "branchName": branch},
                   "message": {"headline": "Propose the verified FCOS lab frontend image"},
                   "expectedHeadOid": base, "fileChanges": {"additions": [{
                       "path": FILE, "contents": base64.b64encode(expected.encode()).decode("ascii"),
                   }]}}
        reply = write("POST", "graphql", {
            "query": "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}",
            "variables": {"input": payload},
        })
        tip = reply["data"]["createCommitOnBranch"]["commit"]["oid"]
    if re.fullmatch(SHA, tip) is None:
        raise ValueError("invalid proposal commit")
    commit = get(f"{prefix}/commits/{tip}")
    if ([item["sha"] for item in commit["parents"]] != [base]
            or [file["filename"] for file in commit["files"]] != [FILE]
            or commit["commit"]["verification"]["verified"] is not True
            or get(f"{prefix}/contents/{FILE}?ref={tip}", raw=True) != expected):
        raise ValueError("the proposal branch does not contain the exact verified pin change")
    if get(f"{prefix}/git/ref/heads/main")["object"]["sha"] != base:
        return "base changed before opening the proposal"

    result = write("POST", f"{prefix}/pulls", {
        "title": f"Propose FCOS lab frontend {proposal.source[:12]}",
        "head": branch, "base": "main", "draft": True,
        "body": (
            f"Refs #93. Frontend lab pin only.\n\n"
            f"- [Publisher run {proposal.run_id}, attempt {proposal.run_attempt}]"
            f"(https://github.com/{UPSTREAM}/actions/runs/{proposal.run_id}/attempts/{proposal.run_attempt})\n"
            f"- Source `{proposal.source}` and OCI index `{proposal.index}`\n"
            f"- Native amd64 `{proposal.amd64}` and arm64 `{proposal.arm64}`\n"
            f"- Signed build evidence SHA-256 `{proposal.evidence}`\n\n"
            "The publisher attestation and both native subjects, CLEAN Grype/Trivy evidence and smoke results passed. "
            "Review current compatibility and approve the native required checks before merging. "
            "The existing timer handles activation after an accepted merge."
        ),
    })
    return f"draft proposal #{int(result['number'])} created"


def main():
    try:
        mode, = sys.argv[1:]
        text = Path(FILE).read_text(encoding="utf-8")
        value = json.load(sys.stdin)
        if mode == "verify":
            plan = candidate(value, Frontend.from_source(text))
            if plan is not None:
                print(json.dumps(asdict(plan), separators=(",", ":")))
        elif mode == "publish":
            print(publish(Proposal(**value), os.environ["GITHUB_SHA"], text))
        else:
            raise ValueError("unsupported proposal operation")
    except (BadZipFile, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        print("FCOS frontend proposal did not pass admission", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
