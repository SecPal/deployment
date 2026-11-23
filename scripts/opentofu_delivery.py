#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Deliver and independently admit provider repairs from the protected deployment branch."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location("opentofu_reconciliation", Path(__file__).with_name("reconcile-opentofu.py"))
RECONCILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECONCILE)
Rejected = RECONCILE.Rejected
require = RECONCILE.require
REPO = RECONCILE.REPOSITORY
APP = "secpal-opentofu-reconciler"
PREFIX = "automation/opentofu/"
PROVIDERS = {"google": "hashicorp/google", "digitalocean": "digitalocean/digitalocean"}
FIELDS = ("base", "source", "version", "proposals")
PULLS = "pulls?state=open&base=main&per_page=100"
SIGNING_STAGE = RECONCILE.GITHUB_WRITE
MERGE_STAGE = RECONCILE.PROTECTED_MERGE
REQUIRED = {
    "Repository Contract", "REUSE Compliance / Check REUSE Compliance", "Markdown and Shell",
    "Quadlet Contract (amd64)", "Quadlet Contract (arm64)", "Repository Security",
    "OpenSSH Account Contract", "DNF4 Exact NEVRA Contract", "Architecture Gate (Python 3.12.13)",
    "Architecture Gate (Python 3.13.14)", "auto-merge / Dependabot Source Safety",
}
COMMIT = "Reconcile OpenTofu provider locks"


class Deferred(Rejected):
    """Independently owned work overlaps this repair."""


def render_intent(intent):
    return json.dumps(intent, sort_keys=True, separators=(",", ":"))


def read_intent(text):
    require(len(text) <= 2048, "oversized reconciliation intent")
    intent = json.loads(text)
    require(isinstance(intent, dict) and set(intent) == set(FIELDS)
            and render_intent(intent) == text and intent["source"] in RECONCILE.PROVIDERS
            and RECONCILE.SHA.fullmatch(intent["base"])
            and re.fullmatch(RECONCILE.VERSION, intent["version"]), "invalid reconciliation intent")
    proposals = intent["proposals"]
    require(isinstance(proposals, list) and len(proposals) == len(RECONCILE.PROVIDERS[intent["source"]][0]),
            "incomplete reconciliation intent")
    require(all(isinstance(item, dict) and set(item) == {"number", "head"}
                and type(item["number"]) is int and item["number"] > 0
                and RECONCILE.SHA.fullmatch(item["head"]) for item in proposals), "invalid proposal evidence")
    numbers = [item["number"] for item in proposals]
    require(numbers == sorted(set(numbers)), "duplicate or unordered proposals")
    return intent


def candidate_ref(intent):
    provider = intent["source"].rsplit("/", 1)[1]
    fingerprint = hashlib.sha256(render_intent(intent).encode()).hexdigest()
    return f"{PREFIX}{provider}/{fingerprint}"


def candidate_paths(source):
    return {f"infra/ci-cloud/{directory}/{file}" for directory in RECONCILE.PROVIDERS[source][0]
            for file in (".terraform.lock.hcl", "versions.tf")}


def require_installation(slug, access):
    require(slug == APP and access["total_count"] == 1
            and [repo["full_name"] for repo in access["repositories"]] == [REPO],
            "unexpected GitHub App or installation repository access")


def app_actor(get):
    identity = get(f"users/{APP}[bot]")
    require(identity["login"] == f"{APP}[bot]" and identity["type"] == "Bot"
            and type(identity["id"]) is int and identity["id"] > 0, "repair App identity unavailable")
    return {key: identity[key] for key in ("login", "id", "type")}


def authored(actor, expected):
    return isinstance(actor, dict) and all(actor.get(key) == value for key, value in expected.items())


def repair_commit(get, head, actor, files=None):
    require(RECONCILE.SHA.fullmatch(head), "invalid repair commit identity")
    commit = get(f"commits/{head}")
    signature = get(f"commit-signature/{head}")
    verified = signature["signature"] or {}
    message = commit["commit"]["message"]
    message = message.rstrip("\n")
    title, separator, body = message.partition("\n\n")
    require(title == COMMIT and separator, "missing signed reconciliation intent")
    intent = read_intent(body)
    tree = commit["commit"]["tree"]["sha"]
    changed = [(item["filename"], item["status"]) for item in commit["files"]]
    payload = commit["commit"]["verification"].get("payload") or ""
    headers, _, signed_message = payload.partition("\n\n")
    author_email = f'{actor["id"]}+{actor["login"]}@users.noreply.github.com'
    require(commit["sha"] == signature["oid"] == head and RECONCILE.signed(commit)
            and authored(commit["author"], actor)
            and [item["sha"] for item in commit["parents"]] == [intent["base"]]
            and verified.get("isValid") is True and verified.get("state") == "VALID"
            and verified.get("wasSignedByGitHub") is True
            and headers.splitlines()[:2] == [f"tree {tree}", f'parent {intent["base"]}']
            and len(re.findall(rf"^author [^\n]+ <{re.escape(author_email)}> [0-9]+ [+-][0-9]{{4}}$",
                               headers, flags=re.MULTILINE)) == 1
            and signed_message.rstrip("\n") == message
            and sorted(changed) == [(path, "modified") for path in sorted(candidate_paths(intent["source"]))],
            "repair commit signature, parent, or changed paths are unauthorized")
    if files is not None:
        entries = RECONCILE.tree_entries(get, tree)
        require(set(files) == candidate_paths(intent["source"])
                and all(RECONCILE.read_blob(get, entries, path) == data for path, data in files.items()),
                "signed repair bytes differ from independent reconciliation")
    return intent


def repair_pr(pr, intent, head, actor):
    require(pr["state"] == "open" and pr.get("draft") is False and authored(pr["user"], actor)
            and pr["commits"] == 1 and pr["head"]["repo"]["full_name"] == REPO
            and pr["base"]["repo"]["full_name"] == REPO and pr["base"]["ref"] == "main"
            and pr["head"]["ref"] == candidate_ref(intent) and pr["head"]["sha"] == head,
            "unexpected repair PR provenance or state")


def reauthenticate(get, intent):
    RECONCILE.protected_base(get, intent["base"])
    first = intent["proposals"][0]
    source, version, proposals = RECONCILE.proposal_set(get, first["number"], first["head"], intent["base"])
    expected = sorted((item["number"], item["head"]) for item in intent["proposals"])
    require((source, version, sorted(proposals.values())) == (intent["source"], intent["version"], expected),
            "signed proposal set changed before delivery")
    RECONCILE.protected_base(get, intent["base"])


def save(output, report, files):
    output.mkdir(mode=0o700)
    for name, data in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data, encoding="utf-8")
    (output / "reconciliation.json").write_text(json.dumps(report, sort_keys=True), encoding="utf-8")


def read_plan(output):
    summary = output / "reconciliation.json"
    require(not output.is_symlink() and not summary.is_symlink() and summary.stat().st_size <= 8192,
            "unsafe reconciliation plan location")
    report = json.loads(summary.read_text())
    intent = read_intent(render_intent({key: report[key] for key in FIELDS}))
    require(set(report["files"]) == candidate_paths(intent["source"]), "unexpected provider file in delivery plan")
    files = {}
    for name, expected in report["files"].items():
        path = output / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 16384, "unsafe delivery file")
        data = path.read_bytes()
        require(len(data) <= 16384 and hashlib.sha256(data).hexdigest() == expected, "delivery plan bytes changed")
        files[name] = data.decode()
    return intent, files


def existing_prs(get, intent, actor):
    """Retain independently owned overlapping maintenance and identify obsolete App repairs."""
    expected_paths = candidate_paths(intent["source"])
    current = []
    stale = []
    for pr in get(PULLS):
        if RECONCILE.bot(pr["user"]):
            continue
        number, head = pr["number"], pr["head"]["sha"]
        ref = pr["head"]["ref"]
        if ref.startswith(PREFIX) and authored(pr["user"], actor):
            if ref.startswith(f'{PREFIX}{intent["source"].rsplit("/", 1)[1]}/'):
                existing = repair_commit(get, head, actor)
                repair_pr(pr, existing, head, actor)
                if existing == intent:
                    current.append(pr)
                else:
                    # The new plan already authenticates the complete current
                    # proposal set. The older, immutable snapshot is obsolete.
                    stale.append((number, head, existing))
            continue
        paths = {item["filename"] for item in get(f"pulls/{number}/files?per_page=100")}
        if expected_paths & paths:
            raise Deferred("an existing independently owned PR overlaps the provider repair")
    require(len(current) <= 1, "duplicate current repair PRs")
    return current, stale


def deliver(get, write, intent, files, actor):
    reauthenticate(get, intent)
    repairs, stale = existing_prs(get, intent, actor)
    require(set(files) == candidate_paths(intent["source"]), "unexpected paths in repair write")
    pr = repairs[0] if repairs else create_repair(get, write, intent, files, actor)
    repair_commit(get, pr["head"]["sha"], actor, files)
    for number, prior_head, prior in stale:
        reauthenticate(get, intent)
        repair_pr(get(f"pulls/{number}"), prior, prior_head, actor)
        require(write("close", {"number": number})["state"] == "closed", "obsolete repair was not closed")
    return pr["number"]


def branch_head(get, ref):
    # Matching an observed, paginated refs response distinguishes an absent
    # branch from transport failure. GitHub rejects simultaneous ref creation.
    refs = get(f"git/matching-refs/heads/{ref}")
    matches = [entry["object"]["sha"] for entry in refs if entry["ref"] == f"refs/heads/{ref}"]
    require(len(matches) <= 1, "ambiguous reconciliation ref")
    return matches[0] if matches else None


def create_repair(get, write, intent, files, actor):
    ref = candidate_ref(intent)
    head = branch_head(get, ref)
    if head is None:
        reauthenticate(get, intent)
        head = write("ref", {"ref": f"refs/heads/{ref}", "sha": intent["base"]})
        require(head == intent["base"], "created ref differs from the verified base")
    if head == intent["base"]:
        reauthenticate(get, intent)
        head = write("commit", {
            "branch": {"repositoryNameWithOwner": REPO, "branchName": ref},
            "expectedHeadOid": head,
            "message": {"headline": COMMIT, "body": render_intent(intent)},
            "fileChanges": {"additions": [{"path": name, "contents": base64.b64encode(data.encode()).decode()}
                                         for name, data in sorted(files.items())]},
        })
    require(repair_commit(get, head, actor, files) == intent, "unexpected commit read-back intent")
    reauthenticate(get, intent)
    require(branch_head(get, ref) == head, "repair branch changed before PR creation")
    new = write("pull", {
        "head": ref, "base": "main", "draft": False,
        "title": f'fix(deps): reconcile {intent["source"]} {intent["version"]}',
        "body": "Provider lock reconciliation from signed Dependabot proposals "
        + ", ".join(f'#{item["number"]}' for item in intent["proposals"])
        + ". Independent protected-base verification and all required checks apply.",
    })
    pr = get(f'pulls/{new["number"]}')
    repair_pr(pr, intent, head, actor)
    return pr


def merge_ready(pr, head, base, checks):
    names = [check["name"] for check in checks]
    return (pr["headRefOid"] == head and pr["baseRefOid"] == base and pr["mergeStateStatus"] == "CLEAN"
            and REQUIRED.issubset(names) and len(set(names)) == len(names)
            and all(check["bucket"] == "pass" for check in checks))


class GitHub:
    def __init__(self, executable):
        self.executable = str(executable)

    def call(self, args, stage, *, payload=None, acceptable=(0,)):
        result = subprocess.run([self.executable, *args], input=json.dumps(payload) if payload is not None else None,
                                capture_output=True, text=True, timeout=90, check=False)
        require(result.returncode in acceptable, f"{stage}: GitHub declined the bounded operation")
        return result.stdout

    def get(self, endpoint):
        if endpoint.startswith(("users/", "installation/")):
            return json.loads(self.call(["api", "--hostname", "github.com", "--method", "GET", endpoint],
                                        RECONCILE.GITHUB_READ))
        return RECONCILE.github_get(self.executable, endpoint)

    def write(self, action, payload):
        if action == "commit":
            query = """mutation($input:CreateCommitOnBranchInput!){
              createCommitOnBranch(input:$input){commit{oid}}}"""
            response = self.call(["api", "--hostname", "github.com", "graphql", "--input", "-"], SIGNING_STAGE,
                                 payload={"query": query, "variables": {"input": payload}})
            return json.loads(response)["data"]["createCommitOnBranch"]["commit"]["oid"]
        if action == "close":
            endpoint, method = f'pulls/{payload["number"]}', "PATCH"
            payload = {"state": "closed"}
        else:
            endpoint, method = {"ref": "git/refs", "pull": "pulls"}[action], "POST"
        result = json.loads(self.call(["api", "--hostname", "github.com", "--method", method,
                                       f"repos/{REPO}/{endpoint}", "--input", "-"],
                                      SIGNING_STAGE, payload=payload))
        return result["object"]["sha"] if action == "ref" else result

    def ready(self, number, intent, head):
        repo_arg = "github.com/" + REPO
        command = ["pr", "view", str(number), "-R", repo_arg,
                   "--json", "headRefOid,baseRefOid,mergeStateStatus"]
        pr = json.loads(self.call(command, MERGE_STAGE))
        checks = json.loads(self.call(["pr", "checks", str(number), "-R", repo_arg, "--required",
                                       "--json", "name,bucket"], MERGE_STAGE, acceptable=(0, 1, 8)))
        return merge_ready(pr, head, intent["base"], checks)

    def merge(self, number, intent, head, actor):
        if not self.ready(number, intent, head):
            print("Protected merge awaits all required checks on the independently verified repair.")
            return
        reauthenticate(self.get, intent)
        repair_pr(self.get(f"pulls/{number}"), intent, head, actor)
        self.call(["pr", "merge", str(number), "-R", "github.com/" + REPO, "--auto", "--squash",
                   "--match-head-commit", head], MERGE_STAGE)


def select(get, mode, source, base, number, head):
    RECONCILE.protected_base(get, base)
    proposals = [get(f"pulls/{number}")] if number else get(PULLS)
    for pr in sorted(proposals, key=lambda item: item["number"]):
        if mode == "prepare":
            match = RECONCILE.BRANCH.fullmatch(pr["head"]["ref"])
            eligible = RECONCILE.bot(pr["user"]) and match and match["source"] == source
        else:
            eligible = pr["head"]["ref"].startswith(f'{PREFIX}{source.rsplit("/", 1)[1]}/')
        if eligible:
            require(not number or pr["head"]["sha"] == head, "event head has changed")
            return pr
    return None


def run(flags, github):
    get = github.get
    source = PROVIDERS[flags.provider]
    if flags.mode == "deliver":
        require_installation(flags.app_slug, get("installation/repositories?per_page=100"))
        intent, files = read_plan(flags.output)
        require(intent["base"] == flags.base and intent["source"] == source, "delivery context differs from plan")
        print(f"Verified repair PR #{deliver(get, github.write, intent, files, app_actor(get))}")
        return
    pr = select(get, flags.mode, source, flags.base, flags.pr, flags.head)
    if pr is None:
        return
    number, head = pr["number"], pr["head"]["sha"]
    if flags.mode == "admit":
        actor = app_actor(get)
        intent = repair_commit(get, head, actor)
        if intent["base"] != flags.base:
            print("Repair is stale. Waiting for the next signed proposal snapshot.")
            return
        repair_pr(pr, intent, head, actor)
        if not flags.pr and not github.ready(number, intent, head):
            print("Scheduled repair still awaits all protected checks.")
            return
        first = intent["proposals"][0]
        trigger, original = first["number"], first["head"]
    else:
        trigger, original = number, head
    report, files = RECONCILE.reconcile(
        get, trigger, original, flags.base,
        lambda provider, version: RECONCILE.generate_lock(flags.tofu.resolve(strict=True), provider, version),
    )
    if flags.mode == "prepare":
        save(flags.output, report, files)
        return
    rebuilt = {key: report[key] for key in FIELDS}
    require(intent == rebuilt == repair_commit(get, head, actor, files), "repair differs from independent reproduction")
    print(f"Independently verified repair PR #{number} at {head}")
    github.merge(number, intent, head, actor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "deliver", "admit"))
    parser.add_argument("--provider", choices=PROVIDERS, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--pr", type=int, default=0)
    parser.add_argument("--head", default="")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--tofu", type=Path, required=True)
    parser.add_argument("--app-slug", default="")
    flags = parser.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == REPO
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GITHUB_SHA") == flags.base
                and os.environ.get("GITHUB_REF_PROTECTED") == "true", "untrusted workflow source")
        require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, timeout=15,
                                        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}).strip() == flags.base,
                "checkout differs from protected workflow source")
        RECONCILE.admit_dispatch(flags.governance.resolve(strict=True))
        with tempfile.TemporaryDirectory(prefix="opentofu-delivery-gh-") as path:
            run(flags, GitHub(RECONCILE.admit_github_cli(Path(path))))
    except Deferred as reason:
        print(f"OpenTofu delivery deferred: {reason}")
        return 0
    except Rejected as error:
        print(f"OpenTofu delivery declined: {error}", file=sys.stderr)
        return 1
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        print("OpenTofu delivery failed without complete authenticated evidence", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
