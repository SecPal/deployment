#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Report candidates from the maintained FCOS lab publishers."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from zipfile import BadZipFile

from fcos_lab_rollout_adapter import Backend, DIGEST, QualificationUnavailable, RUNTIME_SOURCE
from fcos_lab_rollout_adapter import github_json, qualified_backend_source, qualified_frontend_source, verified_gh
from integration_runtime_contract import LAB_FRONTEND_SOURCE_COMMIT


def greatest_version(tags, pattern):
    versions = []
    for tag in tags:
        match = re.fullmatch(pattern, tag)
        if match:
            versions.append((tuple(map(int, match.groups())), tag))
    if not versions:
        raise ValueError("no candidate in the supported version track")
    return max(versions)[1]


def official_tag(catalog, pattern):
    tags = (
        tag.strip()
        for line in catalog.splitlines()
        if line.startswith("Tags: ")
        for tag in line.removeprefix("Tags: ").split(",")
    )
    return greatest_version(tags, pattern)


def stable_release(releases, pattern):
    return greatest_version(
        (release["tag_name"] for release in releases
         if release["draft"] is False and release["prerelease"] is False),
        pattern,
    )


REGISTRY_EVENTS = {"SecPal/api": "workflow_dispatch", "SecPal/frontend": "push"}


def registry_publications(repo):
    return (
        f"repos/{repo}/actions/workflows/publish-container.yml/runs"
        f"?branch=main&status=success&per_page=1&event={REGISTRY_EVENTS[repo]}"
    )


def product_candidate(document, repo):
    run, = document["workflow_runs"]
    commit = run["head_sha"]
    run_id, attempt = run["id"], run["run_attempt"]
    if (
        run["head_branch"] != "main"
        or run["event"] != REGISTRY_EVENTS[repo]
        or run["conclusion"] != "success"
        or run["head_repository"]["full_name"].lower() != repo.lower()
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or type(run_id) is not int
        or run_id <= 0
        or type(attempt) is not int
        or attempt <= 0
    ):
        raise ValueError("invalid product publish result")
    return {"source_commit": commit, "run_id": run_id, "run_attempt": attempt}


def source_relationship(document):
    status = document["status"]
    if status not in {"identical", "ahead", "behind", "diverged"}:
        raise ValueError("invalid GitHub source comparison")
    return status


def get(endpoint, *, raw=False, paginate=False, gh="gh"):
    args = [gh, "api", "--hostname", "github.com", "--method", "GET", endpoint]
    if raw:
        args += ["--header", "Accept: application/vnd.github.raw+json"]
    if paginate:
        args += ["--paginate", "--slurp"]
    output = subprocess.run(
        args, capture_output=True, stdin=subprocess.DEVNULL,
        check=True, timeout=45, text=True,
    ).stdout
    if raw:
        return output
    data = json.loads(output)
    return [item for page in data for item in page] if paginate else data


def discover():
    result = {}
    contract = Path(__file__).with_name(Path(RUNTIME_SOURCE).name)
    products = {"api": Backend.from_source(contract.read_text(encoding="utf-8")).source,
                "frontend": LAB_FRONTEND_SOURCE_COMMIT}
    for name, commit in products.items():
        repo = f"SecPal/{name}"
        publication = product_candidate(get(registry_publications(repo)), repo)
        relationship = get(f"repos/{repo}/compare/{commit}...{publication['source_commit']}")
        result[name] = {**publication, "source_relationship": source_relationship(relationship)}

    for image, pattern in {
        "postgres": r"(18)\.([0-9]+)-bookworm",
        "haproxy": r"(3)\.(2)\.([0-9]+)-trixie",
    }.items():
        catalog = get(f"repos/docker-library/official-images/contents/library/{image}", raw=True)
        result[image] = official_tag(catalog, pattern)

    for name, (repo, pattern) in {
        "crowdsec": ("crowdsecurity/crowdsec", r"v(1)\.([0-9]+)\.([0-9]+)"),
        "spoa": ("crowdsecurity/cs-haproxy-spoa-bouncer", r"v(0)\.([0-9]+)\.([0-9]+)"),
        "crs": ("coreruleset/coreruleset", r"v(4)\.([0-9]+)\.([0-9]+)"),
    }.items():
        result[name] = stable_release(get(f"repos/{repo}/releases?per_page=100"), pattern)
    return result


def protected_source(product, gh):
    branch = github_json(gh, f"repos/SecPal/{product}/branches/main")
    source = branch["commit"]["sha"]
    if branch["name"] != "main" or branch["protected"] is not True or re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise ValueError("upstream main is not protected")
    return source


def qualified_candidate(product, gh, *, current=True, installed_source=None):
    """Report the exact protected-main candidate without conferring deployment authority."""
    if product not in {"frontend", "api"}:
        raise ValueError("unknown product")
    with tempfile.TemporaryDirectory(prefix="fcos-lab-discovery-") as directory:
        environment = {"PATH": "/usr/bin:/bin", "HOME": directory, "GH_CONFIG_DIR": directory,
                       "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_TELEMETRY": "false"}
        verified_gh(gh, environment)
    source = protected_source(product, gh)
    if source == installed_source:
        return None
    verify = qualified_frontend_source if product == "frontend" else qualified_backend_source
    with verify(source, gh, current=current) as result:
        _, run_id, attempt, children, *documents = result
        detail = {"source_commit": source, "run_id": run_id, "run_attempt": attempt,
                  "native": {f"{role}:{platform}": digest for (role, platform), digest in sorted(children.items())}}
        if product == "frontend":
            receipt, _, _, index = documents[0]
            detail["index"] = "sha256:" + hashlib.sha256(index.read_bytes()).hexdigest()
            detail["receipt"] = "sha256:" + hashlib.sha256(receipt.read_bytes()).hexdigest()
        else:
            directory = documents[0]
            raw = (directory / "unpublished-runtime-pair.json").read_bytes()
            pair = json.loads(raw)
            indexes = {role: image["candidate_index_digest"] for role, image in pair["images"].items()}
            if any(re.fullmatch(DIGEST, value) is None for value in indexes.values()):
                raise ValueError("invalid API index")
            deadline = datetime.fromisoformat(
                json.loads((directory / "source-security.json").read_bytes())["database"]["next_update"])
            if deadline.utcoffset() is None:
                raise ValueError("API source-security deadline has no timezone")
            detail.update({
                "indexes": indexes,
                "receipt": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "source_security_expires": deadline.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
    # Recheck after verification so superseded inputs cannot be advertised as current.
    if protected_source(product, gh) != source:
        raise QualificationUnavailable("upstream main changed during discovery")
    return detail


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualified", choices=("frontend", "api"))
    parser.add_argument("--gh", type=Path, help="verified GitHub CLI for archived candidate discovery")
    args = parser.parse_args(argv)
    if (args.qualified is None) != (args.gh is None):
        parser.error("--qualified and --gh must be supplied together")
    try:
        result = qualified_candidate(args.qualified, args.gh.absolute()) if args.qualified else discover()
        print(json.dumps(result, indent=2, sort_keys=True))
    except (BadZipFile, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        print("FCOS release discovery failed to admit a complete upstream report", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
