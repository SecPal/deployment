#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Build lockfile repairs from the current signed Dependabot proposals."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from platform import machine

sys.path.insert(0, str(Path(__file__).resolve().parent))
from image_attestation_runtime import CLOUD_GH_RELEASES, stage_gh_cli

REPOSITORY = "SecPal/deployment"
BOT = {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"}
GITHUB_SIGNER = {"login": "web-flow", "databaseId": 19864447}
BOT_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
ROOT = Path(__file__).resolve().parents[1]
GOVERNANCE_REVISION = "70c90d00ce8f293c217ea8fe4bc5caf0554a6c43"
GITHUB_CLI = "opentofu-reconciliation.github-cli"
GITHUB_READ = "opentofu-reconciliation.github-read"
PROVIDER_LOCK = "opentofu-reconciliation.provider-lock"
DISPATCH_OPERATIONS = (GITHUB_CLI, GITHUB_READ, PROVIDER_LOCK)
TOFU_SHA256 = "36dae7ca1e4f1552a6faef27179dc16ef403203e956f31416c17b3d87a38c3f4"
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}"
PIN = re.compile(rf'^ *version += "(?P<constraint>(?:= *)?(?P<version>{VERSION}))"$', re.MULTILINE)
BRANCH = re.compile(
    rf"dependabot/opentofu/infra/ci-cloud/(?P<directory>[a-z-]+)/"
    rf"(?P<source>[a-z0-9-]+/[a-z0-9-]+)-(?P<version>{VERSION})"
)
LOCK = re.compile(
    r'\A# This file is maintained automatically by "tofu init"\.\n'
    r"# Manual edits may be lost in future updates\.\n\n"
    rf'provider "registry\.opentofu\.org/(?P<source>[a-z0-9-]+/[a-z0-9-]+)" {{\n'
    rf'  version     = "(?P<version>{VERSION})"\n'
    rf'  constraints = "(?:= *)?(?P<constraint>{VERSION})"\n'
    r'  hashes = \[\n(?P<hashes>(?:    "[^"\n]+",\n)+)  \]\n\}\n\Z'
)
PLATFORMS = (
    "darwin_amd64", "darwin_arm64", "freebsd_386", "freebsd_amd64", "freebsd_arm",
    "linux_386", "linux_amd64", "linux_arm", "linux_arm64", "openbsd_386",
    "openbsd_amd64", "windows_386", "windows_amd64", "windows_arm64",
)
PROVIDERS = {
    "hashicorp/google": ({"gcp", "gcp-rocky"}, (*PLATFORMS, "solaris_amd64")),
    "digitalocean/digitalocean": ({"digitalocean"}, (*PLATFORMS, "freebsd_arm64", "windows_arm")),
}


class Rejected(ValueError):
    """The proposal or its package evidence could not be admitted."""


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def signed(commit):
    verification = commit["commit"]["verification"]
    return verification.get("verified") is True and verification.get("reason") == "valid"


def bot(actor):
    return actor is not None and all(actor.get(key) == value for key, value in BOT.items())


def verify_bot_signature(get, oid, base, commit):
    response = get(f"commit-signature/{oid}")
    signature = response["signature"] or {}
    payload = commit["commit"]["verification"].get("payload") or ""
    headers = payload.partition("\n\n")[0].splitlines()
    tree = commit["commit"]["tree"]["sha"]
    require(response["oid"] == oid and signature.get("__typename") == "GpgSignature"
            and signature.get("isValid") is True and signature.get("state") == "VALID"
            and signature.get("wasSignedByGitHub") is True and signature.get("signer") == GITHUB_SIGNER
            and len(headers) == 4 and headers[:2] == [f"tree {tree}", f"parent {base}"]
            and re.fullmatch(rf"author {re.escape(BOT['login'])} <{re.escape(BOT_EMAIL)}> [0-9]+ [+-][0-9]{{4}}", headers[2])
            and re.fullmatch(r"committer GitHub <noreply@github\.com> [0-9]+ [+-][0-9]{4}", headers[3]),
            "the GitHub platform signature does not bind the exact Dependabot author and parent")


def validate_dispatch_coverage(declaration):
    operations = json.loads(declaration.read_text(encoding="utf-8"))["external_operations"]
    expected = [
        {"id": name, "reachable": True, "fallible": True, "trusted": True,
         "diagnostic_identity": {"id": name, "kind": "semantic"}}
        for name in DISPATCH_OPERATIONS
    ]
    actual = [item for item in operations if item["id"].startswith("opentofu-reconciliation.")]
    require(sorted(actual, key=lambda item: item["id"]) == expected,
            "OpenTofu reconciliation diagnostic coverage is incomplete")


def admit_dispatch(governance):
    validate_dispatch_coverage(ROOT / ".secpal/evidence-architecture.json")
    source = ["git", "--no-replace-objects", "-C", str(governance)]
    try:
        revision = subprocess.check_output([*source, "rev-parse", "HEAD"], text=True, timeout=15).strip()
        require(revision == GOVERNANCE_REVISION, "wrong canonical evidence architecture revision")
        subprocess.run(
            [*source, "diff", "--quiet", "HEAD", "--", "scripts/secpal-evidence-architecture.py",
             "scripts/secpal_evidence_architecture", "package.json", "package-lock.json"],
            check=True, timeout=15,
        )
        subprocess.run(
            [sys.executable, "-I", "-S", str(governance / "scripts/secpal-evidence-architecture.py"),
             "--repository-root", str(ROOT), "--repository", REPOSITORY, "--dispatch"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True, timeout=60,
        )
    except subprocess.SubprocessError:
        raise Rejected("canonical evidence architecture refused OpenTofu reconciliation dispatch") from None


def protected_base(get, expected):
    branch = get("branches/main")
    commit = branch["commit"]
    require(SHA.fullmatch(expected) and branch["protected"] is True
            and commit["sha"] == expected and signed(commit), "protected main is unverified or has moved")
    return commit["commit"]["tree"]["sha"]


def proposal_identity(proposal, base, head):
    match = BRANCH.fullmatch(proposal["head"]["ref"])
    require(proposal["state"] == "open" and bot(proposal["user"])
            and proposal["commits"] == 1 and proposal["base"]["ref"] == "main"
            and proposal["base"]["repo"]["full_name"] == REPOSITORY
            and proposal["base"]["sha"] == base and SHA.fullmatch(head)
            and proposal["head"]["repo"] is not None
            and proposal["head"]["repo"]["full_name"] == REPOSITORY
            and proposal["head"]["sha"] == head and match is not None,
            "proposal is not a current, single-commit Dependabot source")
    directory, source, version = match.group("directory", "source", "version")
    require(source in PROVIDERS and directory in PROVIDERS[source][0], "unsupported provider or directory")
    return directory, source, version


def proposal_set(get, trigger, head, base):
    primary = get(f"pulls/{trigger}")
    require(primary["number"] == trigger, "wrong proposal identity")
    _, source, version = proposal_identity(primary, base, head)
    proposals = {trigger: primary}
    for other in get("pulls?state=open&base=main&per_page=100"):
        match = BRANCH.fullmatch(other["head"]["ref"])
        if (bot(other["user"]) and match is not None and match["source"] == source
                and other["number"] != trigger):
            number = other["number"]
            require(type(number) is int and number > 0, "invalid proposal number")
            exact = get(f"pulls/{number}")
            require(exact["number"] == number and exact["head"]["sha"] == other["head"]["sha"],
                    "proposal head changed during discovery")
            proposals[number] = exact
    observed = {}
    for number, proposal in sorted(proposals.items()):
        oid = proposal["head"]["sha"]
        directory, peer, target = proposal_identity(proposal, base, oid)
        require(peer == source and target == version and directory not in observed,
                "conflicting or duplicate proposals for the same provider")
        observed[directory] = (number, oid)
    require(set(observed) == PROVIDERS[source][0], "the provider lacks a matching signed proposal for each root")
    return source, version, observed


def tree_entries(get, tree):
    require(SHA.fullmatch(tree), "invalid tree identity")
    response = get(f"git/trees/{tree}?recursive=1")
    require(response["truncated"] is False, "could not observe the complete source tree")
    entry_map = {item["path"]: item for item in response["tree"]}
    require(len(entry_map) == len(response["tree"]), "ambiguous tree paths")
    return entry_map


def read_blob(get, entries, path):
    entry = entries[path]
    oid = entry["sha"]
    require(entry["type"] == "blob" and entry["mode"] == "100644" and SHA.fullmatch(oid),
            "a required input is not a regular data file")
    blob = get(f"git/blobs/{oid}")
    require(blob["encoding"] == "base64" and blob["sha"] == oid, "wrong blob encoding or identity")
    data = base64.b64decode("".join(blob["content"].splitlines()), validate=True)
    # GitHub already verifies the signed commit. Match Git's SHA-1 blob identifier on read-back.
    require(len(data) <= 16384 and hashlib.sha1(
        f"blob {len(data)}\0".encode() + data, usedforsecurity=False,
    ).hexdigest() == oid,
            "Git blob exceeds its boundary or differs from the observed digest")
    return data.decode()


def manifest_update(original, updated, source, target):
    before = list(PIN.finditer(original))
    after = list(PIN.finditer(updated))
    require(len(before) == len(after) == 1 and f'source  = "{source}"' in original,
            "ambiguous manifest pin or wrong provider source")
    before, after = before[0], after[0]
    require(after["version"] == target and
            original[:before.start("constraint")] + original[before.end("constraint"):]
            == updated[:after.start("constraint")] + updated[after.end("constraint"):],
            "the manifest changes more than the requested exact pin")
    old = before["version"]
    old_parts = tuple(map(int, old.split(".")))
    new_parts = tuple(map(int, target.split(".")))
    require(new_parts[0] == old_parts[0] and new_parts > old_parts, "only stable PATCH and MINOR upgrades qualify")
    return old


def lock_hashes(text, source, version, constraints):
    match = LOCK.fullmatch(text)
    require(match is not None and match["source"] == source and match["version"] == version
            and match["constraint"] in constraints, "wrong provider, version, or constraint in lockfile")
    values = re.findall(r'"([^"]+)"', match["hashes"])
    unique = set(values)
    count = len(PROVIDERS[source][1])
    package = {value for value in unique if re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", value)}
    archive = {value for value in unique if re.fullmatch(r"zh:[0-9a-f]{64}", value)}
    require(len(values) == len(unique) and package | archive == unique
            and len(package) == count and len(archive) >= count, "invalid or incomplete provider checksum inventory")
    return unique


def generate_lock(executable, source, version):
    require(source in PROVIDERS and re.fullmatch(VERSION, version), "unrecognized registry input")
    with executable.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == TOFU_SHA256,
                "OpenTofu binary does not match the verified 1.12.5 release")
    with tempfile.TemporaryDirectory(prefix="opentofu-provider-lock-") as path:
        work = Path(path)
        provider = source.split("/")[-1]
        configuration = {"terraform": {"required_version": "1.12.5", "required_providers": {
            provider: {"source": f"registry.opentofu.org/{source}", "version": version},
        }}}
        (work / "versions.tf.json").write_text(json.dumps(configuration), encoding="utf-8")
        cli_config = work / "direct.tfrc"
        cli_config.write_text("provider_installation { direct {} }\n", encoding="utf-8")
        platforms = PROVIDERS[source][1]
        try:
            process = subprocess.run(
                [str(executable), "providers", "lock", "-no-color",
                 *(f"-platform={platform}" for platform in platforms), f"registry.opentofu.org/{source}"],
                cwd=work, check=True, capture_output=True, text=True, timeout=1200,
                env={
                    "PATH": "/usr/bin:/bin", "HOME": path, "XDG_CONFIG_HOME": path,
                    "TF_CLI_CONFIG_FILE": str(cli_config), "TF_IN_AUTOMATION": "1",
                    "OPENTOFU_ENFORCE_GPG_VALIDATION": "true", "OPENTOFU_ENFORCE_GPG_EXPIRATION": "true",
                },
            )
        except subprocess.SubprocessError:
            raise Rejected(f"{PROVIDER_LOCK}: signature-verified lock generation failed") from None
        verified = re.findall(
            rf"^- Retrieved {re.escape(source)} {re.escape(version)} for (\w+) "
            r"\(signed(?: by [^()\r\n]{1,120})?, key ID [0-9A-Fa-f]{8,40}\)$",
            process.stdout, re.MULTILINE,
        )
        require(sorted(verified) == sorted(platforms),
                f"{PROVIDER_LOCK}: missing signed provider package on a required platform")
        try:
            return (work / ".terraform.lock.hcl").read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise Rejected(f"{PROVIDER_LOCK}: missing or invalid generated lockfile") from None


def reconcile(get, trigger, head, base, generate):
    base_tree = tree_entries(get, protected_base(get, base))
    source, version, proposals = proposal_set(get, trigger, head, base)
    files = {}
    proposed_hashes = []
    previous_versions = set()
    for directory, (_, oid) in sorted(proposals.items()):
        manifest = f"infra/ci-cloud/{directory}/versions.tf"
        lock = f"infra/ci-cloud/{directory}/.terraform.lock.hcl"
        commit = get(f"commits/{oid}")
        changes = [(entry["filename"], entry["status"]) for entry in commit["files"]]
        require(commit["sha"] == oid and bot(commit["author"]) and commit["committer"]["login"] == "web-flow"
                and signed(commit) and [item["sha"] for item in commit["parents"]] == [base]
                and sorted(changes) == [(lock, "modified"), (manifest, "modified")],
                "signed commit provenance or changed files do not match the proposal")
        verify_bot_signature(get, oid, base, commit)
        candidate_tree = tree_entries(get, commit["commit"]["tree"]["sha"])
        old_manifest = read_blob(get, base_tree, manifest)
        files[manifest] = read_blob(get, candidate_tree, manifest)
        old_version = manifest_update(old_manifest, files[manifest], source, version)
        previous_versions.add(old_version)
        lock_hashes(read_blob(get, base_tree, lock), source, old_version, {old_version})
        proposed_hashes.append(lock_hashes(read_blob(get, candidate_tree, lock), source, version, {old_version, version}))
    require(len(previous_versions) == 1 and all(value == proposed_hashes[0] for value in proposed_hashes),
            "provider roots disagree on the old version or proposed checksums")
    generated = generate(source, version)
    require(lock_hashes(generated, source, version, {version}) == proposed_hashes[0],
            "independently signed registry checksums differ from the Dependabot proposal")
    for directory in proposals:
        files[f"infra/ci-cloud/{directory}/.terraform.lock.hcl"] = generated

    require(proposal_set(get, trigger, head, base) == (source, version, proposals),
            "the signed proposal set changed during reconciliation")
    protected_base(get, base)
    report = {
        "repository": REPOSITORY, "base": base, "source": source,
        "previousVersion": next(iter(previous_versions)), "version": version,
        "proposals": [{"number": number, "head": oid} for number, oid in sorted(proposals.values())],
        "platforms": sorted(PROVIDERS[source][1]),
        "files": {path: hashlib.sha256(text.encode()).hexdigest() for path, text in sorted(files.items())},
    }
    return report, files


def admit_github_cli(directory):
    release = CLOUD_GH_RELEASES.get(machine())
    require(release is not None, f"{GITHUB_CLI}: unsupported runner architecture")

    def fetch_archive(argv, environment):
        subprocess.run(argv, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True, timeout=190)

    try:
        return stage_gh_cli(directory, release, fetch_archive, {"HOME": str(directory), "PATH": "/usr/bin:/bin"})
    except (OSError, ValueError, subprocess.SubprocessError):
        raise Rejected(f"{GITHUB_CLI}: the approved executable could not be staged") from None


def github_get(executable, endpoint):
    command = [executable, "api", "--hostname", "github.com"]
    paginated = endpoint.startswith("pulls?")
    signature = endpoint.startswith("commit-signature/")
    if signature:
        oid = endpoint.split("/")[1]
        query = """query($oid:GitObjectID!){
          repository(owner:"SecPal",name:"deployment"){
            object(oid:$oid){... on Commit{
              oid signature{__typename isValid state wasSignedByGitHub signer{login databaseId}}
            }}
          }
        }"""
        command.extend(["graphql", "-f", f"query={query}", "-f", f"oid={oid}"])
    else:
        command.extend(["--method", "GET", *(["--paginate", "--slurp"] if paginated else []),
                        f"repos/{REPOSITORY}/{endpoint}"])
    try:
        output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=90)
        response = json.loads(output.stdout)
        if signature:
            return response["data"]["repository"]["object"]
    except (KeyError, OSError, ValueError, subprocess.SubprocessError):
        raise Rejected(f"{GITHUB_READ}: GitHub source evidence could not be retrieved") from None
    return [item for page in response for item in page] if paginated else response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--tofu", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    flags = parser.parse_args()
    try:
        require(flags.pr > 0, "invalid proposal number")
        admit_dispatch(flags.governance.resolve(strict=True))
        with tempfile.TemporaryDirectory(prefix="opentofu-github-cli-") as path:
            github_cli = admit_github_cli(Path(path))
            report, files = reconcile(
                lambda endpoint: github_get(github_cli, endpoint), flags.pr, flags.head, flags.base,
                lambda source, version: generate_lock(flags.tofu.resolve(strict=True), source, version),
            )
        flags.output.mkdir(mode=0o700)
        for name, text in sorted(files.items()):
            destination = flags.output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
        (flags.output / "reconciliation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Verified {report['source']} {report['version']} from signed Dependabot source")
    except Rejected as error:
        print(f"OpenTofu reconciliation declined: {error}", file=sys.stderr)
        return 1
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        print("OpenTofu reconciliation failed without complete authenticated evidence", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
