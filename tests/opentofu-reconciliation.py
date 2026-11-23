#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Exercise signed provider proposals without writing GitHub or running OpenTofu."""

import base64
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reconcile_opentofu", ROOT / "scripts/reconcile-opentofu.py")
RECONCILER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECONCILER
SPEC.loader.exec_module(RECONCILER)

BASE = "a" * 40
BOT = {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"}
VERIFIED = {"verified": True, "reason": "valid"}
DO, GOOGLE = "digitalocean/digitalocean", "hashicorp/google"


def hashes(provider, offset):
    count = len(RECONCILER.PROVIDERS[provider][1])
    return [
        *(f"h1:{base64.b64encode(bytes([n]) * 32).decode()}" for n in range(offset, offset + count)),
        *(f"zh:{n:064x}" for n in range(offset, offset + count)),
    ]


def lock(provider, version, constraint, items):
    digests = "".join(f'    "{item}",\n' for item in items)
    return (
        '# This file is maintained automatically by "tofu init".\n'
        "# Manual edits may be lost in future updates.\n\n"
        f'provider "registry.opentofu.org/{provider}" {{\n'
        f'  version     = "{version}"\n'
        f'  constraints = "{constraint}"\n'
        f"  hashes = [\n{digests}  ]\n}}\n"
    )


class GitHub:
    def __init__(self):
        self.routes = {
            "branches/main": {
                "protected": True,
                "commit": {"sha": BASE, "commit": {"verification": VERIFIED, "tree": {"sha": "1" * 40}}},
            },
            "git/trees/" + "1" * 40 + "?recursive=1": {"truncated": False, "tree": []},
        }
        self.open = []

    def get(self, endpoint):
        if endpoint == "pulls?state=open&base=main&per_page=100":
            return copy.deepcopy(self.open)
        return copy.deepcopy(self.routes[endpoint])

    def add(self, number, directory, provider, old, new, *, old_equals=False):
        head = f"{number:040x}"
        tree = f"{number + 100:040x}"
        repo = {"full_name": "SecPal/deployment"}
        head_ref = f"dependabot/opentofu/infra/ci-cloud/{directory}/{provider}-{new}"
        pr = {
            "user": BOT,
            "number": number,
            "state": "open",
            "commits": 1,
            "base": {"repo": repo, "ref": "main", "sha": BASE},
            "head": {"repo": repo, "ref": head_ref, "sha": head},
        }
        self.open.append(pr)
        self.routes[f"pulls/{number}"] = pr
        paths = [f"infra/ci-cloud/{directory}/{name}" for name in ("versions.tf", ".terraform.lock.hcl")]
        git_file = (ROOT / paths[0]).read_text()
        base_pin = f"= {old}" if old_equals else old
        current_pin = RECONCILER.PIN.search(git_file)["constraint"]
        base_manifest = git_file.replace(f'version = "{current_pin}"', f'version = "{base_pin}"')
        new_manifest = base_manifest.replace(f'version = "{base_pin}"', f'version = "{new}"')
        self.routes[f"commits/{head}"] = {
            "sha": head, "parents": [{"sha": BASE}], "author": BOT, "committer": {"login": "web-flow"},
            "commit": {"verification": dict(VERIFIED), "tree": {"sha": tree}},
            "files": [{"filename": path, "status": "modified"} for path in paths],
        }
        self.routes[f"git/trees/{tree}?recursive=1"] = {"truncated": False, "tree": []}
        for path, original, updated in zip(
            paths, [base_manifest, lock(provider, old, old, hashes(provider, 1))],
            [new_manifest, lock(provider, new, old, hashes(provider, 30))], strict=True,
        ):
            self.set_file("1" * 40, path, original)
            self.set_file(tree, path, updated)
        return head

    def set_file(self, tree, path, data, mode="100644"):
        body = data.encode()
        sha = hashlib.sha1(f"blob {len(body)}\0".encode() + body).hexdigest()
        entries = self.routes[f"git/trees/{tree}?recursive=1"]["tree"]
        entries[:] = [item for item in entries if item["path"] != path]
        entries.append({"path": path, "mode": mode, "type": "blob", "sha": sha})
        self.routes[f"git/blobs/{sha}"] = {
            "sha": sha, "encoding": "base64", "content": base64.b64encode(body).decode(),
        }


class ProviderReconciliation(unittest.TestCase):
    def setUp(self):
        self.github = GitHub()

    def reconcile(self, head, generator=None):
        return RECONCILER.reconcile(
            self.github.get, 460, head, BASE,
            generator or (lambda source, version: lock(source, version, version, hashes(source, 30))),
        )

    def test_patch_keeps_only_the_signed_digitalocean_update(self):
        head = self.github.add(460, "digitalocean", DO, "2.107.0", "2.107.1", old_equals=True)
        report, files = self.reconcile(head)
        self.assertEqual(report["base"], BASE)
        self.assertEqual(report["source"], DO)
        self.assertEqual(report["proposals"], [{"number": 460, "head": head}])
        self.assertEqual(len(files), 2)
        self.assertIn('constraints = "2.107.1"', files["infra/ci-cloud/digitalocean/.terraform.lock.hcl"])
        self.assertEqual((report, files), self.reconcile(head))

    def test_matching_google_minor_heads_coalesce_independent_of_event_order(self):
        head = self.github.add(460, "gcp", GOOGLE, "8.11.0", "8.12.0")
        sibling = self.github.add(461, "gcp-rocky", GOOGLE, "8.11.0", "8.12.0")
        report, files = self.reconcile(head)
        other_report, other_files = RECONCILER.reconcile(
            self.github.get, 461, sibling, BASE,
            lambda provider, version: lock(provider, version, version, hashes(provider, 30)),
        )
        self.assertEqual((report, files), (other_report, other_files))
        self.assertEqual(len(files), 4)
        self.assertIn("linux_amd64", report["platforms"])
        self.assertIn("linux_arm64", report["platforms"])

    def test_differing_google_versions_or_duplicate_heads_fail_before_generation(self):
        for version, directory in [("8.13.0", "gcp-rocky"), ("8.12.0", "gcp")]:
            with self.subTest(version=version, directory=directory):
                self.github = GitHub()
                head = self.github.add(460, "gcp", GOOGLE, "8.11.0", "8.12.0")
                self.github.add(461, directory, GOOGLE, "8.11.0", version)
                with self.assertRaises(RECONCILER.Rejected):
                    self.reconcile(head, lambda *_: self.fail("registry must not be contacted"))

    def test_rejects_prerelease_major_and_non_forward_versions(self):
        for version in ("3.0.0", "2.108.0-rc.1", "2.107.0", "2.106.9"):
            with self.subTest(version=version):
                self.github = GitHub()
                head = self.github.add(460, "digitalocean", DO, "2.107.0", version)
                with self.assertRaises(RECONCILER.Rejected):
                    self.reconcile(head, lambda *_: self.fail("registry must not be contacted"))

    def test_rejects_wrong_actor_base_head_and_extra_file(self):
        for attack in ("actor", "unsigned", "parent", "head", "extra", "mode", "fork", "unprotected"):
            with self.subTest(attack=attack):
                self.github = GitHub()
                head = self.github.add(460, "digitalocean", DO, "2.107.0", "2.108.0")
                pr = self.github.routes["pulls/460"]
                commit = self.github.routes[f"commits/{head}"]
                tasks = {
                    "actor": lambda: pr["user"].update(id=99),
                    "unsigned": lambda: commit["commit"]["verification"].update(verified=False),
                    "parent": lambda: commit["parents"][0].update(sha="b" * 40),
                    "head": lambda: pr["head"].update(sha="b" * 40),
                    "extra": lambda: commit["files"].append({"filename": ".github/workflows/quality.yml", "status": "modified"}),
                    "mode": lambda: self.github.routes[f'git/trees/{commit["commit"]["tree"]["sha"]}?recursive=1']["tree"][0].update(mode="120000"),
                    "fork": lambda: pr["head"]["repo"].update(full_name="other/deployment"),
                    "unprotected": lambda: self.github.routes["branches/main"].update(protected=False),
                }
                tasks[attack]()
                with self.assertRaises(RECONCILER.Rejected):
                    self.reconcile(head, lambda *_: self.fail("registry must not be contacted"))

    def test_rejects_manifest_changes_outside_the_pin(self):
        head = self.github.add(460, "gcp", GOOGLE, "8.11.0", "8.12.0")
        self.github.add(461, "gcp-rocky", GOOGLE, "8.11.0", "8.12.0")
        tree = self.github.routes[f"commits/{head}"]["commit"]["tree"]["sha"]
        path = "infra/ci-cloud/gcp/versions.tf"
        manifest = (ROOT / path).read_text().replace("8.11.0", "8.12.0")
        self.github.set_file(tree, path, manifest.replace("secpal-dev", "other-project"))
        with self.assertRaisesRegex(RECONCILER.Rejected, "more than the requested exact pin"):
            self.reconcile(head, lambda *_: self.fail("registry must not be contacted"))

    def test_rejects_wrong_registry_bad_checksum_and_incomplete_platform_set(self):
        bad = (
            lambda s, v: lock(s, v, v, hashes(s, 30)).replace("registry.opentofu.org", "elsewhere.invalid"),
            lambda s, v: lock(s, v, v, hashes(s, 60)),
            lambda s, v: lock(s, v, v, hashes(s, 30)[:-1]),
            lambda s, v: lock(s, v, "2.107.0", hashes(s, 30)),
        )
        for generator in bad:
            with self.subTest(generator=generator):
                self.github = GitHub()
                head = self.github.add(460, "digitalocean", DO, "2.107.0", "2.108.0")
                with self.assertRaises(RECONCILER.Rejected):
                    self.reconcile(head, generator)

    def test_requires_current_head_and_base_after_registry_work(self):
        for change in (
            lambda state: state.routes["branches/main"]["commit"].update(sha="b" * 40),
            lambda state: state.routes["pulls/460"]["head"].update(sha="b" * 40),
        ):
            with self.subTest(change=change):
                self.github = GitHub()
                head = self.github.add(460, "digitalocean", DO, "2.107.0", "2.108.0")

                def generate(source, version):
                    change(self.github)
                    return lock(source, version, version, hashes(source, 30))

                with self.assertRaises(RECONCILER.Rejected):
                    self.reconcile(head, generate)

    def test_bad_signature_process_never_produces_an_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "tofu"
            tool.write_bytes(b"test")
            with patch.object(RECONCILER, "TOFU_SHA256", hashlib.sha256(b"test").hexdigest()), patch.object(
                RECONCILER.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "tofu"),
            ) as run:
                with self.assertRaises(RECONCILER.Rejected):
                    RECONCILER.generate_lock(tool, DO, "2.108.0")
            command = run.call_args.args[0]
            self.assertEqual(command[1:3], ["providers", "lock"])
            self.assertIn("-platform=linux_amd64", command)
            self.assertIn("-platform=linux_arm64", command)
            self.assertEqual(run.call_args.kwargs["env"]["OPENTOFU_ENFORCE_GPG_VALIDATION"], "true")
            self.assertEqual(run.call_args.kwargs["env"]["OPENTOFU_ENFORCE_GPG_EXPIRATION"], "true")
            self.assertNotIn("GH_TOKEN", run.call_args.kwargs["env"])

    def test_successful_process_without_platform_signatures_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = Path(tmp) / "tofu"
            tool.write_bytes(b"test")
            signed_lines = "\n".join(
                f"- Retrieved {DO} 2.108.0 for {platform} (signed, key ID 0123456789ABCDEF)"
                for platform in RECONCILER.PROVIDERS[DO][1] if platform != "linux_arm64"
            )
            result = subprocess.CompletedProcess(["tofu"], 0, stdout=signed_lines)
            with patch.object(RECONCILER, "TOFU_SHA256", hashlib.sha256(b"test").hexdigest()), patch.object(
                RECONCILER.subprocess, "run", return_value=result,
            ):
                with self.assertRaisesRegex(RECONCILER.Rejected, "missing signed provider package"):
                    RECONCILER.generate_lock(tool, DO, "2.108.0")


if __name__ == "__main__":
    unittest.main()
