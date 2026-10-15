#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Static and negative tests for the ephemeral cloud CI trust boundary."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-ci-cloud.py"


class CloudCIContractTests(unittest.TestCase):


    def test_openssh_account_smoke_ignores_global_known_hosts(self) -> None:
        smoke = (ROOT / "tests/ci-cloud-openssh-account.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("-o GlobalKnownHostsFile=/dev/null \\\n", smoke)

    maxDiff = None

    def run_validator(self, root: Path = ROOT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VALIDATOR), str(root)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def mutated_root(self, relative_path: str, old: str, new: str) -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="secpal-ci-cloud-contract-"))
        self.addCleanup(shutil.rmtree, temporary)
        for path in (
            ".gitignore",
            ".github/workflows/cloud-janitor.yml",
            ".github/workflows/rocky-cloud-qualification.yml",
            "config/ci-cloud/gcp-rocky-10-2-arm64.json",
            "config/ci-cloud/gcp-rocky-10-2-x86-64.json",
            "infra/ci-cloud/gcp/iam-role.yaml",
            "infra/ci-cloud/gcp-rocky",
            "schemas",
            "scripts/ci-cloud",
            "scripts/fetch-oci-attestation.py",
            "scripts/qualify-production-host.sh",
            "scripts/selinux_isolation_contract.py",
            "scripts/quadlet_authority_contract.py",
            "scripts/quadlet-integration.py",
        ):
            source = ROOT / path
            destination = temporary / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

        target = temporary / relative_path
        document = target.read_text(encoding="utf-8")
        self.assertIn(old, document, f"mutation anchor missing in {relative_path}")
        target.write_text(document.replace(old, new, 1), encoding="utf-8")
        return temporary

    def assert_mutation_rejected(
        self, relative_path: str, old: str, new: str
    ) -> None:
        fixture = self.mutated_root(relative_path, old, new)
        result = self.run_validator(fixture)
        self.assertNotEqual(0, result.returncode, result.stdout)

    def test_repository_cloud_ci_contract_is_valid(self) -> None:
        result = self.run_validator()
        self.assertEqual(0, result.returncode, result.stdout)

    def test_static_contract_rejects_weakened_runtime_authority_admission(self) -> None:
        harness = "scripts/qualify-production-host.sh"
        mutations = (
            (
                '[[ "$service_uid" =~ ^[1-9][0-9]*$ && "$service_gid" =~ ^[1-9][0-9]*$ ]]',
                '[[ "$service_uid" =~ ^[0-9]+$ && "$service_gid" =~ ^[0-9]+$ ]]',
            ),
            (
                'podman_rootless="$(rootless_podman info --format \'{{.Host.Security.Rootless}}\')"',
                'podman_rootless=true',
            ),
            ('[[ -e "$component" && ! -L "$component" ]]', '[[ -e "$component" ]]'),
            (
                '[[ "$uid" == "$administrator_uid" && "$gid" == "$administrator_gid" ]]',
                '[[ "$uid" == "$administrator_uid" ]]',
            ),
            ("(((8#$mode & 8#022) == 0))", ":"),
            (
                'service_account_cannot_write_path "$quadlet_root" /',
                'administrator_path_admitted "$quadlet_root" / 0 0',
            ),
            ('[[ "$value" == 1 ]]', '[[ "$value" =~ ^[01]$ ]]'),
            (
                "for field in CapInh CapPrm CapEff CapBnd CapAmb; do",
                "for field in CapEff; do",
            ),
            ('[[ "$value" == 0000000000000000 ]]', '[[ -n "$value" ]]'),
            ('[[ "$value" == 2 ]]', '[[ "$value" =~ ^[012]$ ]]'),
            (
                'administrator_path_admitted "$quadlet_search_policy" / 0 0 file 644',
                'administrator_path_admitted "$quadlet_root" / 0 0 directory 755',
            ),
            (
                '[[ "$effective_quadlet_dirs" != "$quadlet_root" ]]',
                '[[ -z "$effective_quadlet_dirs" ]]',
            ),
            (
                'python3 "$QUADLET_AUTHORITY_CONTRACT" "$properties_path"',
                'true # bypass "$QUADLET_AUTHORITY_CONTRACT" "$properties_path"',
            ),
            ("trap 'interrupted 129' HUP", "trap cleanup HUP"),
            ("trap 'interrupted 130' INT", "trap cleanup INT"),
            ("trap 'interrupted 143' TERM", "trap cleanup TERM"),
            ('exit_status="$interrupted_status"', "exit_status=0"),
            (
                "/usr/bin/timeout --signal=KILL 30s semodule -B",
                "semodule -B",
            ),
            (
                'rm -f -- "$qualification_success_marker"',
                ": # retain success marker",
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                self.assert_mutation_rejected(harness, old, new)

        authority = "scripts/quadlet_authority_contract.py"
        for old, new in (
            (
                'INVARIANT_OWNER = "quadlet_authority_contract.admit_quadlet_authority"',
                'INVARIANT_OWNER = "caller.selected.authority"',
            ),
            (
                'r"^/run/user/(?P<uid>[1-9][0-9]*)/systemd/generator/"',
                'r"^/run/user/(?P<uid>[0-9]*)/systemd/generator/"',
            ),
            (
                'r"^/etc/containers/systemd/users/(?P<uid>[1-9][0-9]*)/"',
                'r"^/home/runtime/.config/containers/systemd/"',
            ),
            ('or properties["DropInPaths"]', 'or False'),
            (
                'properties["ExecStart"] != expected_exec_start(unit_name)',
                'False',
            ),
            (
                '"executable": "/usr/bin/podman"',
                '"executable": "/usr/bin/sh"',
            ),
            ('"--network",\n        "none",', '"--network",\n        "host",'),
            ('"ignore_errors": False', '"ignore_errors": True'),
            ('"status": "0/0"', '"status": "1/0"'),
        ):
            with self.subTest(old=old):
                self.assert_mutation_rejected(authority, old, new)

        enforcement_mutations = (
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                '! /usr/bin/cmp --silent -- "$work_root/scripts/quadlet_authority_contract.py" "$trusted_quadlet_authority_contract"',
                "false",
            ),
            (
                "scripts/ci-cloud/rocky-control.py",
                '"target and trusted Quadlet authority normalization disagree"',
                '"target authority accepted without trusted agreement"',
            ),
            (
                "schemas/rocky-cloud-qualification-evidence.schema.json",
                '"const": "quadlet_authority_contract.admit_quadlet_authority"',
                '"const": "caller.selected.authority"',
            ),
            (
                "scripts/ci-cloud/bootstrap-rocky-host.tftpl",
                "decode_script 'quadlet_authority_contract' /opt/secpal-control/scripts/quadlet_authority_contract.py",
                ": # omit Quadlet authority owner",
            ),
            (
                "infra/ci-cloud/gcp-rocky/metadata.tf",
                "quadlet_authority_contract",
                "quadlet_authority_contract_unbound",
            ),
        )
        for relative, old, new in enforcement_mutations:
            with self.subTest(relative=relative):
                self.assert_mutation_rejected(relative, old, new)

        preparation = "scripts/ci-cloud/prepare-rocky-host.sh"
        for old, new in (
            (
                '[[ "$runtime_uid" =~ ^[1-9][0-9]*$ && "$runtime_gid" =~ ^[1-9][0-9]*$ ]]',
                '[[ "$runtime_uid" =~ ^[0-9]+$ && "$runtime_gid" =~ ^[0-9]+$ ]]',
            ),
            ("Environment=QUADLET_UNIT_DIRS=%s", "Environment=HOME=%s"),
        ):
            with self.subTest(old=old):
                self.assert_mutation_rejected(preparation, old, new)

    def test_rejects_weakened_current_boot_runtime_user_readiness(self) -> None:
        publisher = "scripts/ci-cloud/publish-rocky-qualification-readiness.py"
        mutations = (
            (
                publisher,
                '["systemctl", "is-active", "--quiet", f"user@{runtime_uid}.service"]',
                '["true"]',
            ),
            (
                publisher,
                "def observe_runtime_user(\n",
                "# loginctl enable-linger is not readiness\n"
                "def observe_runtime_user(\n",
            ),
            (
                publisher,
                "def observe_runtime_user(\n",
                "# runtime.systemd_user from preparation\n"
                "def observe_runtime_user(\n",
            ),
            (
                publisher,
                'stat.S_ISSOCK(os.stat(f"/run/user/{runtime_uid}/bus").st_mode)',
                "True",
            ),
            (
                "scripts/ci-cloud/runtime_user_systemd.py",
                '"show-environment"',
                '"daemon-reload"',
            ),
            (
                publisher,
                'RUNTIME_ACCOUNT = "secpal-runtime"',
                'RUNTIME_ACCOUNT = "another-user"',
            ),
            (
                publisher,
                "RUNTIME_ACCOUNT, runtime_uid, runtime.pw_dir",
                "RUNTIME_ACCOUNT, 1, runtime.pw_dir",
            ),
            (
                "scripts/ci-cloud/runtime_user_systemd.py",
                '"CONTAINER_HOST"',
                '"INHERITED_CONTAINER_HOST"',
            ),
            (
                "scripts/ci-cloud/runtime_user_systemd.py",
                '"CONTAINER_CONNECTION"',
                '"INHERITED_CONTAINER_CONNECTION"',
            ),
            (
                "scripts/ci-cloud/runtime_user_systemd.py",
                'f"HOME={runtime_home}"',
                '"HOME=/tmp"',
            ),
            (
                "scripts/ci-cloud/runtime_user_systemd.py",
                'f"XDG_RUNTIME_DIR={runtime_directory}"',
                '"XDG_RUNTIME_DIR=/run/user/1"',
            ),
            (
                "scripts/ci-cloud/runtime_user_systemd.py",
                'f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_directory}/bus"',
                '"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1/bus"',
            ),
            (
                "infra/ci-cloud/gcp-rocky/metadata.tf",
                "runtime_user_systemd",
                "runtime_user_systemd_unbound",
            ),
            (publisher, "WAIT_SECONDS = 60", "WAIT_SECONDS = 0"),
            (
                publisher,
                "timeout=min(COMMAND_TIMEOUT_SECONDS, remaining)",
                "timeout=COMMAND_TIMEOUT_SECONDS",
            ),
            (
                publisher,
                "sleep(min(interval, remaining))",
                "time.sleep(WAIT_SECONDS)",
            ),
            (
                publisher,
                '"runtime_user_bus_available": result.observation.bus_available,',
                '"runtime_user_bus_available": result.observation.manager_active,',
            ),
            (
                publisher,
                "if current_boot_id() != arguments.boot_id:\n",
                "if False:\n",
            ),
            (
                "scripts/ci-cloud/bootstrap-rocky-host.tftpl",
                '  --boot-id "$boot_id" \\\n',
                "",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                "set -euo pipefail\n",
                "set -euo pipefail\n"
                "/usr/local/sbin/secpal-publish-rocky-qualification-readiness\n",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_rejects_collapsed_quadlet_target_diagnostics(self) -> None:
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        for old, new in (
            (
                '(614, 614, "qualify-quadlet-daemon-reload"),',
                '(614, 614, "qualify-quadlet-runtime"),',
            ),
            (
                '(638, 638, "qualify-quadlet-start"),',
                '(638, 638, "qualify-quadlet-daemon-reload"),',
            ),
            (
                '(639, 639, "qualify-quadlet-active-state"),',
                '(639, 639, "qualify-quadlet-start"),',
            ),
            (
                '(653, 658, "qualify-workload-primary"),',
                '(653, 658, "qualify-workload-secondary"),',
            ),
        ):
            with self.subTest(new=new):
                self.assert_mutation_rejected(classifier, old, new)

    def test_rejects_reintroduced_unreachable_fcontext_diagnostic(self) -> None:
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        self.assert_mutation_rejected(
            classifier,
            '(668, 668, "qualify-selinux-storage-directory-create"),',
            '(670, 670, "qualify-selinux-storage-fcontext-add"),',
        )

    def test_rejects_weakened_target_trace_binding_bounds_and_ambiguity(self) -> None:
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        classifier_source = (ROOT / classifier).read_text(encoding="utf-8")
        self.assertIn(
            'EXPECTED_TARGET_SHA = "402c22b0a1d69a5a3dba74ffb68cf016caba606b"',
            classifier_source,
        )
        self.assertIn(
            'EXPECTED_HARNESS_SHA256 = "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"',
            classifier_source,
        )
        for old, new in (
            (
                'EXPECTED_TARGET_SHA = "402c22b0a1d69a5a3dba74ffb68cf016caba606b"',
                'EXPECTED_TARGET_SHA = ""',
            ),
            (
                'EXPECTED_HARNESS_SHA256 = "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"',
                'EXPECTED_HARNESS_SHA256 = ""',
            ),
            ("MAX_TRACE_FRAMES = 8", "MAX_TRACE_FRAMES = 9"),
            ("MAX_TRACE_LINE = 9_999", "MAX_TRACE_LINE = 10_000"),
            (
                'if len(traced_operations) == 1:\n        return traced_operations.pop(), "command-failed"\n    return "qualification-harness", "unclassified-target-failure"',
                'if traced_operations:\n        return sorted(traced_operations)[0], "command-failed"\n    return "qualification-harness", "unclassified-target-failure"',
            ),
        ):
            with self.subTest(new=new):
                self.assert_mutation_rejected(classifier, old, new)

    def test_corrected_target_pair_is_bound_before_provider_authentication(
        self,
    ) -> None:
        target_sha = "402c22b0a1d69a5a3dba74ffb68cf016caba606b"
        harness_sha256 = (
            "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"
        )
        workflow = (
            ROOT / ".github/workflows/rocky-cloud-qualification.yml"
        ).read_text(encoding="utf-8")
        validation = workflow.split(
            "      - name: Validate immutable inputs\n", 1
        )[1].split("\n  discover:\n", 1)[0]
        classifier_source = (
            ROOT / "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        ).read_text(encoding="utf-8")

        self.assertIn(f"readonly expected_target_sha={target_sha}", validation)
        self.assertIn(
            f"readonly expected_harness_sha256={harness_sha256}", validation
        )
        self.assertIn(
            '[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ]]', validation
        )
        self.assertIn(
            '[[ "$(sha256sum scripts/qualify-production-host.sh | '
            "awk '{print $1}')\" == \\\n"
            '            "$expected_harness_sha256" ]]',
            validation,
        )
        self.assertIn(f'EXPECTED_TARGET_SHA = "{target_sha}"', classifier_source)
        self.assertIn(
            f'EXPECTED_HARNESS_SHA256 = "{harness_sha256}"', classifier_source
        )
        validator_source = (ROOT / "scripts/validate-ci-cloud.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'historical_pre_269_harness_sha256 = (\n        '
            '"f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c"',
            validator_source,
        )
        self.assertIn(
            'HISTORICAL_PRE_269_HARNESS_SHA256 = '
            '"{historical_pre_269_harness_sha256}"',
            validator_source,
        )
        self.assertIn(
            'historical_273_target_sha = '
            '"c76742c828fefd71dda2b2d73fda6a0c43969426"',
            validator_source,
        )
        self.assertIn(
            'HISTORICAL_273_TARGET_SHA = "{historical_273_target_sha}"',
            validator_source,
        )
        mutations = (
            (
                ".github/workflows/rocky-cloud-qualification.yml",
                f"readonly expected_target_sha={target_sha}",
                "readonly expected_target_sha=293977ae93408a7bb812619de58649ab8a92d438",
            ),
            (
                ".github/workflows/rocky-cloud-qualification.yml",
                f"readonly expected_harness_sha256={harness_sha256}",
                "readonly expected_harness_sha256="
                "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db",
            ),
            (
                ".github/workflows/rocky-cloud-qualification.yml",
                '[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ]]',
                '[[ -n "${RAW_TARGET_SHA,,}" ]]',
            ),
            (
                "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
                f'EXPECTED_TARGET_SHA = "{target_sha}"',
                'EXPECTED_TARGET_SHA = "293977ae93408a7bb812619de58649ab8a92d438"',
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                f"readonly expected_target_sha={target_sha}",
                "readonly expected_target_sha=293977ae93408a7bb812619de58649ab8a92d438",
            ),
            (
                "schemas/rocky-cloud-qualification-evidence.schema.json",
                f'"const": "{target_sha}"',
                '"const": "539d5faa6549be62060c8e20028caf200e5eca01"',
            ),
            (
                "schemas/rocky-cloud-target-qualification-failure.schema.json",
                f'"const": "{target_sha}"',
                '"const": "293977ae93408a7bb812619de58649ab8a92d438"',
            ),
            (
                "scripts/ci-cloud/rocky-target-qualification-trace.sh",
                "10#$frame == 614",
                "10#$frame == 237",
            ),
            (
                "scripts/qualify-production-host.sh",
                'readonly DEFAULT_ACCOUNT="secpal-deploy"',
                'readonly DEFAULT_ACCOUNT="caller-selected"',
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, new=new):
                self.assert_mutation_rejected(relative, old, new)

    def test_rejects_schema_pair_substitution_with_unchanged_literal_counts(
        self,
    ) -> None:
        relative = "schemas/rocky-cloud-target-qualification-failure.schema.json"
        current = (
            "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"
        )
        historical = (
            "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"
        )
        fixture = self.mutated_root(relative, current, "x" * 64)
        schema = (fixture / relative).read_text(encoding="utf-8")
        schema = schema.replace(historical, current, 1).replace(
            "x" * 64, historical, 1
        )
        (fixture / relative).write_text(schema, encoding="utf-8")
        result = self.run_validator(fixture)
        self.assertNotEqual(0, result.returncode, result.stdout)

    def test_destroy_cleanup_authenticates_retained_target_before_oidc(self) -> None:
        workflow = (
            ROOT / ".github/workflows/rocky-cloud-qualification.yml"
        ).read_text(encoding="utf-8")
        validation = workflow.split(
            "      - name: Validate immutable inputs\n", 1
        )[1].split("\n  discover:\n", 1)[0]
        cleanup = workflow.split("\n  cleanup:\n", 1)[1]
        self.assertIn(
            'destroy)\n              [[ "${RAW_TARGET_SHA,,}" == '
            '"$expected_target_sha" ||\n                "${RAW_TARGET_SHA,,}" == '
            '"$historical_cleanup_target_sha" ]]',
            validation,
        )
        self.assertIn(
            "readonly historical_cleanup_target_sha="
            "293977ae93408a7bb812619de58649ab8a92d438",
            validation,
        )
        self.assert_mutation_rejected(
            ".github/workflows/rocky-cloud-qualification.yml",
            '[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ||\n'
            '                "${RAW_TARGET_SHA,,}" == '
            '"$historical_cleanup_target_sha" ]]',
            '[[ -n "${RAW_TARGET_SHA,,}" ]]',
        )
        admission = cleanup.index("Admit continuation before cross-run cleanup")
        provider_authentication = cleanup.index(
            "Authenticate separate exact cleanup authority through OIDC"
        )
        self.assertLess(admission, provider_authentication)
        self.assertIn(
            '--target-sha "$TARGET_SHA"',
            cleanup[admission:provider_authentication],
        )

    def test_preprovider_gate_runs_pinned_schema_validator(self) -> None:
        workflow = (
            ROOT / ".github/workflows/rocky-cloud-qualification.yml"
        ).read_text(encoding="utf-8")
        validation_job = workflow.split("jobs:\n  validate:", 1)[1].split(
            "\n  discover:", 1
        )[0]
        self.assertIn(
            "jsonschema==4.25.1 PyYAML==6.0.2", validation_job
        )
        architecture = validation_job.index(
            "scripts/validate-rocky-evidence-architecture.py"
        )
        schema = validation_job.index("scripts/validate-ci-cloud.py")
        immutable = validation_job.index("Validate immutable inputs")
        self.assertLess(architecture, immutable)
        self.assertLess(schema, immutable)

    def test_rejects_process_wide_target_file_limit_and_unbounded_capture(self) -> None:
        runner = "scripts/ci-cloud/run-rocky-target-qualification.sh"
        for old, new in (
            (
                'capture_bounded 4097 "$qualification_trace" <"$trace_fifo"',
                'cat <"$trace_fifo" >"$qualification_trace"',
            ),
            (
                '3>"$trace_fifo" 2>&1 | capture_bounded 65537 "$stdout"',
                '3>"$trace_fifo" >"$stdout" 2>&1',
            ),
            (
                'capture_bounded 4097 "$qualification_trace" <"$trace_fifo"',
                'ulimit -f 128\ncapture_bounded 4097 "$qualification_trace" <"$trace_fifo"',
            ),
            (
                'wait "$observer_pid" >/dev/null 2>&1\n  observer_pid=""',
                'wait "$observer_pid" >/dev/null 2>&1',
            ),
        ):
            with self.subTest(new=new):
                self.assert_mutation_rejected(runner, old, new)

    def test_rejects_weakened_selinux_isolation_admission(self) -> None:
        mutations = (
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                "for attempt in range(12):",
                "for attempt in range(1):",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                'stderr in {b"", b"<no matches>\\n"}',
                "len(stderr) <= 4096",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                'selinux_isolation["denial"]["pid"] != denial_pid',
                "False",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                'selinux_isolation["denial"]["syscall_pid"] != denial_pid',
                "False",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                'isolation_digest != facts["selinux_isolation_sha256"]',
                "False",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                '/usr/bin/cmp --silent -- "$work_root/scripts/'
                'selinux_isolation_contract.py" "$trusted_selinux_isolation_contract"',
                ":",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                "timeout --signal=TERM --kill-after=180s 45m",
                "timeout --signal=TERM --kill-after=30s 45m",
            ),
            (
                "scripts/selinux_isolation_contract.py",
                "MCS_CATEGORY_MAX = 1023",
                "MCS_CATEGORY_MAX = 1024",
            ),
            (
                "scripts/selinux_isolation_contract.py",
                "len(raw_categories) not in {1, 2}",
                "len(raw_categories) not in {1, 2, 3}",
            ),
            (
                "scripts/selinux_isolation_contract.py",
                "len(set(categories)) != len(categories)",
                "False",
            ),
            (
                "scripts/selinux_isolation_contract.py",
                '_field(line, "pid") == str(pid)',
                "True",
            ),
            (
                "scripts/selinux_isolation_contract.py",
                '"permissive": "0"',
                '"permissive": _field(line, "permissive")',
            ),
            (
                "scripts/selinux_isolation_contract.py",
                "_event_id(line), {\"AVC\"",
                '("one", "one"), {"AVC"',
            ),
            (
                "scripts/selinux_isolation_contract.py",
                "len(candidates) != 1",
                "len(candidates) < 1",
            ),
            (
                "schemas/rocky-cloud-qualification-evidence.schema.json",
                '"maximum": 1023',
                '"maximum": 1024',
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                "cwd=str(runtime_home) if name == \"podman\" else None",
                "cwd=None",
            ),
            (
                "scripts/ci-cloud/run-rocky-target-qualification.sh",
                "home_metadata.st_uid == runtime_account.pw_uid",
                "False",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, new=new):
                self.assert_mutation_rejected(relative, old, new)


    def test_rejects_weakened_daemon_reload_failure_adjacency(self) -> None:
        trace = "scripts/ci-cloud/rocky-target-qualification-trace.sh"
        runner = "scripts/ci-cloud/run-rocky-target-qualification.sh"
        observer = "scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py"
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        bootstrap = "scripts/ci-cloud/bootstrap-rocky-host.tftpl"
        reload_runuser = "scripts/ci-cloud/rocky-reload-runuser.py"
        reload_systemctl = "scripts/ci-cloud/rocky-reload-systemctl.py"
        mutations = (
            (
                trace,
                "SECPAL_QUADLET_RELOAD_FAILURE_V3:%s:%s:%s:%s:%s:%s",
                "SECPAL_UNBOUNDED_RELOAD_FAILURE:%s:%s",
            ),
            (
                trace,
                '"$status" "$$" "$secpal_reload_run_space_bytes"',
                '"$status" "1" "$secpal_reload_run_space_bytes"',
            ),
            (
                reload_systemctl,
                "SECPAL_QUADLET_RELOAD_CLIENT_V1:",
                "SECPAL_UNBOUND_RELOAD_CLIENT:",
            ),
            (
                reload_systemctl,
                'REAL_SYSTEMCTL = "/usr/bin/systemctl"',
                'REAL_SYSTEMCTL = "systemctl"',
            ),
            (
                bootstrap,
                "chmod 0555 /usr/local/libexec/secpal-control/rocky-reload-systemctl",
                "chmod 0777 /usr/local/libexec/secpal-control/rocky-reload-systemctl",
            ),
            (
                bootstrap,
                "(( (8#$trusted_mode & 8#022) == 0 ))",
                ":",
            ),
            (
                bootstrap,
                "for trusted_directory in / /opt /opt/secpal-control",
                "for trusted_directory in / /usr",
            ),
            (
                reload_runuser,
                '"/usr/local/libexec/secpal-control/rocky-reload-systemctl"',
                '"/usr/bin/systemctl"',
            ),
            (
                trace,
                "timeout --signal=KILL 2s journalctl --no-pager --quiet --show-cursor --lines=0",
                "journalctl --no-pager --lines=1000",
            ),
            (
                trace,
                '"${14}" == daemon-reload',
                '"${14}" == arbitrary-command',
            ),
            (
                trace,
                "timeout --signal=KILL 1s stat --file-system --format='%a %S' -- /run/systemd",
                "stat --file-system --format='%a %S' -- /run",
            ),
            (trace, "10#$frame == 614", "10#$frame == 638"),
            (observer, "or 614 not in frames", "or 237 not in frames"),
            (
                observer,
                "except (OSError, ObservationError, KeyError, ValueError):",
                "except (OSError, ObservationError, KeyError, pwd.error, ValueError):",
            ),
            (
                reload_runuser,
                "os.dup2(RECORD_FD, 1, inheritable=True)",
                "os.dup2(RECORD_FD, 4, inheritable=True)",
            ),
            (
                reload_runuser,
                "os.closerange(3, int(os.sysconf(\"SC_OPEN_MAX\")))",
                "pass",
            ),
            (
                reload_systemctl,
                "os.getresuid() == (runtime.pw_uid,) * 3",
                "os.geteuid() == runtime.pw_uid",
            ),
            (trace, "read -r -t 25 -u 5", "read -r -u 5"),
            (trace, "trap - ERR", ":"),
            (
                runner,
                "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac",
                "",
            ),
            (
                runner,
                'mkfifo -m 0600 "$reload_event" "$reload_ack"',
                'install -m 0600 /dev/null "$reload_event" "$reload_ack"',
            ),
            (runner, '--reload-adjacency "$reload_adjacency"', ""),
            (observer, "MAX_INPUT_BYTES = 4_096", "MAX_INPUT_BYTES = 65_536"),
            (
                observer,
                'reasons.add("request-client-unbound")',
                'facts["reload_request_client_pid"] = expected_client_pid',
            ),
            (observer, "CAPTURE_DEADLINE_SECONDS = 22", "CAPTURE_DEADLINE_SECONDS = 26"),
            (
                observer,
                "MANAGER_CONTINUITY_TIMEOUT_SECONDS = 2",
                "MANAGER_CONTINUITY_TIMEOUT_SECONDS = 4",
            ),
            (
                observer,
                "PACKAGE_QUERY_TIMEOUT_SECONDS = 1",
                "PACKAGE_QUERY_TIMEOUT_SECONDS = 4",
            ),
            (observer, "time.monotonic() > deadline", "False"),
            (
                observer,
                'raise ObservationError("adjacency command could not execute")',
                "return 125",
            ),
            (
                observer,
                "os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW",
                "os.O_RDONLY | os.O_CLOEXEC",
            ),
            (observer, "stat.S_ISFIFO", "stat.S_ISREG"),
            (observer, "stat.S_ISLNK(link_metadata.st_mode)", "False"),
            (
                observer,
                "directory.resolve(strict=True) == directory",
                "directory.resolve(strict=True) != directory",
            ),
            (observer, 'f"QUADLET_UNIT_DIRS={input_path.parent}"', '"QUADLET_UNIT_DIRS=/"'),
            (observer, '"--dryrun"', '"daemon-reload"'),
            (
                "scripts/ci-cloud/runtime_user_systemd.py",
                '"show-environment"',
                '"daemon-reload"',
            ),
            (
                observer,
                "manager_state_observed and bus_state_observed and control_status != 125",
                "manager_active and bus_available and control_reachable",
            ),
            (
                observer,
                'f"CODE_FUNC={GENERATOR_CODE_FUNC}"',
                'f"IGNORED_CODE_FUNC={GENERATOR_CODE_FUNC}"',
            ),
            (
                observer,
                'f"CODE_FILE={GENERATOR_CODE_FILE}"',
                'f"IGNORED_CODE_FILE={GENERATOR_CODE_FILE}"',
            ),
            (
                observer,
                'f"--boot={boot_id.replace(\'-\', \'\')}"',
                'f"--boot={boot_id}"',
            ),
            (
                observer,
                'f"--output-fields={GENERATOR_OUTPUT_FIELDS}"',
                '"--output=json-pretty"',
            ),
            (
                observer,
                "max_bytes=MAX_GENERATOR_JOURNAL_BYTES",
                "max_bytes=MAX_COMMAND_BYTES",
            ),
            (
                observer,
                'ROCKY_SYSTEMD_SOURCE_RPM = "systemd-257-23.el10_2.2.rocky.0.1.src.rpm"',
                'ROCKY_SYSTEMD_SOURCE_RPM = "upstream-main"',
            ),
            (
                observer,
                'f"--output-fields={RELOAD_OUTPUT_FIELDS}"',
                '"--output=json-pretty"',
            ),
            (observer, 'f"_PID={manager_pid}"', '"_UID=0"'),
            (
                observer,
                'f"--after-cursor={journal_cursor}"',
                'f"--since={arguments.journal_baseline}"',
            ),
            (
                observer,
                '"systemd-257-23.el10_2.2.rocky.0.1.aarch64"',
                '"systemd-257-99.el10.aarch64"',
            ),
            (observer, 'os.statvfs("/run/systemd")', 'os.statvfs("/run")'),
            (observer, '"tclass=system"', '"tclass=file"'),
            (
                observer,
                'r"avc:\\s+denied\\s+\\{\\s*reload\\s*\\}"',
                'r"avc:.*denied"',
            ),
            (
                observer,
                "reload_access_avc(audit, expected_client_pid)",
                "reload_access_avc(audit, control_pid)",
            ),
            (observer, 'comm="podman-system-g"', 'comm="systemd"'),
            (
                classifier,
                '_closed_boolean(observation, "captured_before_cleanup")',
                "True",
            ),
            (
                classifier,
                'observation, "manager_continuity_observed"',
                'observation, "manager_active_after_reload_failure"',
            ),
            (
                classifier,
                '_closed_boolean(\n            observation, "generator_failure_ambiguous"\n        )',
                "False",
            ),
            (
                classifier,
                'generator_ambiguous != (generator_reason != "none")',
                "False",
            ),
            (
                classifier,
                're.fullmatch(r"[0-9a-f]{64}", str(observation["failure_event_sha256"]))',
                "None",
            ),
            (
                classifier,
                'reload_access_avc["source_type"]',
                'observation["control_process_selinux_type"]',
            ),
            (
                classifier,
                'return "reload-authorization-denied", "none"',
                'return "reload-reply-transport-failed", "none"',
            ),
            (
                classifier,
                'return "reload-rate-limited", "none"',
                'return "manager-reload-transaction-failed", "none"',
            ),
            (
                classifier,
                'return "reload-reply-transport-failed", "none"\n',
                'return "manager-reload-transaction-failed", "none"\n',
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_rejects_weakened_quadlet_start_execution_diagnostics(self) -> None:
        trace = "scripts/ci-cloud/rocky-target-qualification-trace.sh"
        runner = "scripts/ci-cloud/run-rocky-target-qualification.sh"
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        start_runuser = "scripts/ci-cloud/rocky-start-runuser.py"
        start_env = "scripts/ci-cloud/rocky-start-env.py"
        start_systemctl = "scripts/ci-cloud/rocky-start-systemctl.py"
        mutations = (
            (
                trace,
                "/opt/secpal-control/libexec/rocky-start-runuser",
                "/usr/sbin/runuser",
            ),
            (
                trace,
                '"${14}" == start',
                '"${14}" == arbitrary-command',
            ),
            (
                start_runuser,
                'REAL_RUNUSER = Path("/usr/sbin/runuser")',
                'REAL_RUNUSER = Path("runuser")',
            ),
            (
                start_runuser,
                'TRUSTED_ENV = Path("/usr/local/libexec/secpal-control/rocky-start-env")',
                'TRUSTED_ENV = Path("/usr/bin/env")',
            ),
            (
                start_env,
                'REAL_ENV = Path("/usr/bin/env")',
                'REAL_ENV = Path("env")',
            ),
            (
                start_systemctl,
                'REAL_SYSTEMCTL = Path("/usr/bin/systemctl")',
                'REAL_SYSTEMCTL = Path("systemctl")',
            ),
            (start_runuser, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (start_env, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (start_systemctl, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (start_runuser, "MAX_PROTOCOL_BYTES = 2_048", "MAX_PROTOCOL_BYTES = 65_536"),
            (start_env, "MAX_PROTOCOL_BYTES = 2_048", "MAX_PROTOCOL_BYTES = 65_536"),
            (start_systemctl, "MAX_PROPERTY_BYTES = 1_024", "MAX_PROPERTY_BYTES = 65_536"),
            (start_runuser, "check=False,", "check=False,\n                shell=True,"),
            (
                trace,
                'exec 6>/var/lib/secpal-rocky/evidence/quadlet-start-observation.json',
                'exec 7>/var/lib/secpal-rocky/evidence/quadlet-start-observation.json',
            ),
            (
                classifier,
                "validate_admitted_quadlet_start_diagnostic",
                "accept_unchecked_quadlet_start_diagnostic",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_rejects_weakened_quadlet_active_execution_diagnostics(self) -> None:
        trace = "scripts/ci-cloud/rocky-target-qualification-trace.sh"
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        active_runuser = "scripts/ci-cloud/rocky-active-runuser.py"
        active_env = "scripts/ci-cloud/rocky-active-env.py"
        active_systemctl = "scripts/ci-cloud/rocky-active-systemctl.py"
        mutations = (
            (
                trace,
                "/opt/secpal-control/libexec/rocky-active-runuser",
                "/usr/sbin/runuser",
            ),
            (
                trace,
                '"${14}" == is-active',
                '"${14}" == arbitrary-command',
            ),
            (
                active_runuser,
                'REAL_RUNUSER = Path("/usr/sbin/runuser")',
                'REAL_RUNUSER = Path("runuser")',
            ),
            (
                active_runuser,
                'TRUSTED_ENV = Path("/usr/local/libexec/secpal-control/rocky-active-env")',
                'TRUSTED_ENV = Path("/usr/bin/env")',
            ),
            (
                active_env,
                'REAL_ENV = Path("/usr/bin/env")',
                'REAL_ENV = Path("env")',
            ),
            (
                active_systemctl,
                'REAL_SYSTEMCTL = Path("/usr/bin/systemctl")',
                'REAL_SYSTEMCTL = Path("systemctl")',
            ),
            (active_runuser, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (active_env, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (active_systemctl, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (
                active_runuser,
                "MAX_PROTOCOL_BYTES = 2_048",
                "MAX_PROTOCOL_BYTES = 65_536",
            ),
            (
                active_env,
                "MAX_PROTOCOL_BYTES = 2_048",
                "MAX_PROTOCOL_BYTES = 65_536",
            ),
            (
                active_runuser,
                "check=False,",
                "check=False,\n                    shell=True,",
            ),
            (
                trace,
                'exec 7>/var/lib/secpal-rocky/evidence/quadlet-active-observation.json',
                'exec 6>/var/lib/secpal-rocky/evidence/quadlet-active-observation.json',
            ),
            (
                classifier,
                "validate_admitted_quadlet_active_diagnostic",
                "accept_unchecked_quadlet_active_diagnostic",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_rejects_weakened_primary_workload_direct_diagnostic(self) -> None:
        trace = "scripts/ci-cloud/rocky-target-qualification-trace.sh"
        runner = "scripts/ci-cloud/run-rocky-target-qualification.sh"
        classifier = "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
        primary_runuser = "scripts/ci-cloud/rocky-primary-runuser.py"
        primary_runtime = "scripts/ci-cloud/rocky-primary-runtime.py"
        mutations = (
            (
                trace,
                '/opt/secpal-control/libexec/rocky-primary-runuser "$@"',
                '/usr/sbin/runuser "$@"',
            ),
            (
                primary_runuser,
                'REAL_RUNUSER = Path("/usr/sbin/runuser")',
                'REAL_RUNUSER = Path("runuser")',
            ),
            (
                primary_runtime,
                'REAL_PODMAN = Path("/usr/bin/podman")',
                'REAL_PODMAN = Path("podman")',
            ),
            (primary_runuser, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (primary_runtime, "#!/usr/bin/python3 -I", "#!/usr/bin/python3"),
            (
                primary_runuser,
                "MAX_PROTOCOL_BYTES = 512",
                "MAX_PROTOCOL_BYTES = 65_536",
            ),
            (
                primary_runuser,
                'environment = {\n        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",\n        "LC_ALL": "C",\n    }',
                "environment = dict(os.environ)",
            ),
            (
                primary_runuser,
                "Once the exact primary request starts",
                "observer errors may replay the primary request",
            ),
            (
                runner,
                'primary_observation="$evidence_root/primary-workload-observation.json"',
                'primary_observation="$work_root/primary-workload-observation.json"',
            ),
            (
                classifier,
                "validate_admitted_primary_workload_diagnostic",
                "accept_unchecked_primary_workload_diagnostic",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_preflight_prunes_generated_opentofu_cache(self) -> None:
        preflight = (ROOT / "scripts" / "preflight.sh").read_text(encoding="utf-8")
        self.assertEqual(
            3,
            preflight.count("-name .terraform"),
            "Markdown, YAML, and Prettier discovery must prune OpenTofu caches",
        )
        self.assertIn("python3 tests/ci-cloud-gcp-janitor.py", preflight)
        self.assertNotIn("required_tools=(actionlint cloud-init", preflight)

    def test_repository_contract_requires_every_cloud_provider_root_and_janitor(self) -> None:
        repository_contract = (ROOT / "tests" / "repository-contract.sh").read_text(
            encoding="utf-8"
        )
        for relative in (
            "infra/ci-cloud/gcp/iam-role.yaml",
            "infra/ci-cloud/gcp-rocky/.terraform.lock.hcl",
            "infra/ci-cloud/gcp-rocky/main.tf",
            "infra/ci-cloud/gcp-rocky/outputs.tf",
            "infra/ci-cloud/gcp-rocky/variables.tf",
            "infra/ci-cloud/gcp-rocky/versions.tf",
            "scripts/ci-cloud/gcp-rocky-janitor.py",
            "scripts/ci-cloud/rocky-control.py",
            "scripts/ci-cloud/rocky-start-runuser.py",
            "scripts/ci-cloud/rocky-start-env.py",
            "scripts/ci-cloud/rocky-start-systemctl.py",
            "scripts/ci-cloud/rocky-active-runuser.py",
            "scripts/ci-cloud/rocky-active-env.py",
            "scripts/ci-cloud/rocky-active-systemctl.py",
            "tests/ci-cloud-gcp-rocky-janitor.py",
            "tests/ci-cloud-rocky-control.py",
            "tests/ci-cloud-rocky-target-diagnostics.py",
            "scripts/ci-cloud/gcp-janitor.py",
            "tests/ci-cloud-gcp-janitor.py",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, repository_contract)

    def test_static_contract_rejects_opaque_target_harness_failure_regression(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/run-rocky-target-qualification.sh",
            "exit 91",
            "printf 'qualification harness failed with exit status %s\\n' \"$status\" >&2\n  exit 1",
        )
        self.assert_mutation_rejected(
            ".github/workflows/rocky-cloud-qualification.yml",
            "Retrieve and validate bounded target-qualification failure",
            "Discard target-qualification failure",
        )

    def test_static_contract_rejects_target_call_stack_coverage_regressions(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/rocky-target-qualification-trace.sh",
            '"${BASH_LINENO[@]}"',
            '"${BASH_LINENO[0]}"',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/rocky-target-qualification-trace.sh",
            "if ((frame_count >= 8)); then",
            "if false; then",
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/rocky-target-qualification-trace.sh",
            'local frames=""',
            'local frames="${FUNCNAME[*]}"',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            'LINE_RULES = (\n    (456, 462, "qualify-host-identity"),',
            'LINE_RULES = (\n    (48, 50, "qualify-rootless-runtime"),\n'
            '    (456, 462, "qualify-host-identity"),',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            "if len(explicit) == 1 and len(traced_operations) > 1:",
            "if False:",
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            'EXPECTED_TARGET_SHA = "402c22b0a1d69a5a3dba74ffb68cf016caba606b"',
            'EXPECTED_TARGET_SHA = ""',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/classify-rocky-target-qualification-failure.py",
            "MAX_TRACE_FRAMES = 8",
            "MAX_TRACE_FRAMES = 8\nMAX_TRACE_FRAMES = 7",
        )


    def test_workflow_bash_uses_explicit_strict_mode(self) -> None:
        strict_shell = "shell: bash --noprofile --norc -euo pipefail {0}"
        for relative in (
            ".github/workflows/cloud-janitor.yml",
            ".github/workflows/rocky-cloud-qualification.yml",
        ):
            with self.subTest(relative=relative):
                self.assertIn(
                    strict_shell,
                    (ROOT / relative).read_text(encoding="utf-8"),
                )


    def test_quality_runs_real_openssh_account_admission_smoke(self) -> None:
        quality = (ROOT / ".github/workflows/quality.yml").read_text(
            encoding="utf-8"
        )
        repository_contract = (ROOT / "tests/repository-contract.sh").read_text(
            encoding="utf-8"
        )
        smoke = ROOT / "tests/ci-cloud-openssh-account.sh"

        self.assertTrue(smoke.is_file())
        self.assertIn("sudo bash tests/ci-cloud-openssh-account.sh", quality)
        self.assertIn("openssh-server", quality)
        self.assertIn("tests/ci-cloud-openssh-account.sh", repository_contract)
        document = smoke.read_text(encoding="utf-8")
        for required in (
            "unshare",
            "mount --bind",
            "/usr/sbin/sshd",
            "AuthenticationMethods publickey",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "UsePAM no",
            "UsePAM yes",
            "*NP*",
            "!",
        ):
            self.assertIn(required, document)


    def test_static_contract_rejects_missing_quadlet_normalization_diagnostic(
        self,
    ) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-workload-evidence.py",
            'NORMALIZATION_DIAGNOSTIC_PREFIX = "Trusted Quadlet '
            'normalization diagnostic: "',
            'NORMALIZATION_DIAGNOSTIC_PREFIX = ""',
        )

    def test_static_contract_rejects_broadened_capability_types(self) -> None:
        for field in ("EffectiveCaps", "BoundingCaps"):
            with self.subTest(field=field):
                self.assert_mutation_rejected(
                    "scripts/ci-cloud/collect-workload-evidence.py",
                    f'item["{field}"] is not None\n'
                    f'                and not isinstance(item["{field}"], list)',
                    "False",
                )

    def test_static_contract_rejects_broken_normalization_evidence_wiring(
        self,
    ) -> None:
        mutations = (
            (
                "scripts/ci-cloud/assemble-evidence.py",
                '"normalization_diagnostics": normalization_diagnostics',
                '"normalization_diagnostics": {}',
            ),
            (
                "schemas/ci-cloud-evidence.schema.json",
                '        "normalization_diagnostics",\n',
                "",
            ),
            (
                "scripts/ci-cloud/validate-evidence.py",
                "Trusted Quadlet normalization diagnostics",
                "Trusted normalization result",
            ),
        )
        for relative, old, new in mutations:
            with self.subTest(relative=relative, old=old):
                self.assert_mutation_rejected(relative, old, new)

    def test_static_contract_rejects_unadmitted_socket_trigger_services(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-workload-evidence.py",
            '"systemctl", "--user", "show", trigger,',
            '"systemctl", "--user", "show", unit,',
        )
        self.assert_mutation_rejected(
            "scripts/ci-cloud/collect-workload-evidence.py",
            "or not root_owned_systemd_unit(service_fragment)",
            "or False",
        )


    def test_runtime_validator_enforces_declared_evidence_schema(self) -> None:
        validator = (
            ROOT / "scripts/ci-cloud/validate-evidence.py"
        ).read_text(encoding="utf-8")
        self.assertIn("Draft202012Validator", validator)
        self.assertIn("ci-cloud-evidence.schema.json", validator)


    def test_rejects_broad_janitor_deletion(self) -> None:
        self.assert_mutation_rejected(
            "scripts/ci-cloud/digitalocean-janitor.py",
            'client.delete(f"/v2/droplets/{candidate.resource_id}")',
            'client.delete("/v2/droplets?tag_name=secpal-ci")',
        )


if __name__ == "__main__":
    unittest.main()
