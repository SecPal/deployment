#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static validation for the cloud conformance trust boundary."""

from __future__ import annotations

import ast
import base64
import gzip
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
REQUIRED_INPUTS = {"target_sha", "provider_profile"}
PROFILES = {"digitalocean-intel", "digitalocean-amd", "gcp-axion"}
BOOTSTRAP_FAILURE_SCHEMA_VERSION = 5
BOOTSTRAP_USER_DATA_HEADROOM = 256
HOST_SETUP_FAILURE_STAGES = {
    "diagnostic-ssh",
    "apt-sources",
    "apt-update",
    "kernel-install",
    "package-install",
    "operator-identity",
    "host-policy",
    "kernel-admission",
    "reboot-state",
    "continuation-state",
    "kernel-verify",
    "host-setup",
    "host-initialize",
    "subordinate-ids",
    "service-policy",
    "apparmor",
    "ssh",
}
CREDENTIAL_KEYS = {
    "DIGITALOCEAN_TOKEN",
    "DIGITALOCEAN_ACCESS_TOKEN",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
}
GCP_IAM_PERMISSIONS = {
    "compute.disks.create",
    "compute.disks.delete",
    "compute.disks.get",
    "compute.disks.list",
    "compute.disks.setLabels",
    "compute.disks.use",
    "compute.firewalls.create",
    "compute.firewalls.delete",
    "compute.firewalls.get",
    "compute.firewalls.update",
    "compute.globalOperations.get",
    "compute.images.get",
    "compute.images.useReadOnly",
    "compute.instances.create",
    "compute.instances.delete",
    "compute.instances.get",
    "compute.instances.list",
    "compute.instances.setLabels",
    "compute.instances.setMetadata",
    "compute.instances.setServiceAccount",
    "compute.instances.setTags",
    "compute.instances.start",
    "compute.instances.stop",
    "compute.machineTypes.get",
    "compute.networks.create",
    "compute.networks.delete",
    "compute.networks.get",
    # Required by the network field on subnetworks.insert and firewalls.insert.
    "compute.networks.updatePolicy",
    "compute.projects.get",
    "compute.regionOperations.get",
    "compute.subnetworks.create",
    "compute.subnetworks.delete",
    "compute.subnetworks.get",
    "compute.subnetworks.use",
    "compute.subnetworks.useExternalIp",
    "compute.zoneOperations.get",
    "compute.zones.get",
    "serviceusage.services.use",
}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def required_block(text: str, start: str, end: str, label: str) -> str:
    require(
        text.count(start) == 1,
        f"{label} start marker is missing or ambiguous",
    )
    _, start_marker, tail = text.partition(start)
    require(bool(start_marker), f"{label} start marker is missing")
    block, end_marker, _ = tail.partition(end)
    require(bool(end_marker), f"{label} end marker is missing")
    return block


def required_suffix(text: str, start: str, label: str) -> str:
    require(
        text.count(start) == 1,
        f"{label} start marker is missing or ambiguous",
    )
    _, start_marker, suffix = text.rpartition(start)
    require(bool(start_marker), f"{label} start marker is missing")
    return suffix


def read(root: Path, relative: str) -> str:
    path = root / relative
    require(path.is_file(), f"required cloud CI file is missing: {relative}")
    return path.read_text(encoding="utf-8")


def string_collection_constant(text: str, name: str) -> set[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        raise ContractError(f"trusted Python source containing {name} is invalid") from None
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        ):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError):
                break
            if isinstance(value, (list, tuple, set)) and all(isinstance(item, str) for item in value):
                return set(value)
    raise ContractError(f"{name} must be a literal string collection")


def integer_mapping_literal(text: str, key: str) -> int:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        raise ContractError(
            f"trusted Python source containing {key} is invalid"
        ) from None
    values: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key_node, value_node in zip(node.keys, node.values, strict=True):
            if not (
                isinstance(key_node, ast.Constant) and key_node.value == key
            ):
                continue
            try:
                value = ast.literal_eval(value_node)
            except (ValueError, TypeError, SyntaxError):
                raise ContractError(f"{key} must be a literal integer") from None
            if type(value) is not int:
                raise ContractError(f"{key} must be a literal integer")
            values.append(value)
    if len(values) != 1:
        raise ContractError(f"{key} literal must occur exactly once")
    return values[0]


def subprocess_literal_arguments(text: str, function_name: str) -> list[list[str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        raise ContractError(
            f"trusted Python source containing {function_name} is invalid"
        ) from None
    function = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        ),
        None,
    )
    if function is None:
        raise ContractError(f"trusted Python function {function_name} is missing")
    commands: list[list[str]] = []
    for node in ast.walk(function):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "run"
            and node.args
        ):
            continue
        try:
            arguments = ast.literal_eval(node.args[0])
        except (ValueError, TypeError, SyntaxError):
            continue
        if isinstance(arguments, list) and all(
            isinstance(argument, str) for argument in arguments
        ):
            commands.append(arguments)
    return commands


def contains_argument_pair(arguments: list[str], option: str, value: str) -> bool:
    return any(
        arguments[index : index + 2] == [option, value]
        for index in range(len(arguments) - 1)
    )


def load_workflow(root: Path, relative: str) -> tuple[dict[str, object], str]:
    text = read(root, relative)
    try:
        document = yaml.load(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise ContractError(f"{relative} is invalid YAML: {error}") from None
    require(isinstance(document, dict), f"{relative} must be a YAML mapping")
    return document, text


def validate_action_pins(document: dict[str, object], relative: str) -> None:
    jobs = document.get("jobs")
    require(isinstance(jobs, dict), f"{relative} must define jobs")
    for job_name, raw_job in jobs.items():
        require(isinstance(raw_job, dict), f"{relative} job {job_name} must be a mapping")
        references: list[str] = []
        job_reference = raw_job.get("uses")
        if isinstance(job_reference, str):
            references.append(job_reference)
        steps = raw_job.get("steps", [])
        require(isinstance(steps, list), f"{relative} job {job_name} steps must be a list")
        for step in steps:
            require(isinstance(step, dict), f"{relative} contains a malformed step")
            reference = step.get("uses")
            if isinstance(reference, str):
                references.append(reference)
        for reference in references:
            if reference.startswith("./"):
                continue
            require(
                PINNED_ACTION.fullmatch(reference) is not None,
                f"{relative} contains an unpinned external action: {reference}",
            )


def validate_conformance_workflow(root: Path) -> None:
    relative = ".github/workflows/cloud-conformance.yml"
    document, text = load_workflow(root, relative)
    cleanup_init_retry = read(
        root, "scripts/ci-cloud/init-cleanup-root.sh"
    )
    require("pull_request_target" not in text, "pull_request_target is forbidden")
    trigger = document.get("on")
    require(isinstance(trigger, dict), "cloud conformance trigger must be a mapping")
    require(set(trigger) == {"workflow_dispatch"}, "cloud conformance must be manual only")
    dispatch = trigger.get("workflow_dispatch")
    require(isinstance(dispatch, dict), "workflow_dispatch configuration is required")
    inputs = dispatch.get("inputs")
    require(isinstance(inputs, dict), "workflow_dispatch inputs are required")
    require(set(inputs) == REQUIRED_INPUTS, "workflow inputs must be exactly target_sha and provider_profile")
    profile = inputs.get("provider_profile")
    require(isinstance(profile, dict), "provider_profile must be configured")
    options = profile.get("options")
    require(isinstance(options, list) and set(options) == PROFILES, "provider_profile options changed")
    require("^[0-9a-fA-F]{40}$" in text, "target_sha needs full-SHA validation")
    require(
        text.count("${{ inputs.target_sha }}") == 1
        and "RAW_TARGET_SHA: ${{ inputs.target_sha }}" in text,
        "target_sha may enter the workflow only through the validation-step environment",
    )
    require(
        text.count("${{ github.run_attempt }}") == 1
        and text.count("github.run_attempt") == 3
        and "RAW_RESOURCE_ATTEMPT: ${{ github.run_attempt }}" in text
        and "GITHUB_RUN_ATTEMPT" not in text,
        "the current workflow attempt may enter only validation and provider admission guards",
    )
    require(
        "resource_attempt: ${{ steps.inputs.outputs.resource_attempt }}" in text
        and "^[1-9][0-9]{0,2}$" in text
        and "printf 'resource_attempt=%s\\n' \"$RAW_RESOURCE_ATTEMPT\""
        in text
        and text.count("${{ needs.validate.outputs.resource_attempt }}")
        == 11
        and text.count("needs.validate.outputs.resource_attempt") == 13,
        "resource identity must remain bound to the original validated attempt",
    )
    require("github.ref == 'refs/heads/main'" in text, "default-branch execution must fail closed")
    concurrency = document.get("concurrency")
    require(
        concurrency
        == {
            "group": "debian13-cloud-conformance",
            "cancel-in-progress": "false",
            "queue": "max",
        },
        "cloud runs must use the FIFO queue without cancellation",
    )
    require(text.count("ref: ${{ github.sha }}") == 4, "trusted checkout must stay on the workflow commit")
    require(text.count("persist-credentials: false") == 4, "checkout credentials must not persist")
    require(
        text.count("if-no-files-found: error") == 2,
        "missing provider evidence must fail the upload step",
    )

    jobs = document.get("jobs")
    assert isinstance(jobs, dict)
    require(
        set(jobs)
        == {"validate", "digitalocean", "digitalocean_cleanup", "gcp", "gcp_cleanup"},
        "unexpected cloud conformance job",
    )
    require(jobs["digitalocean"].get("environment") == "ci-cloud-digitalocean", "DigitalOcean provisioning environment changed")
    require(jobs["digitalocean_cleanup"].get("environment") == "ci-cloud-digitalocean-cleanup", "DigitalOcean cleanup environment changed")
    require(jobs["gcp"].get("environment") == "ci-cloud-gcp", "GCP provisioning environment changed")
    require(jobs["gcp_cleanup"].get("environment") == "ci-cloud-gcp-cleanup", "GCP cleanup environment changed")
    require(
        jobs["digitalocean"].get("timeout-minutes") == "70"
        and jobs["gcp"].get("timeout-minutes") == "100",
        "provider job runtime bounds changed",
    )
    for provider_name in ("digitalocean", "gcp"):
        require(
            jobs[provider_name].get("if")
            == (
                "${{ needs.validate.outputs.provider == "
                f"'{provider_name}' && github.run_attempt == "
                "fromJSON(needs.validate.outputs.resource_attempt) }}"
            ),
            f"{provider_name} provisioning must reject targeted job reruns with stale resource identity",
        )
    for cleanup_name in ("digitalocean_cleanup", "gcp_cleanup"):
        cleanup = jobs[cleanup_name]
        require(isinstance(cleanup, dict), f"{cleanup_name} job must be a mapping")
        require("always()" in str(cleanup.get("if", "")), f"{cleanup_name} must run with always()")
    require(text.count("tofu destroy --auto-approve --input=false") == 2, "each provider cleanup must use exact tofu destroy")
    require(
        text.count(
            '\"$GITHUB_WORKSPACE/scripts/ci-cloud/init-cleanup-root.sh\"'
        )
        == 2,
        "both exact cleanup jobs must use bounded locked initialization",
    )
    require(
        cleanup_init_retry.startswith("#!/usr/bin/env bash\n")
        and "set -euo pipefail" in cleanup_init_retry
        and "max_attempts=3" in cleanup_init_retry
        and cleanup_init_retry.count(
            "tofu init -input=false -lockfile=readonly"
        )
        == 1
        and "timeout --signal=TERM --kill-after=15s 90s" in cleanup_init_retry
        and "delay=$((attempt * 10))" in cleanup_init_retry
        and 'sleep "$delay"' in cleanup_init_retry,
        "cleanup initialization retry contract changed",
    )
    require("--tag-name" not in text and "delete --force" not in text, "broad cleanup is forbidden")
    require("credentials_json" not in text and "service_account_key" not in text, "long-lived GCP keys are forbidden")
    require(text.count("id-token: write") == 2, "OIDC permission must be limited to GCP apply and cleanup jobs")
    require(text.count("google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093") == 3, "GCP auth action pin or scope changed")
    require(text.count("create_credentials_file: false") == 3, "GCP auth must not create ADC files")
    require(text.count("export_environment_variables: false") == 3, "GCP auth must not export job credentials")
    require(
        text.count("projects/94792370946/locations/global/workloadIdentityPools/secpal/providers/github")
        == 2
        and text.count("gcp-service-account@secpal-dev.iam.gserviceaccount.com") == 2,
        "GCP apply and cleanup identities must be validated before authentication",
    )
    require(
        text.count("${{ vars.GCP_BOOTSTRAP_SERVICE_ACCOUNT }}") == 3
        and "GCP_BOOTSTRAP_SERVICE_ACCOUNT: ${{ vars.GCP_BOOTSTRAP_SERVICE_ACCOUNT }}"
        in text
        and "--arg bootstrap_service_account \"$GCP_BOOTSTRAP_SERVICE_ACCOUNT\""
        in text
        and "bootstrap_service_account: $bootstrap_service_account" in text,
        "GCP bootstrap identity must enter only validated trusted provisioning",
    )
    require(
        "^[a-z][a-z0-9-]{4,28}[a-z0-9]@secpal-dev\\.iam\\.gserviceaccount\\.com$"
        in text
        and '[[ "$GCP_BOOTSTRAP_SERVICE_ACCOUNT" != "$GCP_SERVICE_ACCOUNT" ]]'
        in text
        and text.count("created_at + 7200") == 1
        and text.count("created_at + 10800") == 1,
        "GCP bootstrap identity validation or provider TTL budget changed",
    )
    for job_name in ("validate", "digitalocean", "digitalocean_cleanup"):
        raw_permissions = jobs[job_name].get("permissions", {})
        require("id-token" not in raw_permissions, f"{job_name} must not receive OIDC permission")
    for job_name in ("gcp", "gcp_cleanup"):
        permissions = jobs[job_name].get("permissions")
        require(
            isinstance(permissions, dict)
            and permissions == {"contents": "read", "id-token": "write"},
            f"{job_name} OIDC permissions changed",
        )

    secret_steps: set[str] = set()
    for job_name, raw_job in jobs.items():
        assert isinstance(raw_job, dict)
        require(not any(key in raw_job for key in ("env", "secrets")), "job-level cloud credentials are forbidden")
        require(
            "concurrency" not in raw_job,
            f"{job_name} must inherit the reviewed workflow-level queue",
        )
        for raw_step in raw_job.get("steps", []):
            assert isinstance(raw_step, dict)
            name = str(raw_step.get("name", ""))
            run = str(raw_step.get("run", ""))
            require("${{ inputs.target_sha }}" not in run, "untrusted input was interpolated into shell text")
            env = raw_step.get("env", {})
            require(isinstance(env, dict), f"step {name} env must be a mapping")
            credentialed = any(
                str(key) in CREDENTIAL_KEYS or "secrets." in str(value)
                for key, value in env.items()
            )
            if credentialed:
                secret_steps.add(name)
                require(
                    name
                    in {
                        "Apply DigitalOcean infrastructure",
                        "Destroy exact DigitalOcean run infrastructure",
                        "Apply GCP infrastructure",
                        "Remove and verify GCP VM cloud identity",
                        "Destroy exact GCP run infrastructure",
                    },
                    f"cloud credential reached unexpected step: {name}",
                )
                forbidden = ("target-conformance", "run-remote-conformance", "ssh ", "scp ", "target_sha")
                require(not any(value in run for value in forbidden), "target code reached a credentialed step")
            if name in {
                "Run uncredentialed DigitalOcean remote conformance",
                "Run uncredentialed GCP remote conformance",
            }:
                require(
                    not credentialed
                    and env
                    == {
                        "RESOURCE_ATTEMPT": "${{ needs.validate.outputs.resource_attempt }}"
                    },
                    "remote conformance may receive only the validated resource attempt",
                )
    require(
        secret_steps
        == {
            "Apply DigitalOcean infrastructure",
            "Destroy exact DigitalOcean run infrastructure",
            "Apply GCP infrastructure",
            "Remove and verify GCP VM cloud identity",
            "Destroy exact GCP run infrastructure",
        },
        "cloud credentials must be scoped to closed provider-control steps",
    )

    gcp_steps = jobs["gcp"].get("steps", [])
    require(isinstance(gcp_steps, list), "GCP steps must be a list")
    gcp_steps_by_name = {
        str(step.get("name", "")): step
        for step in gcp_steps
        if isinstance(step, dict)
    }
    identity_auth = gcp_steps_by_name.get(
        "Authenticate trusted GCP identity transition through OIDC"
    )
    identity_transition = gcp_steps_by_name.get(
        "Remove and verify GCP VM cloud identity"
    )
    gcp_apply = gcp_steps_by_name.get("Apply GCP infrastructure")
    remote_transition = gcp_steps_by_name.get(
        "Run uncredentialed GCP remote conformance"
    )
    require(
        isinstance(identity_auth, dict)
        and identity_auth.get("id") == "gcp_identity_auth"
        and identity_auth.get("if")
        == "${{ steps.gcp_apply.outcome == 'success' }}"
        and identity_auth.get("continue-on-error") == "true"
        and identity_auth.get("with")
        == {
            "project_id": "${{ vars.GCP_PROJECT_ID }}",
            "workload_identity_provider": (
                "${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}"
            ),
            "service_account": "${{ vars.GCP_SERVICE_ACCOUNT }}",
            "token_format": "access_token",
            "access_token_lifetime": "1200s",
            "create_credentials_file": "false",
            "export_environment_variables": "false",
        },
        "GCP identity transition must use a fresh bounded OIDC token",
    )
    require(
        isinstance(identity_transition, dict)
        and identity_transition.get("id") == "gcp_identity"
        and identity_transition.get("if")
        == (
            "${{ steps.gcp_apply.outcome == 'success' && "
            "steps.gcp_identity_auth.outcome == 'success' }}"
        )
        and identity_transition.get("continue-on-error") == "true"
        and identity_transition.get("env")
        == {
            "GOOGLE_OAUTH_ACCESS_TOKEN": (
                "${{ steps.gcp_identity_auth.outputs.access_token }}"
            ),
            "GCP_BOOTSTRAP_SERVICE_ACCOUNT": (
                "${{ vars.GCP_BOOTSTRAP_SERVICE_ACCOUNT }}"
            ),
            "RESOURCE_ATTEMPT": (
                "${{ needs.validate.outputs.resource_attempt }}"
            ),
        }
        and identity_transition.get("run")
        == (
            "scripts/ci-cloud/detach-gcp-vm-identity.sh \\\n"
            "  secpal-dev europe-west3-a \\\n"
            '  "spci-${GITHUB_RUN_ID}-${RESOURCE_ATTEMPT}-instance" \\\n'
            '  "$GCP_BOOTSTRAP_SERVICE_ACCOUNT" \\\n'
            '  "$RUNNER_TEMP/ci-cloud/ipv4_address"\n'
        ),
        "GCP identity transition invocation changed",
    )
    require(
        isinstance(gcp_apply, dict)
        and "tofu output -raw ipv4_address" not in str(gcp_apply.get("run", "")),
        "stale pre-transition GCP addresses must not reach remote orchestration",
    )
    require(
        isinstance(remote_transition, dict)
        and remote_transition.get("if")
        == (
            "${{ steps.gcp_apply.outcome == 'success' && "
            "steps.gcp_identity.outcome == 'success' }}"
        )
        and gcp_steps.index(identity_auth)
        < gcp_steps.index(identity_transition)
        < gcp_steps.index(remote_transition),
        "target execution must remain after verified GCP identity removal",
    )
    validate_action_pins(document, relative)


def validate_janitor_workflow(root: Path) -> None:
    relative = ".github/workflows/cloud-janitor.yml"
    document, text = load_workflow(root, relative)
    trigger = document.get("on")
    require(isinstance(trigger, dict), "janitor trigger must be a mapping")
    require(set(trigger) == {"schedule", "workflow_dispatch"}, "janitor trigger scope changed")
    require("pull_request" not in text, "janitor must never run for pull requests")
    require("cancel-in-progress: false" in text, "janitor runs must not cancel each other")
    jobs = document.get("jobs")
    require(isinstance(jobs, dict) and set(jobs) == {"digitalocean", "gcp"}, "janitor provider scope changed")
    require(text.count("secrets.DIGITALOCEAN_ACCESS_TOKEN") == 1, "DigitalOcean janitor token scope changed")
    require(text.count("GOOGLE_OAUTH_ACCESS_TOKEN") == 1, "GCP janitor token scope changed")
    require(text.count("id-token: write") == 1, "janitor OIDC permission scope changed")
    require(text.count("google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093") == 1, "janitor auth action pin changed")
    require(
        text.count("projects/94792370946/locations/global/workloadIdentityPools/secpal/providers/github")
        == 1
        and text.count("gcp-service-account@secpal-dev.iam.gserviceaccount.com") == 1,
        "GCP janitor identity must be validated before authentication",
    )
    require(text.count("ref: ${{ github.sha }}") == 2 and text.count("persist-credentials: false") == 2, "janitor checkout trust changed")
    require("scripts/ci-cloud/gcp-janitor.py" in text and "--zone europe-west3-a" in text, "bounded GCP janitor invocation is missing")
    validate_action_pins(document, relative)


def validate_opentofu(root: Path) -> None:
    main = read(root, "infra/ci-cloud/digitalocean/main.tf")
    versions = read(root, "infra/ci-cloud/digitalocean/versions.tf")
    variables = read(root, "infra/ci-cloud/digitalocean/variables.tf")
    outputs = read(root, "infra/ci-cloud/digitalocean/outputs.tf")
    bootstrap = read(root, "scripts/ci-cloud/bootstrap-conformance-host.tftpl")
    gcp_identity = read(root, "scripts/ci-cloud/detach-gcp-vm-identity.sh")
    gcp_outputs = read(root, "infra/ci-cloud/gcp/outputs.tf")
    gcp_identity_gate = read(
        root, "scripts/ci-cloud/defer-bootstrap-for-gcp-identity.sh"
    )
    continuation = read(root, "scripts/ci-cloud/continue-conformance-bootstrap.sh")
    host_setup = read(root, "scripts/ci-cloud/configure-conformance-host.sh")
    quadlet_fixture_installer = read(
        root, "scripts/ci-cloud/quadlet-fixture-installer.py"
    )
    quadlet_fixture_client = read(
        root, "scripts/ci-cloud/quadlet-fixture-client.py"
    )
    quadlet_fixture_handler = required_block(
        quadlet_fixture_installer,
        "def handle_request(\n",
        "\n\ndef systemd_unit_documents(",
        "Quadlet fixture request handler",
    )
    diagnostic_ssh = read(root, "scripts/ci-cloud/install-diagnostic-ssh.sh")
    host_setup_failure = read(root, "scripts/ci-cloud/host-setup-failure.py")
    collector = read(root, "scripts/ci-cloud/collect-host-evidence.py")
    gcp_final_postcondition = required_block(
        gcp_identity,
        "wait_for_admitted_identity_free_public_ipv4() {\n",
        "\n}\n\npublish_current_ipv4() {",
        "GCP final network and identity postcondition",
    )
    gcp_ipv4_publisher = required_block(
        gcp_identity,
        "publish_current_ipv4() {\n",
        "\n}\n\nset_admission_metadata() {",
        "GCP live IPv4 publisher",
    )
    read(root, "infra/ci-cloud/digitalocean/.terraform.lock.hcl")
    require('required_version = "= 1.12.5"' in versions, "OpenTofu version must be exact")
    require('version = "= 2.99.1"' in versions, "DigitalOcean provider version must be exact")
    require("~>" not in versions and ">=" not in versions, "mutable provider constraints are forbidden")
    require(
        "${cloud_identity_gate}" in bootstrap
        and 'identity_path="instance/service-accounts/"' in gcp_identity_gate
        and "instance/attributes/secpal-ci-cloud-identity-admitted"
        in gcp_identity_gate
        and "admission_deadline=$((SECONDS + 900))" in gcp_identity_gate
        and "admission_status" in gcp_identity_gate
        and "identity_status" in gcp_identity_gate
        and "identity_admitted=true\n    break" in gcp_identity_gate
        and "exit 0" not in gcp_identity_gate
        and "curl " not in gcp_identity_gate
        and "/dev/tcp/169.254.169.254/80" in gcp_identity_gate
        and "Metadata-Flavor: Google" in gcp_identity_gate
        and "timeout --signal=TERM --kill-after=1s 5s" in gcp_identity_gate
        and bootstrap.index("${cloud_identity_gate}")
        < bootstrap.index(
            "install -o root -g root -m 0700 /dev/null \\\n"
            "  /usr/local/sbin/secpal-ci-install-diagnostic-ssh"
        ),
        "native GCP bootstrap must defer before target access while identity exists",
    )
    require(
        '[[ "$project_id" == secpal-dev ]]' in gcp_identity
        and '[[ "$zone" == europe-west3-a ]]' in gcp_identity
        and "^spci-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}-instance$"
        in gcp_identity
        and "--disable" in gcp_identity
        and "--noproxy '*'" in gcp_identity
        and "--max-filesize 1048576" in gcp_identity
        and "--config -" in gcp_identity
        and (
            "printf 'header = \"Authorization: Bearer %s\"\\n' "
            '"$access_token" |'
        )
        in gcp_identity
        and "transition_deadline=$((SECONDS + 900))" in gcp_identity
        and gcp_identity.count("SECONDS < transition_deadline") == 3
        and '[[ "$operation_name" =~ ^[a-z0-9][a-z0-9-]{0,127}$ ]]'
        in gcp_identity
        and '--header "Authorization: Bearer $access_token"'
        not in gcp_identity
        and gcp_identity.count("setServiceAccount") == 1
        and gcp_identity.count("setMetadata") == 1
        and "'{\"scopes\":[]}'" in gcp_identity
        and "'{\"email\":\"\",\"scopes\":[]}'" not in gcp_identity
        and "secpal-ci-cloud-identity-admitted" in gcp_identity
        and 'value: "true"' in gcp_identity
        and ".serviceAccounts[0].email == $email" in gcp_identity
        and gcp_identity.count(
            "((.serviceAccounts[0].scopes // []) | length) == 0"
        )
        == 2
        and "already running without an attached cloud identity" in gcp_identity
        and '[[ "$#" -ne 5 ]]' in gcp_identity
        and '[[ "$ipv4_output" != /*/ipv4_address ]]' in gcp_identity
        and "ipaddress.ip_address" in gcp_identity
        and "address.version != 4 or not address.is_global" in gcp_identity
        and gcp_identity.count(
            'live_ipv4="$(wait_for_admitted_identity_free_public_ipv4)"\n'
            '  publish_current_ipv4 "$live_ipv4"'
        )
        == 1
        and gcp_identity.count(
            'live_ipv4="$(wait_for_admitted_identity_free_public_ipv4)"\n'
            'publish_current_ipv4 "$live_ipv4"'
        )
        == 1
        and 'chmod 0600 "$published_ipv4_tmp"' in gcp_identity
        and 'if ! verify_identity_free "$detached_instance"; then'
        in gcp_identity
        and gcp_identity.index('api_request POST "$instance_path/stop"')
        < gcp_identity.index('api_request POST "$instance_path/setServiceAccount"')
        < gcp_identity.index("detached_instance=\"$(wait_for_instance_status TERMINATED)\"")
        < gcp_identity.index('set_admission_metadata "$detached_instance" TERMINATED')
        < gcp_identity.index('api_request POST "$instance_path/start"')
        < gcp_identity.rindex(
            'live_ipv4="$(wait_for_admitted_identity_free_public_ipv4)"'
        )
        and gcp_final_postcondition.index('status="$(jq -er')
        < gcp_final_postcondition.index('if ! verify_identity_free "$response"; then')
        < gcp_final_postcondition.index(
            'if [[ "$(admission_state "$response")" != admitted ]]; then'
        )
        < gcp_final_postcondition.index(
            'live_ipv4="$(public_ipv4_from_instance "$response")"'
        )
        < gcp_final_postcondition.index("75) ;;")
        and gcp_ipv4_publisher.index(
            'validated_ipv4="$(validate_public_ipv4 "$candidate")"'
        )
        < gcp_ipv4_publisher.index('published_ipv4_tmp="$(mktemp')
        < gcp_ipv4_publisher.index('chmod 0600 "$published_ipv4_tmp"')
        < gcp_ipv4_publisher.index(
            'printf \'%s\\n\' "$validated_ipv4" >"$published_ipv4_tmp"'
        )
        < gcp_ipv4_publisher.index(
            'mv -T -- "$published_ipv4_tmp" "$ipv4_output"'
        )
        and 'output "ipv4_address"' not in gcp_outputs
        and 'output "initial_ipv4_address"' not in gcp_outputs
        and "target_sha" not in gcp_identity
        and "run-remote-conformance" not in gcp_identity
        and "iam.serviceAccounts.actAs" not in gcp_identity,
        "GCP VM identity removal must remain exact, bounded, and independently verified",
    )
    require(
        "length(trimspace(var.ssh_public_key)) <= 128" in variables,
        "DigitalOcean public key input must be bounded before API submission",
    )
    require(
        "((file_size > 128))" in host_setup,
        "trusted host setup must preserve the provider public key bound",
    )
    require(main.count('resource "digitalocean_droplet"') == 1, "exactly one droplet resource is allowed")
    require("count" not in main, "resource count abstraction is forbidden")
    require(
        main.count('data "digitalocean_image" "debian_13"') == 1
        and 'slug = "debian-13-x64"' in main
        and "image             = data.digitalocean_image.debian_13.id" in main,
        "cloud image must resolve the closed Debian 13 slug to one exact provider ID",
    )
    require(
        'output "image_id"' in outputs
        and "value       = data.digitalocean_image.debian_13.id" in outputs,
        "exact resolved provider image ID must be exported",
    )
    require('intel = "s-4vcpu-8gb-intel"' in main, "Intel size allowlist changed")
    require('amd   = "s-4vcpu-8gb-amd"' in main, "AMD size allowlist changed")
    require("local.owner_tag," in main, "SecPal CI owner metadata is missing")
    require("local.repo_tag," in main, "repository metadata is missing")
    require("local.sha_tag," in main, "target SHA metadata is missing")
    require("local.created_tag," in main, "creation metadata is missing")
    require("local.expires_tag," in main, "expiration metadata is missing")
    require(
        "tags = [digitalocean_tag.ownership[local.owner_tag].name]" in main
        and "droplet_ids = [digitalocean_droplet.conformance.id]" not in main,
        "firewall must target the unique ownership tag before Droplet creation",
    )
    require(
        "depends_on        = [digitalocean_firewall.conformance]" in main,
        "Droplet must wait for its tag-targeted firewall",
    )
    require(
        'user_data = templatefile("${path.module}/../../../scripts/ci-cloud/bootstrap-conformance-host.tftpl"'
        in main,
        "DigitalOcean must deliver the trusted native shell payload through user data",
    )
    maximum_bootstrap = bootstrap
    for placeholder, replacement in (
        ("${ssh_public_key}", "x" * 128),
        ("${runner_ipv4}", "255.255.255.255"),
        ("${run_id}", "9" * 20),
        ("${run_attempt}", "9" * 3),
        ("${cloud_identity_gate}", ":"),
        ("${diagnostic_ssh_installer}", diagnostic_ssh.strip()),
        (
            "${host_setup_script_base64gzip}",
            base64.b64encode(
                gzip.compress(host_setup.encode("utf-8"), mtime=0)
            ).decode("ascii"),
        ),
        ("${host_setup_failure_script}", host_setup_failure.strip()),
        ("${bootstrap_continuation_script}", continuation.strip()),
        (
            "${quadlet_fixture_installer_base64gzip}",
            base64.b64encode(
                gzip.compress(quadlet_fixture_installer.encode("utf-8"), mtime=0)
            ).decode("ascii"),
        ),
        (
            "${quadlet_fixture_client_base64gzip}",
            base64.b64encode(
                gzip.compress(quadlet_fixture_client.encode("utf-8"), mtime=0)
            ).decode("ascii"),
        ),
    ):
        maximum_bootstrap = maximum_bootstrap.replace(placeholder, replacement)
    require(
        len(maximum_bootstrap.encode("utf-8"))
        <= (64 * 1024) - BOOTSTRAP_USER_DATA_HEADROOM,
        "rendered native bootstrap leaves insufficient DigitalOcean user-data headroom",
    )
    require(
        maximum_bootstrap.count("\n:\n") == 1,
        "DigitalOcean identity gate must render as one exact no-op",
    )
    maximum_gcp_bootstrap = maximum_bootstrap.replace(
        "\n:\n", f"\n{gcp_identity_gate.strip()}\n", 1
    )
    require(
        len(maximum_gcp_bootstrap.encode("utf-8"))
        <= (256 * 1024) - BOOTSTRAP_USER_DATA_HEADROOM,
        "rendered GCP startup script leaves insufficient metadata headroom",
    )
    bootstrap_ssh_policy = required_block(
        bootstrap,
        "<<'SECPAL_SSH_CONFIG'\n",
        "\nSECPAL_SSH_CONFIG\n",
        "native bootstrap SSH policy",
    )
    expected_bootstrap_ssh_policy = """PasswordAuthentication no
KbdInteractiveAuthentication no
MaxSessions 1
PAMServiceName sshd
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
PubkeyAcceptedAlgorithms +ssh-ed25519
AuthorizedKeysCommand none
AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u
AuthorizedPrincipalsCommand none
AuthorizedPrincipalsFile none
TrustedUserCAKeys none
RevokedKeys none
RefuseConnection no
StrictModes yes
ChrootDirectory none
ForceCommand none
DisableForwarding yes
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
UseDNS no
UsePAM yes
AllowUsers secpal-ci"""
    require(
        bootstrap_ssh_policy == expected_bootstrap_ssh_policy,
        "native bootstrap SSH policy must match the closed operator contract",
    )
    for required in (
        "  gh \\\n",
        "  unattended-upgrades\n",
        "Suites: trixie trixie-updates",
        "Suites: trixie-security",
        "Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg",
        'find "$apt_lists_dir" -mindepth 1 -maxdepth 1 \\\n'
        "  ! -name lock \\( -type f -o -type l \\) -delete",
        "APT::Update::Pre-Invoke::=$apt_lists_cleanup",
        "APT::Periodic::Unattended-Upgrade \"1\";",
        "#clear Unattended-Upgrade::Origins-Pattern;",
        "#clear Unattended-Upgrade::Package-Blacklist;",
        "Unattended-Upgrade::Automatic-Reboot \"false\";",
        "QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000",
        "secpal-ci-configure-conformance-host",
        "secpal-ci-host-setup-failure",
        "${host_setup_failure_script}",
        "${host_setup_script_base64gzip}",
        "${quadlet_fixture_installer_base64gzip}",
        "${quadlet_fixture_client_base64gzip}",
        "${bootstrap_continuation_script}",
    ):
        require(required in bootstrap, "native bootstrap omitted required D.1 host policy")
    require(
        "trixie-backports" not in bootstrap,
        "native bootstrap must not activate the unsupported backports suite",
    )
    require("set -euo pipefail" in host_setup, "host setup must use strict Bash mode")
    require(
        "ssh_authorized_keys" not in bootstrap
        and "${diagnostic_ssh_installer}" in bootstrap
        and "/run/secpal-ci-authorized-key" not in bootstrap
        and 'staged_operator_key=/run/secpal-ci-authorized-key' in continuation
        and 'install -o root -g root -m 0600 /dev/null "$staged_operator_key"'
        in continuation
        and continuation.index('printf \'%s\\n\' "$ssh_public_key"')
        < continuation.index("secpal-ci-configure-conformance-host")
        and "install -o root -g root -m 0644 /dev/null \\\n"
        "  /etc/ssh/sshd_config.d/00-secpal-ci.conf" in bootstrap
        and "sshd_config.d/90-secpal-ci.conf" not in bootstrap
        and "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u"
        in bootstrap
        and "usermod --password '*NP*' secpal-ci" in bootstrap
        and "operator_shadow_entry=\"$(getent shadow secpal-ci)\"" in bootstrap
        and '[[ "$operator_password_marker" == \'*NP*\' ]]' in bootstrap
        and "usermod --lock" not in bootstrap,
        "operator SSH key must remain root-only until trusted host setup finishes",
    )
    require(
        "systemctl mask --now ssh.service ssh.socket"
        in diagnostic_ssh
        and "OnActiveSec=10m" in diagnostic_ssh
        and "ForceCommand /usr/local/sbin/secpal-ci-bootstrap-diagnostic"
        in diagnostic_ssh
        and "DisableForwarding yes" in diagnostic_ssh
        and "PermitRootLogin no" in diagnostic_ssh
        and "PermitUserEnvironment no" in diagnostic_ssh
        and "PubkeyAcceptedAlgorithms ssh-ed25519" in diagnostic_ssh
        and "RevokedKeys none" in diagnostic_ssh
        and "RefuseConnection no" in diagnostic_ssh
        and "MaxSessions 1" in diagnostic_ssh
        and "PAMServiceName sshd" in diagnostic_ssh
        and "StrictModes yes" in diagnostic_ssh
        and "UsePAM yes" in diagnostic_ssh
        and "AllowUsers secpal-ci-diagnostic@$runner_ipv4" in diagnostic_ssh
        and "useradd --system" in diagnostic_ssh
        and "usermod --password '*NP*' \"$diagnostic_user\""
        in diagnostic_ssh
        and 'shadow_entry="$(getent shadow "$diagnostic_user")"'
        in diagnostic_ssh
        and '[[ "$password_marker" == \'*NP*\' ]] || return 1'
        in diagnostic_ssh
        and "usermod --lock" not in diagnostic_ssh
        and diagnostic_ssh.count(
            "diagnostic_root=/var/lib/secpal-ci-diagnostic"
        )
        == 2
        and 'diagnostic_key="$diagnostic_root/authorized-key"' in diagnostic_ssh
        and "diagnostic_command=/usr/local/sbin/secpal-ci-bootstrap-diagnostic"
        in diagnostic_ssh
        and "diagnostic_config=/etc/ssh/secpal-ci-diagnostic-sshd.conf"
        in diagnostic_ssh
        and 'diagnostic_home="$diagnostic_root/home"' in diagnostic_ssh
        and 'install -d -o root -g root -m 0755 "$diagnostic_home"'
        in diagnostic_ssh
        and "SECPAL_CI_DIAGNOSTIC_SSH" in diagnostic_ssh
        and "SECPAL_CI_HOST_SETUP_FAILURE" in diagnostic_ssh
        and "/usr/local/sbin/secpal-ci-host-setup-failure read"
        in diagnostic_ssh
        and "exit 125" in diagnostic_ssh
        and "<<'DIAGNOSTIC'\n#!/usr/bin/env bash\nset -euo pipefail\n"
        in diagnostic_ssh
        and '"$key_comment" != "secpal-ci-$3-$4"' in diagnostic_ssh
        and "eval " not in diagnostic_ssh
        and "source " not in diagnostic_ssh,
        "pre-runcmd failures need independent restricted diagnostic SSH",
    )
    diagnostic_installer_runtime = diagnostic_ssh.split(
        "cat >\"$recovery_command_tmp\" <<'RECOVERY'", 1
    )[0]
    diagnostic_cleanup = required_block(
        diagnostic_installer_runtime,
        "cleanup() {",
        "\n}",
        "diagnostic cleanup block",
    )
    diagnostic_handoff_lock = required_block(
        diagnostic_installer_runtime,
        "acquire_ssh_handoff_lock() {",
        "\n}",
        "diagnostic handoff lock block",
    )
    host_handoff_lock = required_block(
        host_setup,
        "acquire_ssh_handoff_lock() {",
        "\n}",
        "host handoff lock block",
    )
    diagnostic_preparation = required_block(
        diagnostic_ssh,
        "prepare_diagnostic_fallback() {",
        "\nstart_diagnostic_fallback_locked() {",
        "diagnostic preparation block",
    )
    diagnostic_start = required_block(
        diagnostic_ssh,
        "start_diagnostic_fallback() {",
        "\n}",
        "diagnostic start block",
    )
    diagnostic_start_locked = required_block(
        diagnostic_ssh,
        "start_diagnostic_fallback_locked() {",
        "\n}",
        "locked diagnostic start block",
    )
    diagnostic_initial_transition = required_suffix(
        diagnostic_ssh,
        "\nif completed_setup_is_valid; then\n  exit 0\nfi\n",
        "completed setup transition",
    )
    operator_activation = required_block(
        host_setup,
        "activate_operator_ssh() {",
        "\n}",
        "operator SSH activation block",
    )
    operator_handoff = required_block(
        host_setup,
        "perform_operator_ssh_handoff() {",
        "\n}",
        "serialized operator SSH handoff block",
    )
    diagnostic_stop = required_block(
        host_setup,
        "stop_diagnostic_ssh() {",
        "\n}",
        "diagnostic stop block",
    )
    diagnostic_restore = required_block(
        host_setup,
        "restore_diagnostic_ssh() {",
        "\n}",
        "diagnostic restore block",
    )
    diagnostic_recovery = required_block(
        host_setup,
        "arm_diagnostic_ssh_recovery() {",
        "\n}",
        "diagnostic recovery block",
    )
    diagnostic_recovery_command = required_block(
        diagnostic_ssh,
        "cat >\"$recovery_command_tmp\" <<'RECOVERY'",
        "\nRECOVERY",
        "diagnostic recovery command block",
    )
    diagnostic_recovery_service = required_block(
        diagnostic_ssh,
        'cat >"$recovery_service_tmp" <<EOF',
        "\nEOF",
        "diagnostic recovery service block",
    )
    diagnostic_timer_service = required_block(
        diagnostic_ssh,
        'cat >"$timer_tmp" <<EOF',
        "\nEOF",
        "diagnostic timer service block",
    )
    completed_validator = required_block(
        diagnostic_ssh,
        "completed_setup_is_valid() {",
        "\n}",
        "completed setup validator block",
    )
    operator_identity_validator = required_block(
        diagnostic_ssh,
        "validate_operator_identity() {",
        "\n}",
        "operator identity validator block",
    )
    require(
        "ensure_diagnostic_identity" in diagnostic_preparation
        and '[[ "$(id -G "$diagnostic_user")" == "$group_gid" ]]'
        in diagnostic_ssh
        and "ssh-keygen -A" in diagnostic_preparation
        and 'sshd -t -f "$config_tmp"' in diagnostic_preparation
        and "OnActiveSec=10m" in diagnostic_preparation
        and 'diagnostic_service_unit="/etc/systemd/system/$diagnostic_service"'
        in diagnostic_ssh
        and 'diagnostic_timer_unit="/etc/systemd/system/$diagnostic_timer"'
        in diagnostic_ssh
        and 'systemd-analyze verify "$diagnostic_service_unit"'
        in diagnostic_ssh
        and 'chmod 0600 "$key_tmp" "$config_tmp" "$service_tmp" "$timer_tmp" \\'
        in diagnostic_preparation
        and '"$recovery_service_tmp"' in diagnostic_preparation
        and 'chmod 0644 "$service_tmp" "$timer_tmp"'
        not in diagnostic_preparation
        and 'chmod 0644 "$diagnostic_key"' in diagnostic_preparation
        and 'chmod 0600 "$diagnostic_config"' in diagnostic_preparation
        and 'chmod 0600 "$diagnostic_key" "$diagnostic_config"'
        not in diagnostic_preparation
        and "Type=notify" in diagnostic_preparation
        and "Type=exec" not in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_key\""
        in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_config\""
        in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_command\""
        in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_service_unit\""
        in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_timer_unit\""
        in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_recovery_command\""
        in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_recovery_service_unit\""
        in diagnostic_preparation
        and "stat -c '%u:%g:%a' -- \"$diagnostic_root\""
        in diagnostic_preparation
        and '"$diagnostic_root_metadata" != 0:0:755'
        in diagnostic_preparation
        and '"$diagnostic_key_metadata" != 0:0:644'
        in diagnostic_preparation
        and '"$diagnostic_config_metadata" != 0:0:600'
        in diagnostic_preparation
        and '"$diagnostic_command_metadata" != 0:0:755'
        in diagnostic_preparation
        and '"$diagnostic_service_unit_metadata" != 0:0:644'
        in diagnostic_preparation
        and '"$diagnostic_timer_unit_metadata" != 0:0:644'
        in diagnostic_preparation
        and '"$diagnostic_recovery_command_metadata" != 0:0:755'
        in diagnostic_preparation
        and '"$diagnostic_recovery_service_unit_metadata" != 0:0:644'
        in diagnostic_preparation
        and "if completed_setup_is_valid; then\n    return 0\n  fi\n"
        in diagnostic_start_locked
        and diagnostic_start_locked.index("completed_setup_is_valid")
        < diagnostic_start_locked.index(
            'rm -f -- "$completion_marker" "$active_operator_key"'
        )
        < diagnostic_start_locked.index("prepare_diagnostic_fallback")
        < diagnostic_start_locked.index('systemctl enable "$diagnostic_service"')
        < diagnostic_start_locked.index("select_diagnostic_ssh")
        < diagnostic_start_locked.index(
            "systemctl mask --now ssh.service ssh.socket"
        )
        < diagnostic_start_locked.index('systemctl restart "$diagnostic_service"')
        < diagnostic_start_locked.index(
            'systemctl is-active --quiet "$diagnostic_service"'
        )
        < diagnostic_start_locked.index('systemctl stop "$diagnostic_timer"')
        and '! systemctl is-active --quiet "$diagnostic_timer"'
        in diagnostic_start_locked
        and "Restart=on-failure" in diagnostic_preparation
        and "RestartSec=5s" in diagnostic_preparation
        and "StartLimitIntervalSec=2m" in diagnostic_preparation
        and "StartLimitBurst=5" in diagnostic_preparation
        and "Wants=network-online.target" in diagnostic_preparation
        and "After=network-online.target" in diagnostic_preparation
        and "Before=secpal-ci-bootstrap-continue.service"
        in diagnostic_preparation
        and "RuntimeDirectory=sshd secpal-ci-evidence"
        in diagnostic_preparation
        and "RuntimeDirectoryMode=0755" in diagnostic_preparation
        and "RuntimeDirectoryPreserve=yes" in diagnostic_preparation
        and "WantedBy=multi-user.target" in diagnostic_preparation
        and "if ! start_diagnostic_fallback; then"
        in diagnostic_initial_transition
        and 'rm -f -- "$completion_marker" "$active_operator_key"'
        not in diagnostic_initial_transition
        and "unable to establish restricted diagnostic SSH during bootstrap"
        in diagnostic_initial_transition
        and "\nprepare_diagnostic_fallback\n"
        not in diagnostic_initial_transition
        and 'completion_marker="$active_operator_root/host-setup-complete"'
        in diagnostic_ssh
        and "operator_ssh_gate_dir=/etc/systemd/system/ssh.service.d"
        in diagnostic_ssh
        and 'operator_ssh_gate="$operator_ssh_gate_dir/secpal-ci-ready.conf"'
        in diagnostic_ssh
        and 'grep -Fqx "ConditionPathExists=!$diagnostic_selector"'
        in completed_validator
        and '! -e "$diagnostic_selector" && ! -L "$diagnostic_selector"'
        in completed_validator
        and 'active_operator_key="$active_operator_root/authorized-keys/secpal-ci"'
        in diagnostic_ssh
        and "if completed_setup_is_valid; then\n  exit 0\nfi\n"
        in diagnostic_ssh
        and "SECPAL_CI_HOST_SETUP_COMPLETE" in diagnostic_ssh
        and 'cmp -s -- - "$active_operator_key"' in diagnostic_ssh
        and "systemctl is-enabled ssh.service" in diagnostic_ssh
        and '"$ssh_service_state" == enabled' in diagnostic_ssh
        and '"$ssh_socket_state" == disabled' in completed_validator
        and "validate_effective_sshd_config || return 1"
        in completed_validator
        and "validate_operator_identity || return 1" in completed_validator
        and "getent shadow secpal-ci" in operator_identity_validator
        and '"$password_marker" == \'*NP*\'' in operator_identity_validator
        and '"$(id -G secpal-ci)" == 20000' in operator_identity_validator
        and "denyusers|denygroups|allowgroups|setenv" in diagnostic_ssh
        and "pubkeyacceptedalgorithms" in diagnostic_ssh
        and "ssh-ed25519" in diagnostic_ssh
        and 'primary_ssh_config=/etc/ssh/sshd_config.d/00-secpal-ci.conf'
        in diagnostic_ssh
        and "if ! start_diagnostic_fallback; then" in diagnostic_cleanup
        and "unable to establish restricted diagnostic SSH after installer failure"
        in diagnostic_cleanup
        and 'rm -f -- "$diagnostic_key" "$diagnostic_command"'
        not in diagnostic_cleanup
        and 'systemctl restart "$diagnostic_service"' in diagnostic_ssh
        and "ConditionPathExists=/var/lib/secpal-ci-diagnostic/selected"
        in diagnostic_preparation
        and "prepare_operator_ssh_boot_gate" in diagnostic_preparation,
        "restricted diagnostic SSH must replace primary SSH transactionally",
    )
    require(
        'systemctl start "$diagnostic_ssh_timer"' in diagnostic_recovery
        and 'systemctl is-active --quiet "$diagnostic_ssh_timer"'
        in diagnostic_recovery
        and "arm_diagnostic_ssh_recovery" in operator_activation
        and 'systemctl stop "$diagnostic_ssh_service"' in operator_handoff
        and 'systemctl enable ssh.service' in operator_handoff
        and 'rm -f -- "$diagnostic_ssh_selector"' in operator_handoff
        and 'systemctl restart ssh.service' in operator_handoff
        and 'systemctl is-active --quiet ssh.service' in operator_handoff
        and "publish_completion_marker" in operator_handoff
        and operator_activation.index(
            "arm_diagnostic_ssh_recovery"
        )
        < operator_activation.index("acquire_ssh_handoff_lock")
        < operator_activation.index("perform_operator_ssh_handoff")
        < operator_activation.index("retire_diagnostic_ssh")
        and operator_activation.count("release_ssh_handoff_lock") == 2
        and "  release_ssh_handoff_lock\n  ssh_key_activated=true\n"
        in operator_activation
        and operator_handoff.index(
            'systemctl stop "$diagnostic_ssh_service"'
        )
        < operator_handoff.index("systemctl enable ssh.service")
        < operator_handoff.index('rm -f -- "$diagnostic_ssh_selector"')
        < operator_handoff.index("systemctl restart ssh.service")
        < operator_handoff.index("systemctl is-active --quiet ssh.service")
        < operator_handoff.index("publish_completion_marker")
        and diagnostic_restore.index('rm -f -- "$completion_marker"')
        < diagnostic_restore.index(
            'systemctl start "$diagnostic_ssh_recovery_service"'
        )
        < diagnostic_restore.index(
            'systemctl is-active --quiet "$diagnostic_ssh_service"'
        )
        < diagnostic_restore.index(
            'systemctl stop "$diagnostic_ssh_timer"'
        )
        and "ConditionPathExists=!/var/lib/secpal-ci/host-setup-complete"
        in diagnostic_recovery_service
        and "ExecStart=$diagnostic_recovery_command"
        in diagnostic_recovery_service
        and "Unit=secpal-ci-diagnostic-ssh-recover.service"
        in diagnostic_timer_service
        and '[[ ! -e "$completion_marker" && ! -L "$completion_marker" ]]'
        in diagnostic_recovery_command
        and "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        in diagnostic_recovery_command
        and "ssh_handoff_lock=/run/secpal-ci-ssh-handoff.lock"
        in diagnostic_recovery_command
        and "set -o noclobber" in diagnostic_recovery_command
        and '"/proc/self/fd/$ssh_handoff_lock_fd"'
        in diagnostic_recovery_command
        and '"$lock_identity" == "$fd_identity"'
        in diagnostic_recovery_command
        and diagnostic_recovery_command.index(
            'flock -x "$ssh_handoff_lock_fd"'
        )
        < diagnostic_recovery_command.index(
            '[[ ! -e "$completion_marker" && ! -L "$completion_marker" ]]'
        )
        and 'mv -T -- "$selector_tmp" "$diagnostic_selector"'
        in diagnostic_recovery_command
        and diagnostic_recovery_command.index(
            'mv -T -- "$selector_tmp" "$diagnostic_selector"'
        )
        < diagnostic_recovery_command.index(
            "systemctl mask --now ssh.service ssh.socket"
        )
        < diagnostic_recovery_command.index(
            "systemctl restart secpal-ci-diagnostic-sshd.service"
        )
        and "ssh_handoff_lock=/run/secpal-ci-ssh-handoff.lock" in host_setup
        and "ssh_handoff_lock=/run/secpal-ci-ssh-handoff.lock" in diagnostic_ssh
        and "command -v flock >/dev/null" in diagnostic_handoff_lock
        and "command -v flock >/dev/null" in host_handoff_lock
        and "set -o noclobber" in diagnostic_handoff_lock
        and "set -o noclobber" in host_handoff_lock
        and 'flock -x "$ssh_handoff_lock_fd"' in diagnostic_handoff_lock
        and 'flock -x "$ssh_handoff_lock_fd"' in host_handoff_lock
        and '"/proc/self/fd/$ssh_handoff_lock_fd"' in diagnostic_handoff_lock
        and '"/proc/self/fd/$ssh_handoff_lock_fd"' in host_handoff_lock
        and '"$lock_identity" != "$fd_identity"' in diagnostic_handoff_lock
        and '"$lock_identity" != "$fd_identity"' in host_handoff_lock
        and diagnostic_start.index("acquire_ssh_handoff_lock")
        < diagnostic_start.index("start_diagnostic_fallback_locked")
        < diagnostic_start.index("release_ssh_handoff_lock")
        and 'systemctl stop "$diagnostic_ssh_recovery_service"'
        in diagnostic_stop
        and '! systemctl is-active --quiet "$diagnostic_ssh_recovery_service"'
        in diagnostic_stop,
        "SSH handoffs must retain a verified listener or armed recovery timer",
    )
    require(
        "ConditionPathExists=/var/lib/secpal-ci-diagnostic/selected"
        in diagnostic_ssh
        and "ConditionPathExists=!%s\\n'" in diagnostic_ssh
        and '"$diagnostic_selector"' in diagnostic_ssh,
        "SSH listeners must have complementary selector-based boot gates",
    )
    require(
        "prepare_operator_ssh_boot_gate() {" in diagnostic_ssh
        and "operator_ssh_boot_gate_is_valid() {" in diagnostic_ssh
        and "operator_ssh_boot_gate_is_valid() {" in host_setup
        and "operator_ssh_gate_dir=/etc/systemd/system/ssh.service.d"
        in diagnostic_ssh
        and 'operator_ssh_gate="$operator_ssh_gate_dir/secpal-ci-ready.conf"'
        in diagnostic_ssh
        and 'grep -Fqx "ConditionPathExists=!$diagnostic_ssh_selector"'
        in host_setup,
        "operator SSH must receive and validate the inverse selector boot gate",
    )
    require(
        "install-diagnostic-ssh.sh" in main
        and "secpal-ci-diagnostic-sshd.timer" in host_setup
        and "secpal-ci-diagnostic-sshd.service" in host_setup
        and "stop_diagnostic_ssh" in host_setup
        and "restore_diagnostic_ssh" in host_setup
        and "retire_diagnostic_ssh" in host_setup
        and 'rm -f -- "$active_ssh_authorized_keys"' in host_setup
        and '! systemctl is-active --quiet "$diagnostic_ssh_timer"'
        in host_setup
        and '! systemctl is-active --quiet "$diagnostic_ssh_service"'
        in host_setup
        and 'userdel "$diagnostic_ssh_user"' in host_setup
        and 'if getent group "$diagnostic_ssh_user" >/dev/null; then'
        in host_setup
        and 'groupdel "$diagnostic_ssh_user"' in host_setup
        and "diagnostic_root=/var/lib/secpal-ci-diagnostic" in host_setup
        and 'diagnostic_ssh_key="$diagnostic_root/authorized-key"' in host_setup
        and 'diagnostic_ssh_home="$diagnostic_root/home"' in host_setup
        and "diagnostic_ssh_service_unit=/etc/systemd/system/"
        "secpal-ci-diagnostic-sshd.service" in host_setup
        and "diagnostic_ssh_timer_unit=/etc/systemd/system/"
        "secpal-ci-diagnostic-sshd.timer" in host_setup
        and "diagnostic_ssh_recovery_service_unit=/etc/systemd/system/"
        "secpal-ci-diagnostic-ssh-recover.service" in host_setup
        and "diagnostic_ssh_recovery_command=/usr/local/sbin/"
        "secpal-ci-recover-diagnostic-ssh" in host_setup
        and 'diagnostic_ssh_selector="$diagnostic_root/selected"' in host_setup
        and 'systemctl disable "$diagnostic_ssh_service"' in host_setup
        and '[[ -e "$diagnostic_ssh_home" || -L "$diagnostic_ssh_home" ]]'
        in host_setup
        and 'rmdir -- "$diagnostic_ssh_home"' in host_setup
        and 'rmdir -- "$diagnostic_root"' in host_setup,
        "trusted SSH activation must retire or restore diagnostic SSH atomically",
    )
    require(
        "activate_operator_ssh || true" not in host_setup
        and "restore_diagnostic_ssh || true" in host_setup
        and 'setup_stage="ssh"\nactivate_operator_ssh\n' in host_setup
        and "active_ssh_authorized_keys_dir=\"$active_ssh_root/authorized-keys\""
        in host_setup
        and "active_ssh_root=/var/lib/secpal-ci" in host_setup
        and 'completion_marker="$active_ssh_root/host-setup-complete"'
        in host_setup
        and "publish_completion_marker" in host_setup
        and "SECPAL_CI_HOST_SETUP_COMPLETE" in host_setup
        and 'active_ssh_authorized_keys="$active_ssh_authorized_keys_dir/secpal-ci"'
        in host_setup
        and 'mv -T -- "$authorized_keys_tmp_dir" \\\n    "$active_ssh_authorized_keys_dir"'
        in host_setup,
        "host setup failures must retain restricted diagnostics without releasing operator SSH",
    )
    require(
        "validate_effective_sshd_config || return 1" in host_setup
        and "sshd -T -C" in host_setup
        and "allowusers secpal-ci" in host_setup
        and "authenticationmethods publickey" in host_setup
        and "authorizedkeyscommand none" in host_setup
        and "authorizedkeysfile /var/lib/secpal-ci/authorized-keys/%u"
        in host_setup
        and "authorizedprincipalscommand none" in host_setup
        and "authorizedprincipalsfile none" in host_setup
        and "permitrootlogin no" in host_setup
        and "permittty no" in host_setup
        and "permituserenvironment no" in host_setup
        and "permituserrc no" in host_setup
        and "forcecommand none" in host_setup
        and "chrootdirectory none" in host_setup
        and "disableforwarding yes" in host_setup
        and "maxsessions 1" in host_setup
        and "pamservicename sshd" in host_setup
        and "refuseconnection no" in host_setup
        and "revokedkeys none" in host_setup
        and "strictmodes yes" in host_setup
        and "trustedusercakeys none" in host_setup
        and "usedns no" in host_setup
        and "usepam yes" in host_setup
        and "denyusers|denygroups|allowgroups|setenv" in host_setup
        and "pubkeyacceptedalgorithms" in host_setup
        and "ssh-ed25519" in host_setup
        and 'runner_ipv4="${1:-}"' in host_setup
        and 'ip -o -4 route get "$runner_ipv4"' in host_setup
        and host_setup.count(
            "host=$runner_ipv4,addr=$runner_ipv4,laddr=$local_ipv4,lport=22"
        )
        == 2,
        "host setup must verify the closed effective SSH policy before key release",
    )
    private_key_install = (
        'install -o root -g root -m 0600 \\\n'
        '    "$staged_ssh_public_key" "$authorized_keys_tmp_dir/secpal-ci"'
    )
    key_publish = (
        'mv -T -- "$authorized_keys_tmp_dir" \\\n'
        '    "$active_ssh_authorized_keys_dir"'
    )
    published_key_chmod = 'chmod 0644 "$active_ssh_authorized_keys"'
    published_directory_chmod = 'chmod 0755 "$active_ssh_authorized_keys_dir"'
    require(
        private_key_install in host_setup
        and key_publish in host_setup
        and published_key_chmod in host_setup
        and published_directory_chmod in host_setup
        and "systemctl unmask ssh.service ssh.socket" in host_setup
        and "systemctl disable --now ssh.socket" in host_setup
        and "systemctl enable ssh.service" in host_setup
        and "systemctl restart ssh.service" in host_setup
        and 'chmod 0755 "$authorized_keys_tmp_dir"' not in host_setup
        and operator_activation.index(private_key_install)
        < operator_activation.index(key_publish)
        < operator_activation.index(published_key_chmod)
        < operator_activation.index(published_directory_chmod)
        < operator_activation.index("perform_operator_ssh_handoff")
        and operator_handoff.index("systemctl unmask ssh.service ssh.socket")
        < operator_handoff.index("systemctl disable --now ssh.socket")
        < operator_handoff.index("systemctl enable ssh.service")
        < operator_handoff.index("systemctl restart ssh.service"),
        "operator SSH key staging must remain private until publication",
    )
    require(
        operator_handoff.index('rm -f -- "$diagnostic_ssh_selector"')
        < operator_handoff.index("systemctl restart ssh.service")
        < operator_handoff.index("publish_completion_marker")
        and operator_activation.index("perform_operator_ssh_handoff")
        < operator_activation.index("release_ssh_handoff_lock")
        < operator_activation.index("ssh_key_activated=true")
        < operator_activation.index("if ! retire_diagnostic_ssh; then")
        and 'rm -f -- "$completion_marker"' in host_setup,
        "operator SSH completion must be persistent, final, and rollback-safe",
    )
    trap_anchor = "trap record_setup_failure EXIT"
    diagnostic_install = (
        'install -d -o root -g root -m 0755 "$diagnostic_dir"'
    )
    diagnostic_reset = (
        'rm -f -- "$diagnostic_dir/host-setup-failure.json"'
    )
    runner_context_validation = (
        'if [[ "$#" -ne 1 ]] || ! is_ipv4 "$runner_ipv4"; then'
    )
    require(
        trap_anchor in host_setup
        and runner_context_validation in host_setup
        and diagnostic_install in host_setup
        and diagnostic_reset in host_setup
        and host_setup.index(trap_anchor)
        < host_setup.index(runner_context_validation)
        and host_setup.index(trap_anchor) < host_setup.index(diagnostic_install)
        and host_setup.index(trap_anchor) < host_setup.index(diagnostic_reset),
        "host setup failure handling must precede fallible initialization",
    )
    require(
        '[[ "$(id -G secpal-ci)" != "$(id -g secpal-ci)" ]]' in host_setup,
        "host setup must reject supplementary disposable-operator groups",
    )
    require(
        string_collection_constant(host_setup_failure, "STAGES")
        == HOST_SETUP_FAILURE_STAGES
        and "/usr/local/sbin/secpal-ci-host-setup-failure" in host_setup
        and '"$failure_writer" write "$setup_stage" "$status"' in host_setup,
        "host setup must emit only closed failure stages and exit status",
    )
    require(
        "normalize_subordinate_ids /etc/subuid --add-subuids --del-subuids UID passwd"
        in host_setup
        and "normalize_subordinate_ids /etc/subgid --add-subgids --del-subgids GID group"
        in host_setup
        and "elif ((start_value <= 265535 && end_value >= 200000)); then"
        in host_setup
        and "fixed secpal-ci range overlaps a host identity" in host_setup,
        "host setup must safely replace automatic subordinate ID ranges",
    )
    require(
        "/run/secpal-ci-evidence/apparmor-status" in host_setup,
        "host setup must capture root-owned AppArmor policy counts",
    )
    require(
        "systemctl disable --now podman.socket podman.service" in host_setup,
        "host setup must disable system-scope Podman API units",
    )
    require(
        bootstrap.startswith("#!/usr/bin/env bash\n")
        and "#cloud-config" not in bootstrap
        and "set -euo pipefail" in bootstrap
        and "export LC_ALL=C" in bootstrap
        and "${diagnostic_ssh_installer}" in bootstrap
        and "${host_setup_script_base64gzip}" in bootstrap
        and "${quadlet_fixture_installer_base64gzip}" in bootstrap
        and "${host_setup_failure_script}" in bootstrap
        and "${bootstrap_continuation_script}" in bootstrap
        and 'install -o root -g root -m 0755 /dev/null "$failure_writer"'
        in bootstrap
        and re.search(
            r"^\s*runner_ipv4\s+= var\.runner_ipv4$", main, re.MULTILINE
        ),
        "native bootstrap must install only trusted host setup",
    )
    require(
        continuation.startswith("#!/usr/bin/env bash\n")
        and "set -euo pipefail" in continuation
        and "systemctl reboot" not in continuation
        and '[[ -d "$state_root" && ! -L "$state_root" ]]' in continuation
        and '== 0:0:700' in continuation
        and "diagnostic_dir=/run/secpal-ci-evidence" in continuation
        and 'install -d -o root -g root -m 0755 "$diagnostic_dir"'
        in continuation
        and 'validate_state_file "$context_file" 1024' in continuation
        and 'validate_state_file "$pending_file" 256' in continuation
        and '[[ "${#context[@]}" -eq 4 && "${#pending[@]}" -eq 2 ]]'
        in continuation
        and '[[ "$expected_kernel" =~ ^6\\.12\\.' in continuation
        and '[[ "$current_boot_id" != "$initial_boot_id" ]]' in continuation
        and '[[ "$(uname -r)" == "$expected_kernel" ]]' in continuation
        and "/usr/local/sbin/secpal-ci-install-diagnostic-ssh" in continuation
        and "/usr/local/sbin/secpal-ci-configure-conformance-host" in continuation
        and continuation.index('systemctl disable "$continuation_service"')
        < continuation.index("secpal-ci-install-diagnostic-ssh")
        < continuation.index('current_boot_id="$(< /proc/sys/kernel/random/boot_id)"')
        < continuation.index('printf \'%s\\n\' "$ssh_public_key"')
        < continuation.index("secpal-ci-configure-conformance-host")
        and '"$failure_writer" write "$setup_stage" "$status"' in continuation
        and 'setup_stage="continuation-state"' in continuation
        and 'setup_stage="kernel-verify"' in continuation
        and 'setup_stage="host-setup"' in continuation
        and 'systemctl disable "$continuation_service"' in continuation,
        "kernel reboot continuation must fail closed before operator SSH release",
    )
    require(
        'failure_marker_ready=true' in continuation
        and continuation.index(
            'install -d -o root -g root -m 0755 "$diagnostic_dir"'
        )
        < continuation.index('failure_marker_ready=true')
        < continuation.index('validate_state_file "$context_file" 1024')
        and 'rm -f -- "$pending_file" "$context_file" "$continuation_unit"'
        in continuation
        and 'rmdir -- "$state_root"' in continuation,
        "kernel continuation must retire its persistent state",
    )
    require(
        continuation.index('printf \'%s\\n\' "$ssh_public_key"')
        < continuation.index("secpal-ci-configure-conformance-host")
        < continuation.index(
            'rm -f -- "$pending_file" "$context_file" "$continuation_unit"'
        ),
        "kernel continuation guard must remain until host setup commits",
    )
    for stage in (
        "diagnostic-ssh",
        "apt-sources",
        "apt-update",
        "kernel-install",
        "package-install",
        "operator-identity",
        "host-policy",
        "kernel-admission",
        "reboot-state",
    ):
        require(
            f'setup_stage="{stage}"' in bootstrap,
            f"native bootstrap omits the closed {stage} failure stage",
        )
    require(
        '"$failure_writer" write "$setup_stage" "$status"' in bootstrap
        and 'setup_stage="initialize"' not in bootstrap
        and 'setup_stage="initialize"' not in continuation
        and 'setup_stage="initialize"' not in host_setup,
        "native bootstrap diagnostics must identify the exact closed phase",
    )
    require(
        continuation.index("secpal-ci-configure-conformance-host")
        < continuation.rindex("trap - EXIT")
        < continuation.index(
            'rm -f -- "$pending_file" "$context_file" "$continuation_unit"'
        ),
        "kernel continuation failure scope must end at the host-setup commit",
    )
    require(
        '! "$failure_writer" read >/dev/null 2>&1' in continuation,
        "kernel continuation must preserve a more specific host-setup failure",
    )
    require(
        "linux-image-cloud-amd64" in bootstrap
        and "linux-image-cloud-arm64" in bootstrap
        and "readlink -e /vmlinuz" not in bootstrap
        and 'meta_package_dependencies="$(' in bootstrap
        and "dpkg-query -W -f '$${Depends}' \"$kernel_meta_package\""
        in bootstrap
        and 'kernel_image_package="$${BASH_REMATCH[1]}"' in bootstrap
        and 'expected_kernel_package_version="$${BASH_REMATCH[3]}"'
        in bootstrap
        and '"$installed_kernel_version" == '
        '"$expected_kernel_package_version"' in bootstrap
        and '[[ -f "/boot/vmlinuz-$expected_kernel"' in bootstrap
        and "apt-cache policy \"$kernel_image_package\"" in bootstrap
        and '"$candidate_kernel_version" == "$installed_kernel_version"'
        in bootstrap
        and "/proc/sys/kernel/random/boot_id" in bootstrap
        and '[[ "$(stat -c \'%u:%g:%a\' -- "$state_root")" == 0:0:700 ]]'
        in bootstrap
        and '[[ ! -e "$state_root" && ! -L "$state_root" ]]' in bootstrap
        and 'install -d -o root -g root -m 0700 "$state_root"' in bootstrap
        and 'chmod 0600 "$context_tmp" "$pending_tmp"' in bootstrap
        and 'mv -T -- "$context_tmp" "$state_root/context"' in bootstrap
        and 'mv -T -- "$pending_tmp" "$pending_file"' in bootstrap
        and "ConditionPathExists=/var/lib/secpal-ci-bootstrap/pending" in bootstrap
        and "Wants=network-online.target "
        "secpal-ci-diagnostic-sshd.service" in bootstrap
        and "After=network-online.target "
        "secpal-ci-diagnostic-sshd.service" in bootstrap
        and "systemctl enable secpal-ci-bootstrap-continue.service" in bootstrap
        and bootstrap.count("systemctl reboot") == 1
        and bootstrap.index("systemctl enable secpal-ci-bootstrap-continue.service")
        < bootstrap.index('mv -T -- "$pending_tmp" "$pending_file"')
        < bootstrap.index("systemctl reboot"),
        "native bootstrap must perform one authenticated kernel reboot",
    )
    package_header = (
        "apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends "
        "\\\n"
    )
    package_footer = '\n\nsetup_stage="operator-identity"'
    package_block = required_block(
        bootstrap,
        package_header,
        package_footer,
        "native bootstrap package block",
    )
    packages = {
        line.strip().removesuffix(" \\")
        for line in package_block.splitlines()
        if line.strip()
    }
    require(
        packages == string_collection_constant(collector, "BOOTSTRAP_PACKAGES"),
        "collector bootstrap package evidence must exactly match native bootstrap packages",
    )
    curl_commands = subprocess_literal_arguments(collector, "cloud_identity_facts")
    identity_probe = curl_commands[1] if len(curl_commands) == 2 else []
    require(
        len(curl_commands) == 2
        and all(command[:2] == ["curl", "--disable"] for command in curl_commands)
        and ["--proto", "=http"] == identity_probe[2:4]
        and "--fail" in identity_probe
        and contains_argument_pair(identity_probe, "--max-filesize", "4096")
        and contains_argument_pair(identity_probe, "--output", "-")
        and contains_argument_pair(
            identity_probe, "--write-out", "\n%{http_code}"
        )
        and 'identity.stdout.rpartition(\n        b"\\n"\n    )' in collector
        and "probe.returncode == 0" in collector
        and "identity.returncode == 0" in collector
        and 'identity_status == b"200"' in collector
        and "len(identity_body) <= 4096" in collector
        and '"identity_present": probe_succeeded and identity_body != b""'
        in collector,
        "cloud identity probe must use bounded body-aware fail-closed semantics",
    )
    forbidden = ("tls_private_key", "private_key", "var.image", "var.machine_type", "var.resource_count")
    require(not any(value in (main + variables) for value in forbidden), "OpenTofu accepted a forbidden control or private key")
    require('condition     = var.region == "fra1"' in variables, "region allowlist changed")
    require('contains(["intel", "amd"], var.cpu_profile)' in variables, "CPU allowlist changed")
    run_bound_key_pattern = (
        '^ssh-ed25519 [A-Za-z0-9+/]+={0,2} '
        'secpal-ci-${var.run_id}-${var.run_attempt}$'
    )
    require(
        run_bound_key_pattern in variables,
        "DigitalOcean operator key must be bound to the workflow run",
    )

    gcp_main = read(root, "infra/ci-cloud/gcp/main.tf")
    gcp_versions = read(root, "infra/ci-cloud/gcp/versions.tf")
    gcp_variables = read(root, "infra/ci-cloud/gcp/variables.tf")
    gcp_outputs = read(root, "infra/ci-cloud/gcp/outputs.tf")
    read(root, "infra/ci-cloud/gcp/.terraform.lock.hcl")
    require(
        main.count("quadlet_fixture_installer_base64gzip") == 1
        and gcp_main.count("quadlet_fixture_installer_base64gzip") == 1
        and main.count("quadlet_fixture_client_base64gzip") == 1
        and gcp_main.count("quadlet_fixture_client_base64gzip") == 1
        and 'base64gzip(file("${path.module}/../../../scripts/ci-cloud/'
        'quadlet-fixture-installer.py"))' in main
        and 'base64gzip(file("${path.module}/../../../scripts/ci-cloud/'
        'quadlet-fixture-installer.py"))' in gcp_main
        and 'base64gzip(file("${path.module}/../../../scripts/ci-cloud/'
        'quadlet-fixture-client.py"))' in main
        and 'base64gzip(file("${path.module}/../../../scripts/ci-cloud/'
        'quadlet-fixture-client.py"))' in gcp_main
        and "/usr/local/sbin/secpal-ci-quadlet-fixture-installer setup"
        in host_setup,
        "both providers must install the same trusted Quadlet fixture bridge and client",
    )
    require(
        "MAX_UNIT_BYTES = 64 * 1024" in quadlet_fixture_installer
        and "MAX_TOTAL_BYTES = 512 * 1024" in quadlet_fixture_installer
        and quadlet_fixture_installer.count("flags |= os.O_NOFOLLOW") == 3
        and "fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)"
        in quadlet_fixture_installer
        and 'state["state"] = "removing"' in quadlet_fixture_installer
        and 'state["state"] not in {"installing", "active", "removing"}'
        in quadlet_fixture_installer
        and "object_pairs_hook=reject_duplicate_keys" in quadlet_fixture_installer
        and 'type(manifest["schema_version"]) is not int'
        in quadlet_fixture_installer
        and quadlet_fixture_installer.count(
            "flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK"
        )
        == 2
        and '"reason": reason' in quadlet_fixture_installer
        and '"retrying"' in quadlet_fixture_installer
        and '"operation-busy"' in quadlet_fixture_installer
        and 'observed_names != set(names)' in quadlet_fixture_installer
        and 'set(manifest) != {' in quadlet_fixture_installer
        and 'state["files"]' in quadlet_fixture_installer
        and 'if not trusted_file_matches(destination, state["files"][name], layout):'
        in quadlet_fixture_installer
        and 'if operation == "install":\n            stop_path_trigger(trigger, stop_trigger)'
        in quadlet_fixture_handler
        and quadlet_fixture_handler.index("stop_path_trigger(trigger, stop_trigger)")
        < quadlet_fixture_handler.index("parse_request(operation, layout")
        and 'retrying = read_active_state(layout)["state"] == "removing"'
        in quadlet_fixture_handler
        and '"retrying",\n                    "internal-error"'
        in quadlet_fixture_handler
        and "Type=oneshot" in quadlet_fixture_installer
        and "NoNewPrivileges=true" in quadlet_fixture_installer
        and "PrivateNetwork=true" in quadlet_fixture_installer
        and "ProtectHome=true" in quadlet_fixture_installer
        and "ProtectSystem=strict" in quadlet_fixture_installer
        and "PathExists={layout.ready_path(operation)}" in quadlet_fixture_installer
        and "TriggerLimitIntervalSec=60s" in quadlet_fixture_installer
        and "TriggerLimitBurst=3" in quadlet_fixture_installer
        and 'os.unlink("ready"' not in quadlet_fixture_installer
        and "-{layout.request_path(operation)}" not in quadlet_fixture_installer
        and '["systemctl", "start", INSTALL_PATH_UNIT, REMOVE_PATH_UNIT]'
        in quadlet_fixture_installer
        and '"systemctl", "enable"' not in quadlet_fixture_installer
        and "rmtree" not in quadlet_fixture_installer
        and ".glob(" not in quadlet_fixture_installer
        and "shell=True" not in quadlet_fixture_installer
        and "eval(" not in quadlet_fixture_installer
        and "os.system" not in quadlet_fixture_installer,
        "trusted Quadlet fixture installation must remain fixed, bounded, and fail closed",
    )
    require(
        quadlet_fixture_client.count("flags |= os.O_NOFOLLOW") == 1
        and "flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK"
        in quadlet_fixture_client
        and '"reason",' in quadlet_fixture_client
        and 'type(result["schema_version"]) is int' in quadlet_fixture_client
        and 'set(manifest) == {' not in quadlet_fixture_client
        and '"source"' not in required_block(
            quadlet_fixture_client,
            "manifest = {\n",
            "\n        }",
            "Quadlet fixture client manifest",
        )
        and "sudo" not in quadlet_fixture_client,
        "unprivileged Quadlet fixture requests must not carry paths or authority",
    )
    require('required_version = "= 1.12.5"' in gcp_versions, "GCP OpenTofu version must be exact")
    require('version = "= 7.40.0"' in gcp_versions, "Google provider version must be exact")
    require("~>" not in gcp_versions and ">=" not in gcp_versions, "mutable Google provider constraints are forbidden")
    require(
        "length(trimspace(var.ssh_public_key)) <= 128" in gcp_variables,
        "GCP public key input must be bounded before API submission",
    )
    require(
        "add_terraform_attribution_label = false" in gcp_versions,
        "GCP provider attribution labels must be disabled for exact janitor ownership",
    )
    require(gcp_main.count('resource "google_compute_instance"') == 1, "exactly one GCP instance is allowed")
    require(gcp_main.count('resource "google_compute_disk"') == 1, "exactly one GCP disk is allowed")
    require(gcp_main.count('resource "google_compute_network"') == 1, "exactly one GCP network is allowed")
    require(gcp_main.count('resource "google_compute_subnetwork"') == 1, "exactly one GCP subnet is allowed")
    require(gcp_main.count('resource "google_compute_firewall"') == 3, "GCP firewall count changed")
    require(
        re.search(r"^\s*count\s*=", gcp_main, re.MULTILINE) is None
        and re.search(r"^\s*for_each\s*=", gcp_main, re.MULTILINE) is None,
        "GCP resource-count abstraction is forbidden",
    )
    require(
        gcp_main.count('data "google_compute_image" "debian_13"') == 1
        and 'family  = "debian-13-arm64"' in gcp_main
        and 'project = "debian-cloud"' in gcp_main
        and "image  = data.google_compute_image.debian_13.self_link" in gcp_main,
        "GCP image must resolve the official Debian 13 arm64 family",
    )
    require(
        'machine_type = "c4a-standard-4"' in gcp_main
        and 'type   = "hyperdisk-balanced"' in gcp_main
        and "size   = 120" in gcp_main
        and 'nic_type   = "GVNIC"' in gcp_main,
        "GCP Axion machine or bounded disk changed",
    )
    require(
        'output "image_id"' in gcp_outputs
        and "value       = data.google_compute_image.debian_13.self_link" in gcp_outputs
        and 'output "machine_type"' in gcp_outputs,
        "resolved GCP inputs must be exported",
    )
    for label in (
        'secpal_ci_owner    = "deployment-conformance"',
        'repository         = "secpal-deployment"',
        "github_run_id      = var.run_id",
        "github_run_attempt = var.run_attempt",
        "target_sha         = var.target_sha",
        "created_at         = var.created_at",
        "expires_at         = var.expires_at",
    ):
        require(label in gcp_main, "GCP ownership or TTL metadata is incomplete")
    require(gcp_main.count("labels              = local.labels") == 1 and "labels = local.labels" in gcp_main, "GCP instance and disk labels must match")
    require(
        gcp_main.count("service_account {") == 1
        and "email  = var.bootstrap_service_account" in gcp_main
        and "scopes = []" in gcp_main
        and 'variable "bootstrap_service_account"' in gcp_variables
        and "@secpal-dev\\\\.iam\\\\.gserviceaccount\\\\.com"
        in gcp_variables
        and '!= "gcp-service-account@secpal-dev.iam.gserviceaccount.com"'
        in gcp_variables,
        "GCP VM must begin with only the closed role-free bootstrap identity",
    )
    require('block-project-ssh-keys   = "true"' in gcp_main, "project SSH keys must be blocked")
    require('disable-legacy-endpoints = "true"' in gcp_main, "legacy GCP metadata endpoints must be disabled")
    require('enable-oslogin           = "FALSE"' in gcp_main, "unbounded OS Login identity is forbidden")
    require(
        "    ssh-keys                 =" not in gcp_main,
        "GCP metadata must not activate the operator SSH key early",
    )
    require(
        re.search(
            r"^\s*runner_ipv4\s+= var\.runner_ipv4$", gcp_main, re.MULTILINE
        ),
        "GCP host setup must receive the validated runner network context",
    )
    require(
        '"startup-script" = templatefile("${path.module}/../../../scripts/ci-cloud/bootstrap-conformance-host.tftpl"'
        in gcp_main
        and re.search(
            r'^\s*cloud_identity_gate\s+= trimspace\(file\("\$\{path\.module\}/\.\./\.\./\.\./scripts/ci-cloud/defer-bootstrap-for-gcp-identity\.sh"\)\)$',
            gcp_main,
            re.MULTILINE,
        )
        and re.search(
            r'^\s*cloud_identity_gate\s+= ":"$', main, re.MULTILINE
        )
        and "secpal-ci-cloud-identity-admitted" not in gcp_main
        and "user-data" not in gcp_main
        and "install-diagnostic-ssh.sh" in gcp_main,
        "GCP must use its documented native startup-script transport",
    )
    require(
        "continue-conformance-bootstrap.sh" in main
        and "continue-conformance-bootstrap.sh" in gcp_main,
        "both providers must embed the common trusted reboot continuation",
    )
    require('protocol = "all"' in gcp_main and "priority  = 65534" in gcp_main, "GCP residual egress must be denied")
    require('condition     = var.project_id == "secpal-dev"' in gcp_variables, "GCP project allowlist changed")
    require('condition     = var.zone == "europe-west3-a"' in gcp_variables, "GCP zone allowlist changed")
    require(
        run_bound_key_pattern in gcp_variables,
        "GCP operator key must be bound to the workflow run",
    )
    forbidden_gcp = ("tls_private_key", "private_key", "var.image", "var.machine_type", "var.resource_count")
    require(not any(value in (gcp_main + gcp_variables) for value in forbidden_gcp), "GCP OpenTofu accepted a forbidden control or private key")
    require(
        gcp_main.count("bootstrap-conformance-host.tftpl") == 1
        and main.count("bootstrap-conformance-host.tftpl") == 1,
        "both providers must consume the single trusted bootstrap payload",
    )


def validate_janitor_script(root: Path) -> None:
    text = read(root, "scripts/ci-cloud/digitalocean-janitor.py")
    require('client.delete(f"/v2/droplets/{candidate.resource_id}")' in text, "janitor must delete one revalidated ID")
    require("tag_name=" not in text, "janitor must not delete by a tag query")
    require("len(raw_tags) != 5" in text, "janitor ownership must fail closed on ambiguous tags")
    require("current != candidate" in text, "janitor must revalidate immediately before deletion")
    gcp = read(root, "scripts/ci-cloud/gcp-janitor.py")
    require("client.delete_resource(candidate.kind, candidate.name)" in gcp, "GCP janitor must delete one exact revalidated name")
    require("set(raw_labels) != LABEL_KEYS" in gcp, "GCP janitor metadata must fail closed")
    require("current != candidate" in gcp, "GCP janitor must revalidate immediately before deletion")
    require("RESOURCE_KINDS = (\"instances\", \"disks\")" in gcp, "GCP janitor resource scope changed")
    require("instances.aggregatedList" not in gcp and "disks.aggregatedList" not in gcp, "broad GCP cleanup is forbidden")


def validate_gcp_iam_role(root: Path) -> None:
    relative = "infra/ci-cloud/gcp/iam-role.yaml"
    text = read(root, relative)
    try:
        document = yaml.load(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise ContractError(f"{relative} is invalid YAML: {error}") from None
    require(isinstance(document, dict), "GCP custom role must be a mapping")
    require(
        set(document) == {"title", "description", "stage", "includedPermissions"},
        "GCP custom role fields changed",
    )
    require(document.get("stage") == "GA", "GCP custom role must be GA")
    permissions = document.get("includedPermissions")
    require(
        isinstance(permissions, list)
        and len(permissions) == len(GCP_IAM_PERMISSIONS)
        and set(permissions) == GCP_IAM_PERMISSIONS,
        "GCP custom role permissions changed",
    )


def validate(root: Path) -> None:
    validate_conformance_workflow(root)
    validate_janitor_workflow(root)
    validate_opentofu(root)
    validate_janitor_script(root)
    validate_gcp_iam_role(root)
    require("gha-creds-*.json" in read(root, ".gitignore"), "generated GCP credential files must be ignored defensively")
    remote = read(root, "scripts/ci-cloud/run-remote-conformance.sh")
    ssh_probe = read(root, "scripts/ci-cloud/probe-ssh-port.py")
    failure_writer = read(root, "scripts/ci-cloud/write-bootstrap-failure.py")
    failure_schema_text = read(
        root, "schemas/ci-cloud-bootstrap-failure.schema.json"
    )
    workflow = read(root, ".github/workflows/cloud-conformance.yml")
    try:
        failure_schema = json.loads(failure_schema_text)
        Draft202012Validator.check_schema(failure_schema)
    except (json.JSONDecodeError, SchemaError):
        raise ContractError("bootstrap failure evidence schema is invalid") from None
    try:
        schema_host_setup_stages = failure_schema["properties"]["test"][
            "properties"
        ]["host_setup_failure"]["oneOf"][1]["properties"]["stage"]["enum"]
    except (KeyError, IndexError, TypeError):
        raise ContractError(
            "bootstrap failure host-setup stage schema is invalid"
        ) from None
    require(
        isinstance(schema_host_setup_stages, list)
        and len(schema_host_setup_stages) == len(HOST_SETUP_FAILURE_STAGES)
        and set(schema_host_setup_stages) == HOST_SETUP_FAILURE_STAGES,
        "bootstrap failure evidence stages must match the host marker",
    )
    require(
        failure_schema["properties"]["schema_version"].get("const")
        == BOOTSTRAP_FAILURE_SCHEMA_VERSION
        and integer_mapping_literal(failure_writer, "schema_version")
        == BOOTSTRAP_FAILURE_SCHEMA_VERSION,
        "bootstrap failure writer and declared schema version must match",
    )
    root_ssh_admission = required_block(
        remote,
        'bootstrap_stage="root-ssh"',
        'started_at="$(date -u',
        "root SSH admission block",
    )
    require(
        "root_ssh_denied=true" in root_ssh_admission
        and '"$root_probe_status" -eq 255' in root_ssh_admission
        and "operator_recheck_status" in root_ssh_admission
        and 'ssh "${ssh_options[@]}" "secpal-ci@$address" true'
        in root_ssh_admission
        and "permission denied" not in root_ssh_admission
        and "root_probe=" not in root_ssh_admission,
        "remote orchestration must prove effective root SSH denial",
    )
    require(
        "tofu output -raw image_id" in workflow
        and 'provider_image_id="${11}"' in remote
        and '"$root_ssh_denied" "$provider_image_slug" "$provider_image_id"' in remote,
        "resolved provider image ID must reach the trusted evidence collector",
    )
    require(
        "debian-13-trixie-arm64-v[0-9]{8}" in remote,
        "GCP evidence must admit only the official codename-bearing image name",
    )
    require(
        "/usr/bin/env -i" in remote
        and "/usr/bin/python3 -I -" in remote
        and '\n  python3 - "$provider"' not in remote,
        "trusted evidence collector must ignore target-owned Python startup state",
    )
    require(
        "/tmp/secpal-target-conformance.log" not in remote
        and ") >/dev/null 2>&1" in remote,
        "target output must not use a shared temporary path",
    )
    require(
        'bootstrap_stage="host-key"' in remote
        and 'host_key_observations_json="null"' in remote
        and "record_host_key_observation()" in remote
        and "observe_failed_host_key_scan()" in remote
        and "scripts/ci-cloud/probe-ssh-port.py" in remote
        and "connection_refused" in remote
        and "connection_timeout" in remote
        and "multiple_keys" in remote
        and "changed_key" in remote
        and 'orchestration_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"'
        in remote
        and '"$orchestration_started_at"' in remote
        and "scripts/ci-cloud/write-bootstrap-failure.py" in remote
        and 'bootstrap_stage="bootstrap"' in remote
        and "native bootstrap did not reach trusted host setup" in remote
        and "cloud-init" not in remote,
        "early remote failures need bounded structured evidence and diagnostics",
    )
    host_key_classifier = required_block(
        remote,
        "classify_host_key_scan() {",
        "\n}\n",
        "host-key classifier block",
    )
    require(
        "connection_refused | connection_timeout | other"
        in host_key_classifier
        and "reachable" in host_key_classifier
        and "grep" not in host_key_classifier
        and "_scan_error" not in remote,
        "host-key reachability must use closed observations instead of scanner text",
    )
    require(
        "PROBE_TIMEOUT_SECONDS = 5.0" in ssh_probe
        and "socket.AF_INET, socket.SOCK_STREAM" in ssh_probe
        and "connection.connect_ex((address, 22))" in ssh_probe
        and "errno.ECONNREFUSED" in ssh_probe
        and "errno.ETIMEDOUT" in ssh_probe
        and 'return "connection_refused"' in ssh_probe
        and 'return "connection_timeout"' in ssh_probe
        and "ipaddress.ip_address(arguments.address)" in ssh_probe
        and "not address.is_global" in ssh_probe
        and "subprocess" not in ssh_probe
        and "os.environ" not in ssh_probe,
        "SSH reachability evidence must come from a bounded public-IPv4 TCP probe",
    )
    require(
        "operator_ssh_ready=false" in remote
        and "for _ in {1..30}; do" not in remote
        and remote.count("while ((SECONDS < bootstrap_deadline)); do") == 2
        and "operator SSH access did not become ready; trusted host setup"
        in remote
        and "network reachability, or sshd may have failed" in remote,
        "remote orchestration must wait boundedly for deferred operator SSH access",
    )
    require(
        "diagnostic_ssh_seen=false" in remote
        and "SECPAL_CI_DIAGNOSTIC_SSH" in remote
        and "SECPAL_CI_HOST_SETUP_FAILURE" in remote
        and "scripts/ci-cloud/host-setup-failure.py validate" in remote
        and '"$diagnostic_probe_status" -eq 125' in remote
        and '"secpal-ci-diagnostic@$address"' in remote
        and "native bootstrap did not reach trusted host setup" in remote,
        "remote orchestration must recognize bounded restricted diagnostics",
    )
    require(
        "bootstrap_deadline=$((SECONDS + 15 * 60))" in remote
        and "host_key_deadline" not in remote,
        "remote orchestration must wait boundedly for masked SSH",
    )
    require(
        "scripts/ci-cloud/host-setup-failure.py" in remote
        and "/usr/bin/python3 -I - read" in remote
        and "Trusted host setup failure" in remote
        and '"$bootstrap_stage" "$status" "$host_setup_failure_json"'
        in remote,
        "remote orchestration must preserve the closed host-setup diagnostic",
    )
    require(
        "ci-cloud-bootstrap-failure.schema.json" in failure_writer
        and "validate_declared_schema(document)" in failure_writer
        and "write_bundle(" in failure_writer
        and "os.link(" in failure_writer,
        "bootstrap failure evidence must be schema-validated and failure-atomic",
    )


def main(arguments: list[str]) -> int:
    root = Path(arguments[0]).resolve() if arguments else Path.cwd()
    try:
        validate(root)
    except (ContractError, OSError, UnicodeError) as error:
        print(f"FAIL: cloud CI contract: {error}", file=sys.stderr)
        return 1
    print("Cloud CI static trust-boundary contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
