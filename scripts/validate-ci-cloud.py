#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static validation for the cloud conformance trust boundary."""

from __future__ import annotations

import ast
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
    "compute.instances.setTags",
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
    for cleanup_name in ("digitalocean_cleanup", "gcp_cleanup"):
        cleanup = jobs[cleanup_name]
        require(isinstance(cleanup, dict), f"{cleanup_name} job must be a mapping")
        require("always()" in str(cleanup.get("if", "")), f"{cleanup_name} must run with always()")
    require(text.count("tofu destroy --auto-approve --input=false") == 2, "each provider cleanup must use exact tofu destroy")
    require("--tag-name" not in text and "delete --force" not in text, "broad cleanup is forbidden")
    require("credentials_json" not in text and "service_account_key" not in text, "long-lived GCP keys are forbidden")
    require(text.count("id-token: write") == 2, "OIDC permission must be limited to GCP apply and cleanup jobs")
    require(text.count("google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093") == 2, "GCP auth action pin or scope changed")
    require(text.count("create_credentials_file: false") == 2, "GCP auth must not create ADC files")
    require(text.count("export_environment_variables: false") == 2, "GCP auth must not export job credentials")
    require(
        text.count("projects/94792370946/locations/global/workloadIdentityPools/secpal/providers/github")
        == 2
        and text.count("gcp-service-account@secpal-dev.iam.gserviceaccount.com") == 2,
        "GCP apply and cleanup identities must be validated before authentication",
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
                require(not credentialed and not env, "remote conformance step must have no credential environment")
    require(
        secret_steps
        == {
            "Apply DigitalOcean infrastructure",
            "Destroy exact DigitalOcean run infrastructure",
            "Apply GCP infrastructure",
            "Destroy exact GCP run infrastructure",
        },
        "cloud credentials must be scoped to apply and exact destroy only",
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
    cloud_init = read(root, "infra/ci-cloud/digitalocean/cloud-init.tftpl")
    host_setup = read(root, "scripts/ci-cloud/configure-conformance-host.sh")
    diagnostic_ssh = read(root, "scripts/ci-cloud/install-diagnostic-ssh.sh")
    host_setup_failure = read(root, "scripts/ci-cloud/host-setup-failure.py")
    collector = read(root, "scripts/ci-cloud/collect-host-evidence.py")
    read(root, "infra/ci-cloud/digitalocean/.terraform.lock.hcl")
    require('required_version = "= 1.12.5"' in versions, "OpenTofu version must be exact")
    require('version = "= 2.99.1"' in versions, "DigitalOcean provider version must be exact")
    require("~>" not in versions and ">=" not in versions, "mutable provider constraints are forbidden")
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
    for required in (
        "  - gh\n",
        "  - unattended-upgrades\n",
        "APT::Periodic::Unattended-Upgrade \"1\";",
        "#clear Unattended-Upgrade::Origins-Pattern;",
        "#clear Unattended-Upgrade::Package-Blacklist;",
        "Unattended-Upgrade::Automatic-Reboot \"false\";",
        "QUADLET_UNIT_DIRS=/etc/containers/systemd/users/20000",
        "secpal-ci-configure-conformance-host",
        "secpal-ci-host-setup-failure",
        "${host_setup_failure_script}",
    ):
        require(required in cloud_init, "cloud-init omitted required D.1 host policy")
    require("set -euo pipefail" in host_setup, "host setup must use strict Bash mode")
    require("groups: []" not in cloud_init, "cloud-init user groups must satisfy its schema")
    require(
        "ssh_authorized_keys" not in cloud_init
        and "${diagnostic_ssh_installer}" in cloud_init
        and "  - path: /run/secpal-ci-authorized-key\n" in cloud_init
        and '    owner: root:root\n    permissions: "0600"\n' in cloud_init
        and "  - path: /etc/ssh/sshd_config.d/00-secpal-ci.conf\n"
        in cloud_init
        and "sshd_config.d/90-secpal-ci.conf" not in cloud_init
        and "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u"
        in cloud_init,
        "operator SSH key must remain root-only until trusted host setup finishes",
    )
    require(
        "systemctl mask --now ssh.service ssh.socket"
        in diagnostic_ssh
        and "OnActiveSec=10m" in diagnostic_ssh
        and "ForceCommand /run/secpal-ci-cloud-init-diagnostic"
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
    diagnostic_cleanup = diagnostic_ssh.split("cleanup() {", 1)[1].split(
        "\n}", 1
    )[0]
    diagnostic_preparation = diagnostic_ssh.split(
        "prepare_diagnostic_fallback() {", 1
    )[1].split("\n}", 1)[0]
    diagnostic_start = diagnostic_ssh.split(
        "start_diagnostic_fallback() {", 1
    )[1].split("\n}", 1)[0]
    diagnostic_initial_transition = diagnostic_ssh.rsplit(
        "if completed_setup_is_valid; then", 1
    )[1]
    operator_activation = host_setup.split(
        "activate_operator_ssh() {", 1
    )[1].split("\n}", 1)[0]
    diagnostic_restore = host_setup.split(
        "restore_diagnostic_ssh() {", 1
    )[1].split("\n}", 1)[0]
    diagnostic_recovery = host_setup.split(
        "arm_diagnostic_ssh_recovery() {", 1
    )[1].split("\n}", 1)[0]
    completed_validator = diagnostic_ssh.split(
        "completed_setup_is_valid() {", 1
    )[1].split("\n}", 1)[0]
    require(
        "ensure_diagnostic_identity" in diagnostic_preparation
        and '[[ "$(id -G "$diagnostic_user")" == "$group_gid" ]]'
        in diagnostic_ssh
        and "ssh-keygen -A" in diagnostic_preparation
        and 'sshd -t -f "$config_tmp"' in diagnostic_preparation
        and "OnActiveSec=10m" in diagnostic_preparation
        and "/run/systemd/system/$diagnostic_service" in diagnostic_ssh
        and "/run/systemd/system/$diagnostic_timer" in diagnostic_ssh
        and 'systemd-analyze verify "$diagnostic_service_unit"'
        in diagnostic_ssh
        and 'chmod 0600 "$key_tmp" "$config_tmp" "$service_tmp" "$timer_tmp"'
        in diagnostic_preparation
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
        and diagnostic_start.index("prepare_diagnostic_fallback")
        < diagnostic_start.index("systemctl mask --now ssh.service ssh.socket")
        < diagnostic_start.index('systemctl restart "$diagnostic_service"')
        < diagnostic_start.index(
            'systemctl is-active --quiet "$diagnostic_service"'
        )
        < diagnostic_start.index('systemctl stop "$diagnostic_timer"')
        and '! systemctl is-active --quiet "$diagnostic_timer"'
        in diagnostic_start
        and "Restart=on-failure" in diagnostic_preparation
        and "RestartSec=5s" in diagnostic_preparation
        and "StartLimitIntervalSec=2m" in diagnostic_preparation
        and "StartLimitBurst=5" in diagnostic_preparation
        and "if ! start_diagnostic_fallback; then"
        in diagnostic_initial_transition
        and "unable to establish restricted diagnostic SSH during bootstrap"
        in diagnostic_initial_transition
        and "\nprepare_diagnostic_fallback\n"
        not in diagnostic_initial_transition
        and 'completion_marker="$active_operator_root/host-setup-complete"'
        in diagnostic_ssh
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
        and 'systemctl restart "$diagnostic_service"' in diagnostic_ssh,
        "restricted diagnostic SSH must replace primary SSH transactionally",
    )
    require(
        'systemctl start "$diagnostic_ssh_timer"' in diagnostic_recovery
        and 'systemctl is-active --quiet "$diagnostic_ssh_timer"'
        in diagnostic_recovery
        and "arm_diagnostic_ssh_recovery" in operator_activation
        and 'systemctl stop "$diagnostic_ssh_service"' in operator_activation
        and 'systemctl restart ssh.service' in operator_activation
        and 'systemctl is-active --quiet ssh.service' in operator_activation
        and operator_activation.index(
            "arm_diagnostic_ssh_recovery"
        )
        < operator_activation.index(
            'systemctl stop "$diagnostic_ssh_service"'
        )
        < operator_activation.index("systemctl restart ssh.service")
        < operator_activation.index("systemctl is-active --quiet ssh.service")
        < operator_activation.index("retire_diagnostic_ssh")
        and 'arm_diagnostic_ssh_recovery || return 1' in diagnostic_restore
        and diagnostic_restore.index("arm_diagnostic_ssh_recovery")
        < diagnostic_restore.index("systemctl mask --now ssh.service ssh.socket")
        < diagnostic_restore.index(
            'systemctl restart "$diagnostic_ssh_service"'
        )
        < diagnostic_restore.index(
            'systemctl is-active --quiet "$diagnostic_ssh_service"'
        )
        < diagnostic_restore.index(
            'systemctl stop "$diagnostic_ssh_timer"'
        ),
        "SSH handoffs must retain a verified listener or armed recovery timer",
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
        and 'groupdel "$diagnostic_ssh_user"' in host_setup,
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
        and host_setup.index(private_key_install) < host_setup.index(key_publish)
        < host_setup.index(published_key_chmod)
        < host_setup.index(published_directory_chmod)
        < host_setup.index("systemctl unmask ssh.service ssh.socket")
        < host_setup.index("systemctl disable --now ssh.socket")
        < host_setup.index("systemctl enable ssh.service")
        < host_setup.index("systemctl restart ssh.service"),
        "operator SSH key staging must remain private until publication",
    )
    require(
        host_setup.index("if ! publish_completion_marker; then")
        < host_setup.index("systemctl restart ssh.service")
        < host_setup.index("ssh_key_activated=true")
        < host_setup.index("if ! retire_diagnostic_ssh; then")
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
        == {"initialize", "subordinate-ids", "service-policy", "apparmor", "ssh"}
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
    try:
        cloud_config = yaml.load(cloud_init, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise ContractError(f"cloud-init template is invalid YAML: {error}") from None
    require(isinstance(cloud_config, dict), "cloud-init template must be a YAML mapping")
    users = cloud_config.get("users")
    require(
        isinstance(users, list)
        and len(users) == 1
        and isinstance(users[0], dict)
        and "ssh_authorized_keys" not in users[0],
        "cloud-init must not activate the operator key during user creation",
    )
    write_files = cloud_config.get("write_files")
    require(
        isinstance(write_files, list)
        and any(
            isinstance(entry, dict)
            and entry.get("path") == "/run/secpal-ci-authorized-key"
            and entry.get("owner") == "root:root"
            and entry.get("permissions") == "0600"
            and entry.get("content") == "${ssh_public_key}\n"
            for entry in write_files
        ),
        "cloud-init must stage exactly one root-owned operator public key",
    )
    require(
        any(
            isinstance(entry, dict)
            and entry.get("path")
            == "/usr/local/sbin/secpal-ci-host-setup-failure"
            and entry.get("owner") == "root:root"
            and entry.get("permissions") == "0755"
            for entry in write_files
        ),
        "restricted diagnostics must be able to execute the closed failure reader",
    )
    sshd_files = [
        entry
        for entry in write_files
        if isinstance(entry, dict)
        and str(entry.get("path", "")).startswith("/etc/ssh/sshd_config.d/")
    ]
    require(
        len(sshd_files) == 1
        and sshd_files[0].get("path")
        == "/etc/ssh/sshd_config.d/00-secpal-ci.conf"
        and sshd_files[0].get("owner") == "root:root"
        and sshd_files[0].get("permissions") == "0644"
        and sshd_files[0].get("content")
        == "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "MaxSessions 1\n"
        "PAMServiceName sshd\n"
        "PermitRootLogin no\n"
        "PubkeyAuthentication yes\n"
        "AuthenticationMethods publickey\n"
        "PubkeyAcceptedAlgorithms +ssh-ed25519\n"
        "AuthorizedKeysCommand none\n"
        "AuthorizedKeysFile /var/lib/secpal-ci/authorized-keys/%u\n"
        "AuthorizedPrincipalsCommand none\n"
        "AuthorizedPrincipalsFile none\n"
        "TrustedUserCAKeys none\n"
        "RevokedKeys none\n"
        "RefuseConnection no\n"
        "StrictModes yes\n"
        "ChrootDirectory none\n"
        "ForceCommand none\n"
        "DisableForwarding yes\n"
        "PermitTTY no\n"
        "PermitUserEnvironment no\n"
        "PermitUserRC no\n"
        "UseDNS no\n"
        "UsePAM yes\n"
        "AllowUsers secpal-ci\n",
        "cloud-init SSH policy must be exact, prioritized, and operator-scoped",
    )
    require(
        cloud_config.get("bootcmd")
        == [
            [
                "/bin/bash",
                "-c",
                "${diagnostic_ssh_installer}\n",
                "secpal-ci-install-diagnostic-ssh",
                "${ssh_public_key}",
                "${runner_ipv4}",
                "${run_id}",
                "${run_attempt}",
            ]
        ]
        and cloud_config.get("runcmd")
        == [["/usr/local/sbin/secpal-ci-configure-conformance-host", "${runner_ipv4}"]]
        and "runner_ipv4               = var.runner_ipv4" in main,
        "host setup must receive the validated runner network context",
    )
    packages = cloud_config.get("packages")
    require(
        isinstance(packages, list)
        and all(isinstance(package, str) for package in packages)
        and set(packages) == string_collection_constant(collector, "BOOTSTRAP_PACKAGES"),
        "collector bootstrap package evidence must exactly match cloud-init packages",
    )
    curl_commands = subprocess_literal_arguments(collector, "cloud_identity_facts")
    require(
        len(curl_commands) == 2
        and all(command[:2] == ["curl", "--disable"] for command in curl_commands),
        "cloud identity probe must ignore target-owned curl configuration",
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
    gcp_cloud_init = read(root, "infra/ci-cloud/gcp/cloud-init.tftpl")
    read(root, "infra/ci-cloud/gcp/.terraform.lock.hcl")
    require('required_version = "= 1.12.5"' in gcp_versions, "GCP OpenTofu version must be exact")
    require('version = "= 7.40.0"' in gcp_versions, "Google provider version must be exact")
    require("~>" not in gcp_versions and ">=" not in gcp_versions, "mutable Google provider constraints are forbidden")
    require(
        "add_terraform_attribution_label = false" in gcp_versions,
        "GCP provider attribution labels must be disabled for exact janitor ownership",
    )
    require(gcp_main.count('resource "google_compute_instance"') == 1, "exactly one GCP instance is allowed")
    require(gcp_main.count('resource "google_compute_disk"') == 1, "exactly one GCP disk is allowed")
    require(gcp_main.count('resource "google_compute_network"') == 1, "exactly one GCP network is allowed")
    require(gcp_main.count('resource "google_compute_subnetwork"') == 1, "exactly one GCP subnet is allowed")
    require(gcp_main.count('resource "google_compute_firewall"') == 3, "GCP firewall count changed")
    require("count" not in gcp_main and "for_each" not in gcp_main, "GCP resource-count abstraction is forbidden")
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
    require("service_account" not in gcp_main, "GCP test VM must not have a service account")
    require('block-project-ssh-keys   = "true"' in gcp_main, "project SSH keys must be blocked")
    require('disable-legacy-endpoints = "true"' in gcp_main, "legacy GCP metadata endpoints must be disabled")
    require('enable-oslogin           = "FALSE"' in gcp_main, "unbounded OS Login identity is forbidden")
    require(
        "    ssh-keys                 =" not in gcp_main,
        "GCP metadata must not activate the operator SSH key early",
    )
    require(
        "runner_ipv4               = var.runner_ipv4" in gcp_main,
        "GCP host setup must receive the validated runner network context",
    )
    require(
        "install-diagnostic-ssh.sh" in gcp_main,
        "GCP cloud-init must embed the trusted diagnostic SSH installer",
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
    require(gcp_cloud_init == cloud_init, "provider cloud-init admission policy drifted")


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
    require(
        "root_ssh_denied=true" in remote
        and 'grep -qi \'permission denied\'' in remote,
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
        and "classify_host_key_scan()" in remote
        and "connection_refused" in remote
        and "connection_timeout" in remote
        and "multiple_keys" in remote
        and "changed_key" in remote
        and 'orchestration_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"'
        in remote
        and '"$orchestration_started_at"' in remote
        and "scripts/ci-cloud/write-bootstrap-failure.py" in remote
        and "cloud-init status --long" in remote
        and "head -c 8192" in remote
        and "cloud-init-output.log" not in remote,
        "early remote failures need bounded structured evidence and diagnostics",
    )
    host_key_classifier = remote.split("classify_host_key_scan() {", 1)[
        1
    ].split("\n}\n", 1)[0]
    nonzero_host_key_fallback = (
        "elif ((status != 0)); then\n    printf 'other\\n'"
    )
    empty_successful_host_key_scan = (
        "elif ((line_count == 0)); then\n    printf 'no_key\\n'"
    )
    require(
        nonzero_host_key_fallback in host_key_classifier
        and empty_successful_host_key_scan in host_key_classifier
        and host_key_classifier.index(nonzero_host_key_fallback)
        < host_key_classifier.index(empty_successful_host_key_scan),
        "failed host-key scans must not be classified as successful empty scans",
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
        and "cloud-init did not reach trusted host setup" in remote,
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
