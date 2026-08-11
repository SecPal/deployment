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
    require("cancel-in-progress: false" in text, "cloud cleanup must not be cancelled by concurrency")
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
        and "bootcmd:\n"
        "  - [systemctl, mask, --runtime, --now, ssh.service, ssh.socket]\n"
        in cloud_init
        and "  - path: /run/secpal-ci-authorized-key\n" in cloud_init
        and '    owner: root:root\n    permissions: "0600"\n' in cloud_init
        and "  - path: /etc/ssh/sshd_config.d/00-secpal-ci.conf\n"
        in cloud_init
        and "sshd_config.d/90-secpal-ci.conf" not in cloud_init
        and "AuthorizedKeysFile /run/secpal-ci-authorized-keys/%u"
        in cloud_init,
        "operator SSH key must remain root-only until trusted host setup finishes",
    )
    require(
        "activate_operator_ssh || true" in host_setup
        and 'setup_stage="ssh"\nactivate_operator_ssh\n' in host_setup
        and "active_ssh_authorized_keys_dir=/run/secpal-ci-authorized-keys"
        in host_setup
        and 'active_ssh_authorized_keys="$active_ssh_authorized_keys_dir/secpal-ci"'
        in host_setup
        and 'mv -T -- "$authorized_keys_tmp_dir" \\\n    "$active_ssh_authorized_keys_dir"'
        in host_setup,
        "host setup must defer operator SSH access and preserve failure diagnostics",
    )
    require(
        "validate_effective_sshd_config || return 1" in host_setup
        and "sshd -T -C" in host_setup
        and "allowusers secpal-ci" in host_setup
        and "authenticationmethods publickey" in host_setup
        and "authorizedkeyscommand none" in host_setup
        and "authorizedkeysfile /run/secpal-ci-authorized-keys/%u"
        in host_setup
        and "authorizedprincipalscommand none" in host_setup
        and "authorizedprincipalsfile none" in host_setup
        and "permitrootlogin no" in host_setup
        and "trustedusercakeys none" in host_setup
        and "usedns no" in host_setup
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
        and "systemctl unmask --runtime ssh.service ssh.socket" in host_setup
        and "systemctl restart ssh.service" in host_setup
        and 'chmod 0755 "$authorized_keys_tmp_dir"' not in host_setup
        and host_setup.index(private_key_install) < host_setup.index(key_publish)
        < host_setup.index(published_key_chmod)
        < host_setup.index(published_directory_chmod)
        < host_setup.index("systemctl unmask --runtime ssh.service ssh.socket")
        < host_setup.index("systemctl restart ssh.service"),
        "operator SSH key staging must remain private until publication",
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
        "PermitRootLogin no\n"
        "PubkeyAuthentication yes\n"
        "AuthenticationMethods publickey\n"
        "AuthorizedKeysCommand none\n"
        "AuthorizedKeysFile /run/secpal-ci-authorized-keys/%u\n"
        "AuthorizedPrincipalsCommand none\n"
        "AuthorizedPrincipalsFile none\n"
        "TrustedUserCAKeys none\n"
        "UseDNS no\n"
        "AllowUsers secpal-ci\n",
        "cloud-init SSH policy must be exact, prioritized, and operator-scoped",
    )
    require(
        cloud_config.get("bootcmd")
        == [["systemctl", "mask", "--runtime", "--now", "ssh.service", "ssh.socket"]]
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
        and 'orchestration_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"'
        in remote
        and '"$orchestration_started_at"' in remote
        and "scripts/ci-cloud/write-bootstrap-failure.py" in remote
        and "cloud-init status --long" in remote
        and "head -c 8192" in remote
        and "cloud-init-output.log" not in remote,
        "early remote failures need bounded structured evidence and diagnostics",
    )
    require(
        "operator_ssh_ready=false" in remote
        and "for _ in {1..30}; do" in remote
        and "operator SSH access did not become ready; trusted host setup"
        in remote
        and "network reachability, or sshd may have failed" in remote,
        "remote orchestration must wait boundedly for deferred operator SSH access",
    )
    require(
        "host_key_deadline=$((SECONDS + 15 * 60))" in remote
        and "while ((SECONDS < host_key_deadline)); do" in remote,
        "remote orchestration must wait boundedly for runtime-masked SSH",
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
