#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static validation for the cloud conformance trust boundary."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
REQUIRED_INPUTS = {"target_sha", "provider_profile"}
PROFILES = {"digitalocean-intel", "digitalocean-amd"}
CREDENTIAL_KEYS = {"DIGITALOCEAN_TOKEN", "DIGITALOCEAN_ACCESS_TOKEN"}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def read(root: Path, relative: str) -> str:
    path = root / relative
    require(path.is_file(), f"required cloud CI file is missing: {relative}")
    return path.read_text(encoding="utf-8")


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
    require(text.count("ref: ${{ github.sha }}") == 2, "trusted checkout must stay on the workflow commit")
    require(text.count("persist-credentials: false") == 2, "checkout credentials must not persist")

    jobs = document.get("jobs")
    assert isinstance(jobs, dict)
    require(set(jobs) == {"provision_test", "cleanup"}, "unexpected cloud conformance job")
    cleanup = jobs["cleanup"]
    require(isinstance(cleanup, dict), "cleanup job must be a mapping")
    require(jobs["provision_test"].get("environment") == "ci-cloud-digitalocean", "provisioning environment changed")
    require(cleanup.get("environment") == "ci-cloud-digitalocean-cleanup", "cleanup environment changed")
    require("always()" in str(cleanup.get("if", "")), "cleanup job must run with always()")
    require("tofu destroy --auto-approve --input=false" in text, "cleanup must use exact tofu destroy")
    require("--tag-name" not in text and "delete --force" not in text, "broad cleanup is forbidden")

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
                    name in {"Apply DigitalOcean infrastructure", "Destroy exact run infrastructure"},
                    f"cloud credential reached unexpected step: {name}",
                )
                forbidden = ("target-conformance", "run-remote-conformance", "ssh ", "scp ", "target_sha")
                require(not any(value in run for value in forbidden), "target code reached a credentialed step")
            if name == "Run uncredentialed remote conformance":
                require(not credentialed and not env, "remote conformance step must have no credential environment")
    require(
        secret_steps == {"Apply DigitalOcean infrastructure", "Destroy exact run infrastructure"},
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
    require(text.count("secrets.DIGITALOCEAN_ACCESS_TOKEN") == 1, "janitor token scope changed")
    require("ref: ${{ github.sha }}" in text and "persist-credentials: false" in text, "janitor checkout trust changed")
    validate_action_pins(document, relative)


def validate_opentofu(root: Path) -> None:
    main = read(root, "infra/ci-cloud/digitalocean/main.tf")
    versions = read(root, "infra/ci-cloud/digitalocean/versions.tf")
    variables = read(root, "infra/ci-cloud/digitalocean/variables.tf")
    read(root, "infra/ci-cloud/digitalocean/cloud-init.tftpl")
    read(root, "infra/ci-cloud/digitalocean/.terraform.lock.hcl")
    require('required_version = "= 1.12.5"' in versions, "OpenTofu version must be exact")
    require('version = "= 2.99.1"' in versions, "DigitalOcean provider version must be exact")
    require("~>" not in versions and ">=" not in versions, "mutable provider constraints are forbidden")
    require(main.count('resource "digitalocean_droplet"') == 1, "exactly one droplet resource is allowed")
    require("count" not in main, "resource count abstraction is forbidden")
    require('image             = "debian-13-x64"' in main, "cloud image must be the fixed Debian 13 slug")
    require('intel = "s-8vcpu-16gb-intel"' in main, "Intel size allowlist changed")
    require('amd   = "s-8vcpu-16gb-amd"' in main, "AMD size allowlist changed")
    require("local.owner_tag," in main, "SecPal CI owner metadata is missing")
    require("local.repo_tag," in main, "repository metadata is missing")
    require("local.sha_tag," in main, "target SHA metadata is missing")
    require("local.created_tag," in main, "creation metadata is missing")
    require("local.expires_tag," in main, "expiration metadata is missing")
    forbidden = ("tls_private_key", "private_key", "var.image", "var.machine_type", "var.resource_count")
    require(not any(value in (main + variables) for value in forbidden), "OpenTofu accepted a forbidden control or private key")
    require('condition     = var.region == "fra1"' in variables, "region allowlist changed")
    require('contains(["intel", "amd"], var.cpu_profile)' in variables, "CPU allowlist changed")


def validate_janitor_script(root: Path) -> None:
    text = read(root, "scripts/ci-cloud/digitalocean-janitor.py")
    require('client.delete(f"/v2/droplets/{candidate.resource_id}")' in text, "janitor must delete one revalidated ID")
    require("tag_name=" not in text, "janitor must not delete by a tag query")
    require("len(raw_tags) != 5" in text, "janitor ownership must fail closed on ambiguous tags")
    require("current != candidate" in text, "janitor must revalidate immediately before deletion")


def validate(root: Path) -> None:
    validate_conformance_workflow(root)
    validate_janitor_workflow(root)
    validate_opentofu(root)
    validate_janitor_script(root)


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
