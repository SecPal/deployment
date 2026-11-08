#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static validation for the cloud conformance trust boundary."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
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
    "compute.firewalls.list",
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
    "compute.networks.list",
    # Required by the network field on subnetworks.insert and firewalls.insert.
    "compute.networks.updatePolicy",
    "compute.projects.get",
    "compute.regionOperations.get",
    "compute.subnetworks.create",
    "compute.subnetworks.delete",
    "compute.subnetworks.get",
    "compute.subnetworks.list",
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
    require(text.count("GOOGLE_OAUTH_ACCESS_TOKEN") == 2, "GCP janitor token scope changed")
    require(text.count("id-token: write") == 1, "janitor OIDC permission scope changed")
    require(text.count("google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093") == 1, "janitor auth action pin changed")
    require(
        text.count("projects/94792370946/locations/global/workloadIdentityPools/secpal/providers/github")
        == 1
        and text.count("gcp-service-account@secpal-dev.iam.gserviceaccount.com") == 1,
        "GCP janitor identity must be validated before authentication",
    )
    require(text.count("ref: ${{ github.sha }}") == 2 and text.count("persist-credentials: false") == 2, "janitor checkout trust changed")
    require(
        "scripts/ci-cloud/gcp-janitor.py" in text
        and "scripts/ci-cloud/gcp-rocky-janitor.py" in text
        and "--zone europe-west3-a" in text,
        "bounded GCP janitor invocation is missing",
    )
    validate_action_pins(document, relative)


def exact_version(constraint: str) -> str | None:
    """OpenTofu treats a bare version and an explicit equality identically."""
    match = re.fullmatch(r"(?:=\s*)?([0-9]+\.[0-9]+\.[0-9]+)", constraint.strip())
    return match.group(1) if match else None


def validate_provider_pin(root: Path, directory: str, source: str) -> str:
    """versions.tf owns the pin; each readonly lock must agree with it."""
    versions = read(root, f"infra/ci-cloud/{directory}/versions.tf")
    lock = read(root, f"infra/ci-cloud/{directory}/.terraform.lock.hcl")
    label = "Rocky" if directory == "gcp-rocky" else "cleanup"
    tofu_versions = re.findall(r'^\s*required_version\s*=\s*"([^"]*)"', versions, re.MULTILINE)
    require(len(tofu_versions) == 1 and exact_version(tofu_versions[0]) == "1.12.5",
            "OpenTofu version must be exact")
    require(f'source  = "{source}"' in versions, f"{label} provider source changed")
    provider_versions = re.findall(r'^\s*version\s*=\s*"([^"]*)"', versions, re.MULTILINE)
    require(len(provider_versions) == 1, f"{label} provider must declare one version")
    version = exact_version(provider_versions[0])
    require(version is not None, f"{label} provider version must be exact")
    require("~>" not in versions and ">=" not in versions, "mutable provider constraints are forbidden")
    require(f'provider "registry.opentofu.org/{source}"' in lock
            and re.search(r'version\s*=\s*"' + re.escape(version) + r'"', lock),
            f"{label} provider lock must match the pinned provider")
    constraints = re.findall(r'^\s*constraints\s*=\s*"([^"]*)"\s*$', lock, re.MULTILINE)
    require(len(constraints) == 1 and exact_version(constraints[0]) == version,
            f"{label} provider lock constraints must match the pinned provider")
    return version


def validate_opentofu(root: Path) -> None:
    # Cleanup and provisioning share the manifest/lock agreement rule.
    validate_provider_pin(root, "digitalocean", "digitalocean/digitalocean")
    validate_provider_pin(root, "gcp", "hashicorp/google")
    validate_provider_pin(root, "gcp-rocky", "hashicorp/google")
    gcp = read(root, "infra/ci-cloud/gcp/versions.tf")
    require('project                         = "secpal-dev"' in gcp
            and 'zone                            = "europe-west3-a"' in gcp
            and 'add_terraform_attribution_label = false' in gcp,
            "cleanup provider must retain the reviewed GCP scope")


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


def validate_rocky_control_plane(root: Path) -> None:
    """Only exact retained-state cleanup remains reachable; no provisioning."""
    relative = ".github/workflows/rocky-cloud-qualification.yml"
    document, text = load_workflow(root, relative)
    require(set(document["on"]) == {"workflow_dispatch"}, "recovery must be manually dispatched")
    inputs = document["on"]["workflow_dispatch"]["inputs"]
    require(inputs["operation"]["options"] == ["destroy"], "GCP provisioning is retired")
    jobs = document["jobs"]
    require(set(jobs) == {"validate", "cleanup"}, "only retained-state cleanup is allowed")
    require(jobs["cleanup"]["needs"] == "validate"
            and jobs["cleanup"]["if"] == "${{ needs.validate.result == 'success' }}",
            "cleanup requires successful independent admission")
    require("id-token" not in jobs["validate"].get("permissions", {})
            and jobs["cleanup"]["permissions"] == {"actions": "read", "contents": "read", "id-token": "write"},
            "source admission and cleanup authority must stay separate")
    require('[[ "$IS_DEFAULT_BRANCH" == true ]]' in text
            and "IS_DEFAULT_BRANCH: ${{ github.ref == 'refs/heads/main' }}" in text,
            "cleanup must use protected main")
    cleanup = text.split("\n  cleanup:\n", 1)[1]
    require('[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ||\n'
            '                "${RAW_TARGET_SHA,,}" == "$historical_cleanup_target_sha" ]]' in text,
            "cleanup target must match its retained source authority")
    require(cleanup.index("rocky-control.py validate-continuation") < cleanup.index("id: cleanup_auth")
            and "--allow-expired-for-destroy --allow-control-sha-mismatch-for-destroy" in cleanup,
            "retained identity must be admitted before cleanup OIDC")
    for field in ("trusted_control_sha", "target_sha", "run_id", "run_attempt", "exact_image_self_link", "profile", "created_at", "expires_at"):
        require(f".{field}" in cleanup,
                "retained state/continuation agreement is missing")
    for fragment in ('tofu destroy --auto-approve --input=false',
                     'test -z "$(tofu state list)"', '--exact-action cleanup',
                     '--exact-action verify', 'PROVIDER_RUN_RESOURCE_SET_ABSENT',
                     'create_credentials_file: false', 'export_environment_variables: false'):
        require(fragment in cleanup, "exact cleanup or independent provider absence is missing")
    require("tofu apply" not in text and "rocky-gcp-transition.py" not in text,
            "recovery must not create or resume GCP resources")
    require(text.count("projects/94792370946/locations/global/workloadIdentityPools/secpal/providers/github") == 1
            and text.count("gcp-service-account@secpal-dev.iam.gserviceaccount.com") == 1
            and cleanup.count("persist-credentials: false") == 1
            and cleanup.count("ref: ${{ github.sha }}") == 1,
            "exact cleanup identity and accepted-source checkout must be preserved")
    for name in ("main.tf", "metadata.tf", "variables.tf", "outputs.tf"):
        require(not (root / "infra/ci-cloud/gcp-rocky" / name).exists(),
                "retired GCP resource source is present")
    validate_action_pins(document, relative)


def validate(root: Path) -> None:
    validate_opentofu(root)
    validate_janitor_workflow(root)
    validate_janitor_script(root)
    validate_gcp_iam_role(root)
    validate_rocky_control_plane(root)
    require("gha-creds-*.json" in read(root, ".gitignore"), "generated GCP credential files must be ignored defensively")
    workload_collector = read(root, "scripts/ci-cloud/collect-workload-evidence.py")
    workload_admission = read(root, "scripts/ci-cloud/workload-admission.py")
    evidence_assembler = read(root, "scripts/ci-cloud/assemble-evidence.py")
    evidence_validator = read(root, "scripts/ci-cloud/validate-evidence.py")
    evidence_schema_text = read(root, "schemas/ci-cloud-evidence.schema.json")
    require(
        "CI_UID = 20000" in workload_collector
        and "CI_GID = 20000" in workload_collector
        and 'CHECKOUT = Path("/home/secpal-ci/deployment-target")'
        in workload_collector
        and 'QUADLET_ROOT = Path("/etc/containers/systemd/users/20000")'
        in workload_collector
        and "instance != target_sha[:12]" in workload_collector
        and 'phase not in {"baseline", "normalize", "live", "post-cleanup"}'
        in workload_collector
        and 'choices=["baseline", "normalize", "live", "post-cleanup"]'
        in workload_collector
        and '"systemctl", "--user", "set-environment"'
        in workload_collector
        and 'f"QUADLET_UNIT_DIRS={QUADLET_ROOT}"' in workload_collector
        and '"systemctl", "--user", "show-environment"' in workload_collector
        and '"systemctl", "--user", "unset-environment", *names'
        in workload_collector
        and "TRUSTED_MANAGER_ENVIRONMENT" in workload_collector
        and "TRUSTED_USER_ENVIRONMENT_GENERATOR" in workload_collector
        and "trusted_user_environment_generator_is_admitted" in workload_collector
        and "trusted_user_environment_generator_admission_failure"
        in workload_collector
        and "NORMALIZATION_STAGES" in workload_collector
        and "prepared != expected" in workload_collector
        and workload_collector.count("observed != expected") == 2
        and '"pre-reload-manager-environment-read"' in workload_collector
        and '"pre-reload-manager-environment-admission"' in workload_collector
        and '"FragmentPath"' in workload_collector
        and '"DropInPaths"' in workload_collector
        and "generated_service_unit_activation_is_trusted" in workload_collector
        and '["systemctl", "--user", "daemon-reload"]' in workload_collector
        and 'NORMALIZATION_DIAGNOSTIC_PREFIX = "Trusted Quadlet '
        'normalization diagnostic: "' in workload_collector
        and "NORMALIZATION_STAGES = frozenset(" in workload_collector
        and "NORMALIZATION_FAILURE_REASONS = frozenset(" in workload_collector
        and "failure_reason: str | None" in workload_collector
        and "command_status: int | None" in workload_collector
        and "outcome.document()" in workload_collector
        and "workload_admission_failures" not in workload_collector
        and "def workload_admission_failures(" in workload_admission
        and "ADMISSION_CONTRACT" in workload_collector
        and "NORMALIZATION_SURFACE" in workload_collector
        and "COLLECTION_SURFACE" in workload_collector
        and "shell=True" not in workload_collector
        and "os.system" not in workload_collector
        and "eval(" not in workload_collector,
        "workload collection must remain fixed, rootless, bounded, and independent",
    )
    require(
        'phase not in {"baseline", "normalize", "live", "post-cleanup"}'
        in workload_collector
        and '("Names", "Name", "name")' in workload_collector
        and 'if "Health" not in state:' in workload_collector
        and 'health_value = state["Health"]' in workload_collector
        and 'if "Healthcheck" not in config:' in workload_collector
        and 'configured_healthcheck = config["Healthcheck"]'
        in workload_collector
        and 'if "IDMappings" not in host_config:' in workload_collector
        and 'configured_id_maps(host_config["IDMappings"])'
        in workload_collector
        and '[] if item["EffectiveCaps"] is None else item["EffectiveCaps"]'
        in workload_collector
        and '[] if item["BoundingCaps"] is None else item["BoundingCaps"]'
        in workload_collector
        and 'item["EffectiveCaps"] is not None\n'
        '                and not isinstance(item["EffectiveCaps"], list)'
        in workload_collector
        and 'item["BoundingCaps"] is not None\n'
        '                and not isinstance(item["BoundingCaps"], list)'
        in workload_collector
        and '"rootless": rootless' in workload_collector
        and 'item["Rootless"]' not in workload_collector
        and 'security_options != ["no-new-privileges"]' in workload_admission
        and "WORKLOAD_RESOURCE_INVENTORY" in workload_admission
        and "WORKLOAD_VOLUME_TOPOLOGY" in workload_admission
        and "WORKLOAD_TMPFS_TOPOLOGY" in workload_admission
        and "WORKLOAD_CONTAINER_LIFECYCLE" in workload_admission
        and "container_lifecycle_events" in workload_collector
        and 'item.get("effective_caps") != expected_caps' in workload_admission
        and "PODMAN_HEALTH_TIMER_PROPERTIES" in workload_collector
        and "PODMAN_HEALTH_SERVICE_PROPERTIES" in workload_collector
        and "podman_health_exec_is_trusted" in workload_collector
        and 'service_properties["Environment"] == trusted_path'
        in workload_collector
        and '"podman_health_timers"' in workload_collector
        and 'OPAQUE_PROCESS_EXECUTABLE = "[permission-denied]"'
        in workload_collector
        and "elif reviewed_opaque:" in workload_collector
        and "if role not in READY_ROLES:" in workload_collector
        and 'item.get("cap_add") not in ([], expected_caps)'
        in workload_admission,
        "Podman evidence must use admitted v5 fields and exact inventory/security facts",
    )
    require(
        "TRUSTED_USER_SOCKET_UNITS" in workload_collector
        and "TRUSTED_USER_SERVICE_UNITS" in workload_collector
        and "TRUSTED_USER_UNIT_PACKAGES" in workload_collector
        and "def root_owned_systemd_unit(path: Path) -> bool:"
        in workload_collector
        and "def systemd_unit_owned_by_package(path: Path, package: str) -> bool:"
        in workload_collector
        and "metadata.st_uid == 0" in workload_collector
        and "metadata.st_gid == 0" in workload_collector
        and "stat.S_IMODE(metadata.st_mode) == 0o644" in workload_collector
        and '"systemctl", "--user", "show", trigger,' in workload_collector
        and "service_fragment not in service_fragments" in workload_collector
        and "not root_owned_systemd_unit(service_fragment)" in workload_collector
        and '"dbus.socket": "dbus-common"' in workload_collector
        and '"dbus.service": "dbus-broker"' in workload_collector
        and '["rpm", "-qf", "--qf", "%{NAME}", str(canonical)]'
        in workload_collector
        and "dpkg-query" not in workload_collector
        and 'not systemd_unit_owned_by_package(fragment, package)'
        in workload_collector
        and "not systemd_unit_owned_by_package(\n"
        "                service_fragment, service_package\n"
        "            )" in workload_collector
        and 'service_properties["DropInPaths"] != ""' in workload_collector,
        "every admitted user socket and triggered service must remain root-owned and fixed",
    )
    try:
        evidence_schema = json.loads(evidence_schema_text)
        Draft202012Validator.check_schema(evidence_schema)
    except (json.JSONDecodeError, SchemaError):
        raise ContractError("cloud evidence schema is invalid") from None
    require(
        evidence_schema.get("properties", {})
        .get("schema_version", {})
        .get("const")
        == 5
        and {"workload"}.issubset(
            set(evidence_schema.get("required", []))
        )
        and "guarded_decision(module, workload)" in evidence_assembler
        and "load_workload_admission()" in evidence_assembler
        and "WORKLOAD_ADMISSION_PATH" in evidence_validator
        and "TARGET_WORKLOAD_PREPARE_START" in evidence_assembler
        and "TRUSTED_POST_CLEANUP_COLLECTION" in evidence_assembler,
        "application-workload evidence must remain independently validated and fail closed",
    )
    require(
        "read_normalization_diagnostic(" in evidence_assembler
        and '"normalization_diagnostics": normalization_diagnostics'
        in evidence_assembler
        and "normalization_diagnostics" in evidence_schema["properties"]["test"]["required"]
        and "normalizationDiagnostic" in evidence_schema.get("$defs", {})
        and 'test["normalization_diagnostics"]' in evidence_validator
        and "Trusted Quadlet normalization diagnostics" in evidence_validator,
        "trusted Quadlet normalization diagnostics must reach validated evidence and its summary",
    )


def main(arguments: list[str]) -> int:
    root = Path(arguments[0]).resolve() if arguments else Path.cwd()
    try:
        validate(root)
        purity_path = root / "scripts" / "ci-cloud" / "workload-purity.py"
        spec = importlib.util.spec_from_file_location("ci_cloud_purity", purity_path)
        if spec is None or spec.loader is None:
            raise ContractError("PURITY_SOURCE_INVALID")
        purity = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(purity)
        purity.check_files(purity_path.parent)
    except (ContractError, OSError, UnicodeError) as error:
        print(f"FAIL: cloud CI contract: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"FAIL: cloud CI contract: {error}", file=sys.stderr)
        return 1
    print("Cloud CI static trust-boundary contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
