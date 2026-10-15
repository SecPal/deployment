#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Fail-closed static validation for the cloud conformance trust boundary."""

from __future__ import annotations

import ast
import hashlib
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


def read(root: Path, relative: str) -> str:
    path = root / relative
    require(path.is_file(), f"required cloud CI file is missing: {relative}")
    return path.read_text(encoding="utf-8")


def literal_constant(text: str, name: str) -> object:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        raise ContractError(f"trusted Python source containing {name} is invalid") from None
    values: list[object] = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        ):
            try:
                values.append(ast.literal_eval(node.value))
            except (ValueError, TypeError, SyntaxError):
                raise ContractError(f"{name} must be a literal constant") from None
    if len(values) != 1:
        raise ContractError(f"{name} must have exactly one top-level assignment")
    return values[0]


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


def validate_opentofu(root: Path) -> None:
    # These provider configurations remain necessary for exact-state cleanup.
    for directory, source, version in (
        ("digitalocean", "digitalocean/digitalocean", "2.99.1"),
        ("gcp", "hashicorp/google", "7.40.0"),
    ):
        versions = read(root, f"infra/ci-cloud/{directory}/versions.tf")
        lock = read(root, f"infra/ci-cloud/{directory}/.terraform.lock.hcl")
        require('required_version = "= 1.12.5"' in versions, "OpenTofu version must be exact")
        require(f'source  = "{source}"' in versions, "cleanup provider source changed")
        require(f'version = "= {version}"' in versions, "cleanup provider version must be exact")
        require("~>" not in versions and ">=" not in versions, "mutable provider constraints are forbidden")
        require(f'provider "registry.opentofu.org/{source}"' in lock
                and re.search(r'version\s*=\s*"' + re.escape(version) + r'"', lock),
                "cleanup provider lock must match the pinned provider")
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
    expected_target_sha = "402c22b0a1d69a5a3dba74ffb68cf016caba606b"
    expected_harness_sha256 = (
        "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"
    )
    historical_273_target_sha = "c76742c828fefd71dda2b2d73fda6a0c43969426"
    historical_273_harness_sha256 = (
        "436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac"
    )
    historical_269_target_sha = "b76c24fe59fbe2406d8b84094fc9e6694c57f0c6"
    historical_pre_269_harness_sha256 = (
        "f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c"
    )
    historical_265_target_sha = "539d5faa6549be62060c8e20028caf200e5eca01"
    historical_pre_265_harness_sha256 = (
        "f1ed6f62f769d608b721592b28835daca5ea7c0b0c3575311691628383e88f3c"
    )
    expected_target_line_rules = (
        (456, 462, "qualify-host-identity"),
        (464, 467, "qualify-administrator-execution"),
        (468, 471, "qualify-fixture-reference"),
        (472, 493, "qualify-service-account"),
        (497, 500, "qualify-selinux-host"),
        (502, 515, "qualify-native-architecture"),
        (517, 520, "qualify-cgroup"),
        (521, 537, "qualify-rootless-runtime"),
        (538, 541, "qualify-fixture-presence"),
        (543, 552, "qualify-fixture-setup"),
        (554, 613, "qualify-quadlet-authority"),
        (614, 614, "qualify-quadlet-daemon-reload"),
        (615, 637, "qualify-quadlet-authority"),
        (638, 638, "qualify-quadlet-start"),
        (639, 639, "qualify-quadlet-active-state"),
        (641, 652, "qualify-quadlet-authority"),
        (653, 658, "qualify-workload-primary"),
        (659, 665, "qualify-seccomp"),
        (668, 668, "qualify-selinux-storage-directory-create"),
        (670, 674, "qualify-workload-primary"),
        (675, 678, "qualify-workload-secondary"),
        (680, 686, "qualify-selinux-storage"),
        (690, 694, "qualify-avc-correlation"),
        (698, 704, "qualify-selinux-policy-restoration"),
        (707, 711, "qualify-avc-correlation"),
        (713, 721, "qualify-selinux-policy-restoration"),
        (724, 740, "qualify-avc-correlation"),
        (749, 752, "qualify-runtime-fallback-absence"),
        (754, 754, "qualification-harness"),
        (760, 768, "qualify-avc-correlation"),
    )

    def schema_const_pairs(document: object) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if isinstance(document, dict):
            properties = document.get("properties")
            required = document.get("required")
            if (
                isinstance(properties, dict)
                and isinstance(required, list)
                and all(isinstance(item, str) for item in required)
            ):
                target = properties.get("target_sha")
                harness = properties.get("harness_sha256")
                if (
                    {"target_sha", "harness_sha256"} <= set(required)
                    and isinstance(target, dict)
                    and isinstance(target.get("const"), str)
                    and isinstance(harness, dict)
                    and isinstance(harness.get("const"), str)
                ):
                    pairs.append((target["const"], harness["const"]))
            for value in document.values():
                pairs.extend(schema_const_pairs(value))
        elif isinstance(document, list):
            for value in document:
                pairs.extend(schema_const_pairs(value))
        return pairs

    def schema_const_pair_at(
        document: object, *path: object
    ) -> tuple[str, str] | None:
        node = document
        for component in path:
            if isinstance(component, str) and isinstance(node, dict):
                node = node.get(component)
            elif (
                isinstance(component, int)
                and isinstance(node, list)
                and 0 <= component < len(node)
            ):
                node = node[component]
            else:
                return None
        if not isinstance(node, dict):
            return None
        properties = node.get("properties")
        if not isinstance(properties, dict):
            return None
        target = properties.get("target_sha")
        harness = properties.get("harness_sha256")
        if not isinstance(target, dict) or not isinstance(harness, dict):
            return None
        if not isinstance(target.get("const"), str) or not isinstance(
            harness.get("const"), str
        ):
            return None
        return target["const"], harness["const"]
    relative = ".github/workflows/rocky-cloud-qualification.yml"
    # Historical mutation tests construct a deliberately minimal legacy tree.
    # Repository presence is owned independently by repository-contract.sh.
    if not (root / relative).is_file():
        return
    document, text = load_workflow(root, relative)
    validate_action_pins(document, relative)
    trigger = document.get("on")
    require(isinstance(trigger, dict), "Rocky workflow trigger must be a mapping")
    dispatch = trigger.get("workflow_dispatch")
    require(isinstance(dispatch, dict), "Rocky workflow must be manually dispatched")
    inputs = dispatch.get("inputs")
    require(isinstance(inputs, dict), "Rocky workflow inputs must be closed")
    require(
        set(inputs)
        == {
            "operation",
            "qualification",
            "target_sha",
            "provider_profile",
            "continuation_run_id",
            "continuation_run_attempt",
        },
        "Rocky workflow input set changed",
    )
    qualification = inputs.get("qualification")
    require(
        isinstance(qualification, dict)
        and qualification.get("type") == "choice"
        and qualification.get("default") == "rocky-host"
        and qualification.get("options") == ["rocky-host", "native-postgresql-18", "product-backend-policy"],
        "Rocky/PostgreSQL qualification selector must remain closed",
    )
    require(
        inputs["target_sha"].get("required") == "false"
        and '[[ -z "$RAW_TARGET_SHA" ]]' in text
        and 'RAW_TARGET_SHA="$expected_target_sha"' in text,
        "PostgreSQL source identity must be trusted-derived, not dispatch-selected",
    )
    operation = inputs.get("operation")
    profile = inputs.get("provider_profile")
    require(
        isinstance(operation, dict)
        and operation.get("options")
        == ["discover", "provision-and-prepare", "qualify", "destroy"],
        "Rocky lifecycle operations must remain closed",
    )
    require(
        isinstance(profile, dict)
        and profile.get("options")
        == ["gcp-rocky-10-2-arm64", "gcp-rocky-10-2-x86-64"],
        "Rocky provider profile must remain closed",
    )
    arm64_profile = json.loads(
        read(root, "config/ci-cloud/gcp-rocky-10-2-arm64.json")
    )
    x86_64_profile = json.loads(
        read(root, "config/ci-cloud/gcp-rocky-10-2-x86-64.json")
    )
    require(
        arm64_profile["profile"] == "gcp-rocky-10-2-arm64"
        and arm64_profile["architecture"] == "aarch64"
        and arm64_profile["machine_type"] == "c4a-standard-4"
        and arm64_profile["image"]["discovery_family"]
        == "rocky-linux-10-arm64"
        and x86_64_profile["profile"] == "gcp-rocky-10-2-x86-64"
        and x86_64_profile["architecture"] == "x86_64"
        and x86_64_profile["cpu_baseline"] == "x86-64-v3"
        and x86_64_profile["machine_type"] == "c3-standard-4"
        and x86_64_profile["image"]["discovery_family"] == "rocky-linux-10"
        and arm64_profile["fixture"]["input"]
        == x86_64_profile["fixture"]["input"]
        and arm64_profile["fixture"]["arm64_child"]
        != x86_64_profile["fixture"]["amd64_child"],
        "Rocky reviewed profiles have incompatible provider or architecture facts",
    )
    require(
        "config/ci-cloud/${" not in text
        and "config/ci-cloud/${{ inputs.provider_profile }}" not in text
        and 'gcp-rocky-10-2-x86-64) machine_type=c3-standard-4'
        in text,
        "Rocky profile selection must remain closed and path-independent",
    )
    require(
        "github.ref == 'refs/heads/main'" in text
        and "^[0-9a-fA-F]{40}$" in text
        and f"readonly expected_target_sha={expected_target_sha}" in text
        and f"readonly expected_harness_sha256={expected_harness_sha256}" in text
        and text.count('[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ]]')
        == 2
        and text.count(
            "readonly historical_cleanup_target_sha="
            "293977ae93408a7bb812619de58649ab8a92d438"
        )
        == 1
        and text.count(
            '[[ "${RAW_TARGET_SHA,,}" == "$expected_target_sha" ||\n'
            '                "${RAW_TARGET_SHA,,}" == '
            '"$historical_cleanup_target_sha" ]]'
        )
        == 1
        and (
            '[[ "$(sha256sum scripts/qualify-production-host.sh | awk '
            "'{print $1}')\" == \\\n"
            '            "$expected_harness_sha256" ]]'
        )
        in text,
        "Rocky control must authenticate one immutable target/harness pair",
    )
    jobs = document.get("jobs")
    require(isinstance(jobs, dict), "Rocky workflow jobs must be a mapping")
    require(
        set(jobs)
        == {
            "validate",
            "discover",
            "confirm_postgresql",
            "provision",
            "resume_control",
            "qualify_target",
            "cleanup",
        },
        "Rocky lifecycle job set changed",
    )
    target_job = jobs["qualify_target"]
    require(isinstance(target_job, dict), "target qualification job is malformed")
    target_text = json.dumps(target_job, sort_keys=True)
    preparation = read(root, "scripts/ci-cloud/prepare-rocky-host.sh")
    target_runner = read(root, "scripts/ci-cloud/run-rocky-target-qualification.sh")
    qualification_harness = read(root, "scripts/qualify-production-host.sh")
    quadlet_authority_contract = read(
        root, "scripts/quadlet_authority_contract.py"
    )
    selinux_isolation_contract = read(
        root, "scripts/selinux_isolation_contract.py"
    )
    qualification_schema = json.loads(
        read(root, "schemas/rocky-cloud-qualification-evidence.schema.json")
    )
    target_failure_schema = json.loads(
        read(root, "schemas/rocky-cloud-target-qualification-failure.schema.json")
    )
    target_failure_classifier = read(
        root, "scripts/ci-cloud/classify-rocky-target-qualification-failure.py"
    )
    target_replay_verifier = read(
        root, "scripts/ci-cloud/verify-rocky-target-qualification-replay.py"
    )
    rocky_control = read(root, "scripts/ci-cloud/rocky-control.py")
    target_failure_trace = read(
        root, "scripts/ci-cloud/rocky-target-qualification-trace.sh"
    )
    reload_adjacency_observer = read(
        root, "scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py"
    )
    reload_runuser = read(root, "scripts/ci-cloud/rocky-reload-runuser.py")
    reload_systemctl = read(root, "scripts/ci-cloud/rocky-reload-systemctl.py")
    start_runuser = read(root, "scripts/ci-cloud/rocky-start-runuser.py")
    start_env = read(root, "scripts/ci-cloud/rocky-start-env.py")
    start_systemctl = read(root, "scripts/ci-cloud/rocky-start-systemctl.py")
    active_runuser = read(root, "scripts/ci-cloud/rocky-active-runuser.py")
    active_env = read(root, "scripts/ci-cloud/rocky-active-env.py")
    active_systemctl = read(root, "scripts/ci-cloud/rocky-active-systemctl.py")
    primary_runuser = read(root, "scripts/ci-cloud/rocky-primary-runuser.py")
    primary_runtime = read(root, "scripts/ci-cloud/rocky-primary-runtime.py")
    bootstrap = read(root, "scripts/ci-cloud/bootstrap-rocky-host.tftpl")
    readiness_publisher = read(
        root, "scripts/ci-cloud/publish-rocky-qualification-readiness.py"
    )
    direct_user_systemd = read(root, "scripts/ci-cloud/runtime_user_systemd.py")
    readiness_waiter = read(
        root, "scripts/ci-cloud/wait-rocky-qualification-readiness.py"
    )
    main = read(root, "infra/ci-cloud/gcp-rocky/main.tf")
    main += read(root, "infra/ci-cloud/gcp-rocky/metadata.tf")
    source_names = set(re.findall(
        r"^\s+(\w+)\s*=\s*(?:file\(|var\.(?:postgresql_candidate_json|product_backend_policy_json)\s*$)",
        read(root, "infra/ci-cloud/gcp-rocky/metadata.tf"), re.MULTILINE,
    ))
    installer_names = {
        quoted or bare for quoted, bare in re.findall(
            r"^\s*decode_script (?:'([a-z0-9_]+)'|([a-z0-9_]+)) ",
            bootstrap, re.MULTILINE,
        )
    }
    require(source_names == installer_names,
            "Rocky transport must preserve the exact fixed installed component inventory")
    require(
        "metadata = local.rocky_metadata" in main
        and main.count("terraform_data.rocky_metadata_admission]") == 2
        and "rocky_metadata_values_admitted" in main
        and "rocky_metadata_aggregate_admitted" in main
        and "rocky_bootstrap_expansion_admitted" in main
        and "ROCKY_BOOTSTRAP_TRANSPORT_INTEGRITY_FAILED" in bootstrap
        and "decoder.unconsumed_tail or decoder.unused_data" in bootstrap
        and "hashlib.sha256(payload).hexdigest()" in bootstrap
        and "object_pairs_hook=unique_object" in bootstrap
        and "sorted(sources) != names" in bootstrap
        and text.count("python3 scripts/ci-cloud/admit-rocky-metadata.py") == 1
        and text.index("python3 scripts/ci-cloud/admit-rocky-metadata.py")
        < text.index("      - name: Authenticate trusted provisioning through OIDC")
        < text.index("          tofu apply --auto-approve --input=false"),
        "Rocky metadata must admit the actual bounded transport before provider credentials and resources",
    )
    target_line_rules = literal_constant(target_failure_classifier, "LINE_RULES")
    target_failure_schema_pair_sequence = [
        schema_const_pair_at(
            target_failure_schema, "allOf", 0, "then", "oneOf", 1
        ),
        schema_const_pair_at(
            target_failure_schema, "allOf", 0, "then", "oneOf", 0
        ),
        *[
            schema_const_pair_at(
                target_failure_schema, "allOf", 3, "then", "anyOf", index
            )
            for index in range(4)
        ],
        *[
            schema_const_pair_at(
                target_failure_schema,
                "allOf",
                condition,
                "if",
                "anyOf",
                index,
            )
            for condition, length in ((18, 7), (19, 5), (20, 5))
            for index in range(length)
        ],
    ]
    expected_target_failure_schema_pair_sequence = [
        (expected_target_sha, expected_harness_sha256),
        (historical_273_target_sha, historical_273_harness_sha256),
        (expected_target_sha, expected_harness_sha256),
        (historical_273_target_sha, historical_273_harness_sha256),
        (historical_269_target_sha, historical_pre_269_harness_sha256),
        (historical_265_target_sha, historical_pre_265_harness_sha256),
        ("83d0c3720d342d0222e8dee9819e28d0c6739f84", "ba4daa656cc462264c00f830985ad3c346e7ca4db8df9a50e8ee0c7a7d499946"),
        ("293977ae93408a7bb812619de58649ab8a92d438", "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"),
        ("b8f5a505d318d06a64a5975cfaba9f1e5ba0041f", "918c992aad9c937fa2639cd345adc849784344574c44da3d7e3dfeb01bd770fa"),
        (expected_target_sha, expected_harness_sha256),
        (historical_273_target_sha, historical_273_harness_sha256),
        (historical_269_target_sha, historical_pre_269_harness_sha256),
        (historical_265_target_sha, historical_pre_265_harness_sha256),
        ("293977ae93408a7bb812619de58649ab8a92d438", "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"),
        (expected_target_sha, expected_harness_sha256),
        (historical_273_target_sha, historical_273_harness_sha256),
        (historical_269_target_sha, historical_pre_269_harness_sha256),
        (historical_265_target_sha, historical_pre_265_harness_sha256),
        ("293977ae93408a7bb812619de58649ab8a92d438", "8459724a91bee7643d6f0e3d64984161a3441848e9d836ce1210ccef689fb4db"),
        (expected_target_sha, expected_harness_sha256),
        (historical_273_target_sha, historical_273_harness_sha256),
        (historical_269_target_sha, historical_pre_269_harness_sha256),
        (historical_265_target_sha, historical_pre_265_harness_sha256),
    ]
    storage_setup_line_rules = [
        rule
        for rule in target_line_rules
        if rule[2] == "qualify-selinux-storage-directory-create"
    ]
    validate_job_text = json.dumps(jobs["validate"], sort_keys=True)
    require(
        "scripts/validate-rocky-evidence-architecture.py" in validate_job_text
        and "scripts/validate-ci-cloud.py" in validate_job_text
        and "jsonschema==4.25.1 PyYAML==6.0.2" in validate_job_text,
        "Rocky schema and diagnostic agreement must fail before provider authority",
    )
    require(
        hashlib.sha256((root / "scripts/qualify-production-host.sh").read_bytes()).hexdigest()
        == expected_harness_sha256
        and f'EXPECTED_TARGET_SHA = "{expected_target_sha}"'
        in target_failure_classifier
        and f'EXPECTED_HARNESS_SHA256 = "{expected_harness_sha256}"'
        in target_failure_classifier
        and f'HISTORICAL_273_TARGET_SHA = "{historical_273_target_sha}"'
        in target_failure_classifier
        and f'HISTORICAL_273_HARNESS_SHA256 = "{historical_273_harness_sha256}"'
        in target_failure_classifier
        and f'HISTORICAL_PRE_269_TARGET_SHA = "{historical_269_target_sha}"'
        in target_failure_classifier
        and f'HISTORICAL_PRE_269_HARNESS_SHA256 = "{historical_pre_269_harness_sha256}"'
        in target_failure_classifier
        and f'HISTORICAL_PRE_265_TARGET_SHA = "{historical_265_target_sha}"'
        in target_failure_classifier
        and f'HISTORICAL_PRE_265_HARNESS_SHA256 = "{historical_pre_265_harness_sha256}"'
        in target_failure_classifier
        and f"readonly expected_target_sha={expected_target_sha}" in target_runner
        and f"readonly expected_harness_sha256={expected_harness_sha256}"
        in target_runner
        and '[[ "$target_sha" != "$expected_target_sha" ||' in target_runner
        and '"$qualification_harness_sha256" != "$expected_harness_sha256" ]]'
        in target_runner
        and target_runner.index('[[ "$target_sha" != "$expected_target_sha" ||')
        < target_runner.index("secpal-collect-rocky-preparation")
        < target_runner.index("getent ahostsv4 github.com")
        < target_runner.index('bash "$work_root/scripts/qualify-production-host.sh"')
        and schema_const_pairs(target_failure_schema).count(
            (expected_target_sha, expected_harness_sha256)
        )
        == 5
        and schema_const_pairs(target_failure_schema).count(
            (historical_273_target_sha, historical_273_harness_sha256)
        )
        == 5
        and schema_const_pairs(target_failure_schema).count(
            (historical_269_target_sha, historical_pre_269_harness_sha256)
        )
        == 4
        and schema_const_pairs(target_failure_schema).count(
            (historical_265_target_sha, historical_pre_265_harness_sha256)
        )
        == 4
        and target_failure_schema_pair_sequence
        == expected_target_failure_schema_pair_sequence
        and qualification_schema["properties"]["target_sha"]
        == {"enum": [historical_273_target_sha, expected_target_sha]}
        and qualification_schema["properties"]["native_observation"]["properties"][
            "target_sha"
        ]
        == {"enum": [historical_273_target_sha, expected_target_sha]}
        and qualification_schema["allOf"][0]["then"]["properties"]["target_sha"]
        == {"const": historical_273_target_sha}
        and qualification_schema["allOf"][1]["then"]["properties"]["target_sha"]
        == {"const": expected_target_sha},
        "active target, harness, classifier, and schema bindings disagree",
    )
    for forbidden in (
        "id-token",
        "google-github-actions/auth",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "GCP_SERVICE_ACCOUNT",
        "credentials_file",
        "ci-cloud-gcp",
    ):
        require(
            forbidden not in target_text,
            f"target qualification job retains cloud-control authority: {forbidden}",
        )
    require(
        "run-rocky-target-qualification" in target_text
        and "run-rocky-target-qualification" not in json.dumps(jobs["resume_control"]),
        "only the uncredentialed target job may request target-owned execution",
    )
    metadata_policy = required_block(
        preparation,
        "block_metadata_credentials() {\n",
        "\n}\n\nconfigure_subids() {",
        "Rocky metadata credential policy",
    )
    udp_dns = "ip daddr 169.254.169.254 udp dport 53 accept"
    tcp_dns = "ip daddr 169.254.169.254 tcp dport 53 accept"
    metadata_reject = "ip daddr 169.254.169.254 reject"
    applied_metadata_policy = [
        line.strip()
        for line in metadata_policy.splitlines()
        if line.strip().startswith("ip daddr 169.254.169.254")
    ][-3:]
    require(
        metadata_policy.count(udp_dns) == 2
        and metadata_policy.count(tcp_dns) == 2
        and metadata_policy.count(metadata_reject) == 2
        and applied_metadata_policy == [udp_dns, tcp_dns, metadata_reject]
        and "8.8.8.8" not in metadata_policy
        and "1.1.1.1" not in metadata_policy,
        "GCE DNS must remain usable while all non-DNS metadata channels fail closed",
    )
    require(
        "getent ahostsv4 github.com" in target_runner
        and "resolve-target-source" in target_runner
        and "fetch-exact-target" in target_runner
        and "checkout-exact-target" in target_runner
        and "verify-target-sha" in target_runner
        and "exit 81" in target_runner
        and "exit 82" in target_runner
        and "exit 83" in target_runner
        and "exit 84" in target_runner
        and "exit 86" in target_runner
        and "https://github.com/SecPal/deployment.git" in target_runner
        and "validate-target-source-failure" in target_runner,
        "target source acquisition must be exact and emit only closed guest-owned failures",
    )
    require(
        '"$(sha256sum "$work_root/scripts/qualify-production-host.sh" | awk \'{print $1}\')" != "$qualification_harness_sha256"'
        in target_runner
        and 'bash "$work_root/scripts/qualify-production-host.sh"' in target_runner
        and '-f "$work_root/scripts/selinux_isolation_contract.py"' in target_runner
        and '! -L "$work_root/scripts/selinux_isolation_contract.py"' in target_runner
        and "readonly trusted_selinux_isolation_contract=/opt/secpal-control/scripts/selinux_isolation_contract.py"
        in target_runner
        and '-f "$trusted_selinux_isolation_contract"' in target_runner
        and '! -L "$trusted_selinux_isolation_contract"' in target_runner
        and '"$(stat -c \'%u:%g:%a\' -- "$trusted_selinux_isolation_contract")" == 0:0:700'
        in target_runner
        and '/usr/bin/cmp --silent -- "$work_root/scripts/selinux_isolation_contract.py" "$trusted_selinux_isolation_contract"'
        in target_runner
        and '-f "$work_root/scripts/quadlet_authority_contract.py"'
        in target_runner
        and '! -L "$work_root/scripts/quadlet_authority_contract.py"'
        in target_runner
        and "readonly trusted_quadlet_authority_contract=/opt/secpal-control/scripts/quadlet_authority_contract.py"
        in target_runner
        and '-f "$trusted_quadlet_authority_contract"' in target_runner
        and '! -L "$trusted_quadlet_authority_contract"' in target_runner
        and '"$(stat -c \'%u:%g:%a\' -- "$trusted_quadlet_authority_contract")" == 0:0:700'
        in target_runner
        and '/usr/bin/cmp --silent -- "$work_root/scripts/quadlet_authority_contract.py" "$trusted_quadlet_authority_contract"'
        in target_runner
        and target_runner.index(
            '/usr/bin/cmp --silent -- "$work_root/scripts/selinux_isolation_contract.py" "$trusted_selinux_isolation_contract"'
        )
        < target_runner.index('bash "$work_root/scripts/qualify-production-host.sh"')
        and target_runner.index(
            '/usr/bin/cmp --silent -- "$work_root/scripts/quadlet_authority_contract.py" "$trusted_quadlet_authority_contract"'
        )
        < target_runner.index('bash "$work_root/scripts/qualify-production-host.sh"')
        and "timeout --signal=TERM --kill-after=180s 45m" in target_runner
        and "qualification_harness" not in bootstrap + main,
        "trusted control must bind the exact target qualification workload bytes",
    )
    require(
        "trap cleanup EXIT" in qualification_harness
        and "trap 'interrupted 129' HUP" in qualification_harness
        and "trap 'interrupted 130' INT" in qualification_harness
        and "trap 'interrupted 143' TERM" in qualification_harness
        and "if ((interrupted_status != 0)); then" in qualification_harness
        and 'exit_status="$interrupted_status"' in qualification_harness
        and qualification_harness.count("/usr/bin/timeout --signal=KILL") >= 8
        and qualification_harness.count(
            "/usr/bin/timeout --signal=KILL 30s semodule -B"
        ) == 2
        and qualification_harness.count(
            'rm -f -- "$qualification_success_marker"'
        ) == 2
        and qualification_harness.index(
            'install -o 0 -g 0 -m 0600 /dev/null "$qualification_success_marker"'
        )
        < qualification_harness.index(
            "printf 'PASS: Rocky Linux %s target workload contract"
        ),
        "qualification interruption must preserve bounded cleanup and non-success",
    )
    require(
        '[[ "$service_uid" =~ ^[1-9][0-9]*$ && "$service_gid" =~ ^[1-9][0-9]*$ ]]'
        in qualification_harness
        and 'podman_rootless="$(rootless_podman info --format \'{{.Host.Security.Rootless}}\')"'
        in qualification_harness
        and 'runtime_status="$(run_as_service_account cat /proc/self/status)"'
        in qualification_harness
        and qualification_harness.count("runtime_identity_admitted \\\n") == 2,
        "qualification must bind a non-root service identity to effective rootless Podman and Quadlet execution",
    )
    require(
        "administrator_path_admitted() {" in qualification_harness
        and '[[ -e "$component" && ! -L "$component" ]]'
        in qualification_harness
        and "stat -c '%u:%g:%a' -- \"$component\"" in qualification_harness
        and '[[ "$uid" == "$administrator_uid" && "$gid" == "$administrator_gid" ]]'
        in qualification_harness
        and "(((8#$mode & 8#022) == 0))" in qualification_harness
        and "service_account_cannot_write_path() {" in qualification_harness
        and qualification_harness.count(
            'service_account_cannot_write_path "$quadlet_'
        )
        == 4
        and 'service_account_cannot_write_path "$unit_path" /'
        in qualification_harness
        and qualification_harness.index(
            'administrator_path_admitted "$unit_path" / 0 0 file 644'
        )
        < qualification_harness.index(
            "\nuser_systemctl daemon-reload\n"
        ),
        "qualification must admit immutable administrator ownership across the exact Quadlet ancestry before reload",
    )
    require(
        '[[ "$runtime_uid" =~ ^[1-9][0-9]*$ && "$runtime_gid" =~ ^[1-9][0-9]*$ ]]'
        in preparation
        and preparation.index(
            '[[ "$runtime_uid" =~ ^[1-9][0-9]*$ && "$runtime_gid" =~ ^[1-9][0-9]*$ ]]'
        )
        < preparation.index('usermod --shell /usr/sbin/nologin "$runtime_account"')
        and 'user_manager_dropin="/etc/systemd/system/user@${runtime_uid}.service.d"'
        in preparation
        and "Environment=QUADLET_UNIT_DIRS=%s" in preparation
        and 'systemctl daemon-reload\n  systemctl start "user@$runtime_uid.service"'
        in preparation
        and 'administrator_path_admitted "$quadlet_search_policy" / 0 0 file 644'
        in qualification_harness
        and 'service_account_cannot_write_path "$quadlet_search_policy" /'
        in qualification_harness
        and 'user_systemctl show-environment |' in qualification_harness
        and '[[ "$effective_quadlet_dirs" != "$quadlet_root" ]]'
        in qualification_harness,
        "administrator preparation and effective generator discovery must agree on the one immutable UID-scoped Quadlet path",
    )
    require(
        "effective_quadlet_service_admitted() {" in qualification_harness
        and 'readonly QUADLET_AUTHORITY_INVARIANT_OWNER="quadlet_authority_contract.admit_quadlet_authority"'
        in qualification_harness
        and 'python3 "$QUADLET_AUTHORITY_CONTRACT" "$properties_path"'
        in qualification_harness
        and '"\\"invariant_owner\\":\\"${QUADLET_AUTHORITY_INVARIANT_OWNER}\\""'
        in qualification_harness
        and '--property=FragmentPath --property=SourcePath' in qualification_harness
        and '--property=DropInPaths --property=ExecStart' in qualification_harness
        and 'INVARIANT_OWNER = "quadlet_authority_contract.admit_quadlet_authority"'
        in quadlet_authority_contract
        and 'r"^/run/user/(?P<uid>[1-9][0-9]*)/systemd/generator/"'
        in quadlet_authority_contract
        and 'r"^/etc/containers/systemd/users/(?P<uid>[1-9][0-9]*)/"'
        in quadlet_authority_contract
        and 'properties["DropInPaths"]' in quadlet_authority_contract
        and 'properties["ExecStart"] != expected_exec_start(unit_name)'
        in quadlet_authority_contract
        and "runtime_uid > 4_294_967_294" in quadlet_authority_contract
        and "return 125" in quadlet_authority_contract
        and "((status == 1)) && return 1" in qualification_harness
        and "return 125" in qualification_harness
        and "ERROR: unable to evaluate effective Quadlet service authority"
        in qualification_harness
        and '"qualify-quadlet-authority", "command-failed"'
        in target_failure_classifier
        and quadlet_authority_contract.count('"executable": "/usr/bin/podman"')
        == 2
        and '"--network",\n        "none",' in quadlet_authority_contract
        and quadlet_authority_contract.count('"ignore_errors": False') == 2
        and quadlet_authority_contract.count('"status": "0/0"') == 2
        and qualification_schema["$defs"]["quadlet_authority"]["properties"][
            "invariant_owner"
        ]["const"]
        == "quadlet_authority_contract.admit_quadlet_authority"
        and 'QUADLET_AUTHORITY_INVARIANT_OWNER = (' in rocky_control
        and '"quadlet_authority_contract.admit_quadlet_authority"'
        in rocky_control
        and "load_quadlet_authority_contract()" in rocky_control
        and "target and trusted Quadlet authority normalization disagree"
        in rocky_control
        and "quadlet_authority_contract" in main
        and "decode_script 'quadlet_authority_contract' /opt/secpal-control/scripts/quadlet_authority_contract.py"
        in bootstrap
        and qualification_harness.index("\nuser_systemctl daemon-reload\n")
        < qualification_harness.index(
            "\nif effective_quadlet_service_admitted \\\n"
        )
        < qualification_harness.index(
            '\nuser_systemctl start "${unit_name}.service"\n'
        ),
        "the Quadlet authority owner and every enforcement point must agree before activation",
    )
    require(
        "least_authority_process_admitted() {" in qualification_harness
        and 'identities="$(effective_process_ids "$status_path")"'
        in qualification_harness
        and '[[ "$value" == 1 ]]' in qualification_harness
        and "for field in CapInh CapPrm CapEff CapBnd CapAmb; do"
        in qualification_harness
        and '[[ "$value" == 0000000000000000 ]]' in qualification_harness
        and '[[ "$value" == 2 ]]' in qualification_harness
        and 'rootless_podman exec "$unit_name" awk' in qualification_harness
        and 'least_authority_process_admitted \\\n'
        '    "$workload_status" "$WORKLOAD_UID" "$WORKLOAD_GID"'
        in qualification_harness,
        "qualification must observe and admit the running workload's complete least-authority process state",
    )
    require(
        "ulimit -f" not in target_runner
        and 'trace_fifo="$work_root/target-qualification.trace.fifo"'
        in target_runner
        and "capture_bounded() {" in target_runner
        and '/usr/bin/head -c "$maximum"' in target_runner
        and "/usr/bin/cat >/dev/null" in target_runner
        and 'capture_bounded 4097 "$qualification_trace" <"$trace_fifo"'
        in target_runner
        and '3>"$trace_fifo" 2>&1 | capture_bounded 65537 "$stdout"'
        in target_runner
        and 'pipeline_statuses=("${PIPESTATUS[@]}")' in target_runner
        and 'wait "$trace_capture_pid"' in target_runner
        and 'wait "$observer_pid" >/dev/null 2>&1\n  observer_pid=""'
        in target_runner
        and '"$stdout_capture_status" -ne 0'
        in target_runner
        and '"$trace_capture_status" -ne 0'
        in target_runner,
        "target output and trace must be bounded without limiting target filesystem writes",
    )
    require(
        'audit_baseline="$(date -u \'+%m/%d/%y %H:%M:%S\')"' in target_runner
        and 'audit_checkpoint = re.fullmatch(' in target_runner
        and 'r"([0-9]{2}/[0-9]{2}/[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})"'
        in target_runner
        and "audit_date, audit_time = audit_checkpoint.groups()" in target_runner
        and 'datetime.strptime(audit_baseline, "%m/%d/%y %H:%M:%S")'
        in target_runner
        and '"/usr/sbin/ausearch", "--input-logs", "-m", "AVC", "-ts",'
        in target_runner
        and 'audit_date, audit_time, "-i",' in target_runner
        and "def run_bounded(" in target_runner
        and "def acquire_audit_events(" in target_runner
        and 'stderr in {b"", b"<no matches>\\n"}' in target_runner
        and 'and not stdout\n                and stderr in {b"", b"<no matches>\\n"}'
        in target_runner
        and "for attempt in range(12):" in target_runner
        and "time.sleep(0.5)" in target_runner
        and "selinux_isolation_contract.admit_selinux_isolation(" in target_runner
        and "except selinux_isolation_contract.NoMatchingAvc:" in target_runner
        and "except selinux_isolation_contract.IsolationError:" in target_runner
        and 'SECPAL_AVC_CORRELATION_DIAGNOSTIC_FD=6' in target_runner
        and '--avc-correlation-diagnostic "$avc_correlation_diagnostic"'
        in target_runner
        and "diagnose_avc_correlation_bytes(" in qualification_harness
        and "capture_avc_correlation_diagnostic(" in qualification_harness
        and "publish_avc_correlation_diagnostic" in qualification_harness
        and "reject_avc_observation() {" in qualification_harness
        and 'reject_avc_observation "$denial_status"'
        in qualification_harness
        and "validate_avc_correlation_diagnostic" in rocky_control
        and rocky_control.count(
            "json.loads(payload, object_pairs_hook=reject_duplicate_keys)"
        )
        == 2
        and "build_avc_correlation_diagnostic(" in target_failure_classifier
        and "contract.validate_avc_correlation_diagnostic(projection)"
        in target_failure_classifier
        and 'projection.get("correlation_outcome") == "admitted"'
        in target_failure_classifier
        and target_failure_schema["properties"]["schema_version"]["enum"]
        == [1, 2, 3, 4]
        and "avc_correlation_diagnostic"
        in target_failure_schema["properties"]
        and "process_a=facts[\"process_a\"]" in target_runner
        and "process_b=facts[\"process_b\"]" in target_runner
        and "storage_a=facts[\"storage_a\"]" in target_runner
        and 'selinux_isolation["denial"]["pid"] != denial_pid'
        in target_runner
        and 'selinux_isolation["denial"]["syscall_pid"] != denial_pid'
        in target_runner
        and "selinux_isolation_contract.canonical_bytes(selinux_isolation)"
        in target_runner
        and 'isolation_digest != facts["selinux_isolation_sha256"]'
        in target_runner
        and 'stdout_limit=65536' in target_runner
        and 'stderr_limit=4096' in target_runner
        and 'timeout=5' in target_runner
        and "re.DOTALL" not in target_runner,
        "AVC observation must reach the canonical SELinux isolation owner",
    )
    isolation_schema = qualification_schema["$defs"]["selinux_isolation"]
    context_schema = qualification_schema["$defs"]["normalized_context"]
    normalize_unique_avc_source = selinux_isolation_contract.split(
        "def normalize_unique_enforcing_avc(", 1
    )[1].split("\ndef admit_selinux_isolation(", 1)[0]
    require(
        'RESPONSIBILITY = "normalization,admission"'
        in selinux_isolation_contract
        and 'INVARIANT_OWNER = "selinux_isolation_contract.admit_selinux_isolation"'
        in selinux_isolation_contract
        and "MCS_CATEGORY_MIN = 0" in selinux_isolation_contract
        and "MCS_CATEGORY_MAX = 1023" in selinux_isolation_contract
        and "len(raw_categories) not in {1, 2}" in selinux_isolation_contract
        and "len(set(categories)) != len(categories)" in selinux_isolation_contract
        and "events.setdefault(" in normalize_unique_avc_source
        and "_event_id(line)" in normalize_unique_avc_source
        and "len(candidates) != 1" in normalize_unique_avc_source
        and '"permissive": "0"' in selinux_isolation_contract
        and 'def _syscall_matches(line: str, pid: int)' in selinux_isolation_contract
        and '_field(line, "pid") == str(pid)' in selinux_isolation_contract
        and 'EXPECTED_COMMAND = "cat"' in selinux_isolation_contract
        and '_field(line, "comm") == EXPECTED_COMMAND' in selinux_isolation_contract
        and '"SYSCALL": []' in normalize_unique_avc_source
        and isolation_schema["properties"]["invariant_owner"]["const"]
        == "selinux_isolation_contract.admit_selinux_isolation"
        and context_schema["properties"]["mcs_categories"]["items"]["maximum"]
        == 1023,
        "canonical SELinux isolation owner and schema projection disagree",
    )
    require(
        'runtime_home == Path("/home/secpal-runtime")' in target_runner
        and "def admitted_runtime_home()" in target_runner
        and "except (KeyError, OSError):" in target_runner
        and "runtime_identity = admitted_runtime_home()" in target_runner
        and "home_metadata.st_uid == runtime_account.pw_uid"
        in target_runner
        and "home_metadata.st_gid == runtime_account.pw_gid"
        in target_runner
        and "parent_metadata.st_uid == 0" in target_runner
        and "not parent_metadata.st_mode & 0o022" in target_runner
        and "parent_metadata.st_mode & stat.S_IXOTH" in target_runner
        and 'cwd=str(runtime_home) if name == "podman" else None'
        in target_runner,
        "rootless cleanup observation must use the validated runtime home cwd",
    )
    require(
        '"/usr/sbin/runuser", "--user", "secpal-runtime"' in target_runner
        and '"/usr/bin/podman", "ps", "-a"' in target_runner
        and '"/usr/bin/find", "/var/tmp"' in target_runner
        and '"/usr/bin/systemctl", "list-units"' in target_runner
        and "cleanup_results = [\n    run_bounded(" in target_runner
        and "timeout=10" in target_runner,
        "target cleanup observation must remain absolute, bounded, and timed",
    )
    require(
        text.index("Wait for authenticated current-boot guest readiness")
        < text.index("Execute exact target SHA once on the ready identity-free guest")
        < text.index("Retrieve and validate bounded target-source failure")
        and "source_failure_expected" in target_text
        and "head -c 1025" in target_text
        and "stat -c %s" in target_text
        and "target-source-failure.json" in target_text
        and "validate-target-source-failure" in target_text,
        "target source diagnostics must remain after readiness and before evidence admission",
    )
    readiness_facts = {
        "runtime_user_manager_active",
        "runtime_user_bus_available",
        "runtime_user_control_reachable",
    }
    require(
        literal_constant(readiness_publisher, "WAIT_SECONDS") == 60
        and literal_constant(readiness_publisher, "PROBE_INTERVAL_SECONDS") == 5
        and literal_constant(readiness_publisher, "MAX_PROBES") == 13
        and "timeout=min(COMMAND_TIMEOUT_SECONDS, remaining)" in readiness_publisher
        and "sleep(min(interval, remaining))" in readiness_publisher
        and '"systemctl", "is-active", "--quiet", f"user@{runtime_uid}.service"'
        in readiness_publisher
        and 'stat.S_ISSOCK(os.stat(f"/run/user/{runtime_uid}/bus").st_mode)'
        in readiness_publisher
        and "direct_user_show_environment" in readiness_publisher
        and 'RUNTIME_ACCOUNT = "secpal-runtime"' in readiness_publisher
        and "RUNTIME_ACCOUNT, runtime_uid, runtime.pw_dir"
        in readiness_publisher
        and "--machine=" not in readiness_publisher
        and '"runuser"' in direct_user_systemd
        and '"--user"' in direct_user_systemd
        and '"CONTAINER_HOST"' in direct_user_systemd
        and '"CONTAINER_CONNECTION"' in direct_user_systemd
        and 'f"HOME={runtime_home}"' in direct_user_systemd
        and 'f"XDG_RUNTIME_DIR={runtime_directory}"' in direct_user_systemd
        and 'f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_directory}/bus"'
        in direct_user_systemd
        and '"show-environment"' in direct_user_systemd
        and all(readiness_publisher.count(f'"{fact}"') == 1 for fact in readiness_facts)
        and '"runtime_user_manager_active": result.observation.manager_active'
        in readiness_publisher
        and '"runtime_user_bus_available": result.observation.bus_available'
        in readiness_publisher
        and '"runtime_user_control_reachable": result.observation.control_reachable'
        in readiness_publisher
        and "loginctl" not in readiness_publisher
        and "runtime.systemd_user" not in readiness_publisher
        and "daemon-reload" not in readiness_publisher
        and all(
            operation not in readiness_publisher
            for operation in ('"start"', '"restart"', '"stop"', '"reset-failed"')
        )
        and "time.sleep(WAIT_SECONDS)" not in readiness_publisher,
        "current-boot runtime-user readiness must remain bounded, independent, and non-mutating",
    )
    require(
        all(f'"{fact}"' in readiness_waiter for fact in readiness_facts)
        and 'Path(__file__).resolve().parents[2]' in readiness_waiter
        and "rocky-cloud-qualification-readiness.schema.json" in readiness_waiter
        and '"runtime-user-manager"' in readiness_waiter
        and '"runtime-user-bus"' in readiness_waiter
        and '"runtime-user-control"' in readiness_waiter,
        "qualification admission must preserve each closed runtime-user boundary",
    )
    require(
        "readiness_publisher" in main
        and "runtime_user_systemd" in main
        and "secpal-publish-rocky-qualification-readiness" in bootstrap
        and "runtime_user_systemd.py" in bootstrap
        and '--boot-id "$boot_id"' in bootstrap
        and readiness_publisher.count("current_boot_id() != arguments.boot_id") == 2
        and "secpal-publish-rocky-qualification-readiness" not in target_runner
        and bootstrap.index('rm -f -- "$qualification_readiness"')
        < bootstrap.index("/usr/local/sbin/secpal-prepare-rocky-host")
        < bootstrap.index('boot_id="$(cat /proc/sys/kernel/random/boot_id)"')
        < bootstrap.rindex("/usr/local/sbin/secpal-publish-rocky-qualification-readiness")
        and "guest_startup_complete\":true" not in bootstrap,
        "startup must bind one invalidated current-boot marker to runtime-user admission",
    )
    require(
        "EXPECTED_TARGET_SHA = \"402c22b0a1d69a5a3dba74ffb68cf016caba606b\""
        in target_failure_classifier
        and "EXPECTED_HARNESS_SHA256 = \"436756f79c7f120d5c4b9fc15b12b2fd91da0fdea5e93ed2907172a73c2861ac\""
        in target_failure_classifier
        and "unclassified-target-failure" in target_failure_classifier
        and "SECPAL_TARGET_ERR_V2" in target_failure_classifier
        and "SECPAL_TARGET_ERR_V1" not in target_failure_classifier
        and "${BASH_LINENO[@]}" in target_failure_trace
        and "SECPAL_TARGET_ERR_V2:%s:%s" in target_failure_trace
        and "frame_count >= 8" in target_failure_trace
        and all(
            forbidden not in target_failure_trace
            for forbidden in ("BASH_SOURCE", "FUNCNAME", "COMP_WORDS")
        )
        and target_failure_trace.count("BASH_COMMAND") == 1
        and literal_constant(target_failure_classifier, "MAX_TRACE_FRAMES") == 8
        and literal_constant(target_failure_classifier, "MAX_TRACE_LINE") == 9_999
        and all(
            isinstance(rule, tuple)
            and len(rule) == 3
            and type(rule[0]) is int
            and type(rule[1]) is int
            and rule[0] > 91
            for rule in target_line_rules
        )
        and target_line_rules == expected_target_line_rules
        and [rule for rule in target_line_rules if rule[0] <= 652 and rule[1] >= 614]
        == [
            (614, 614, "qualify-quadlet-daemon-reload"),
            (615, 637, "qualify-quadlet-authority"),
            (638, 638, "qualify-quadlet-start"),
            (639, 639, "qualify-quadlet-active-state"),
            (641, 652, "qualify-quadlet-authority"),
        ]
        and all(
            operation not in {
                "qualify-selinux-storage-fcontext-add",
                "qualify-selinux-storage-restorecon",
                "qualify-selinux-storage-matchpathcon",
            }
            for _, _, operation in target_line_rules
        )
        and storage_setup_line_rules
        == [
            (668, 668, "qualify-selinux-storage-directory-create"),
        ]
        and "qualify-quadlet-runtime" not in target_failure_classifier
        and 'if len(explicit) > 1:\n        return "qualification-harness", "unclassified-target-failure"'
        in target_failure_classifier
        and "if len(explicit) == 1 and len(traced_operations) == 1:" in target_failure_classifier
        and "if len(explicit) == 1 and len(traced_operations) > 1:" in target_failure_classifier
        and "if len(traced_operations) == 1:" in target_failure_classifier
        and 'if len(traced_operations) == 1:\n        return traced_operations.pop(), "command-failed"\n    return "qualification-harness", "unclassified-target-failure"'
        in target_failure_classifier
        and 'return "qualification-harness", "unclassified-target-failure"'
        in target_failure_classifier.split(
            'if len(traced_operations) == 1:', 1
        )[1]
        and "validate-target-qualification-failure" in target_runner
        and target_runner.count("exit 91") == 2
        and 'rm -f -- "$stdout"' in target_runner
        and "qualification_failure_expected" in target_text
        and "head -c 16385" in target_text
        and "target-qualification-failure.json" in target_text,
        "target harness failures must retain one bounded negative-only semantic identity",
    )
    require(
        "/opt/secpal-control/libexec/rocky-start-runuser" in target_failure_trace
        and "SECPAL_START_EXACT_CALL" not in target_failure_trace + start_runuser
        and '"$#" -eq 15' in target_failure_trace
        and '"${12}" == systemctl' in target_failure_trace
        and '"${14}" == start' in target_failure_trace
        and "SECPAL_START_OBSERVATION_PATH"
        not in target_failure_trace + target_runner + start_runuser
        and "10#$frame == 614" in target_failure_trace
        and 'REAL_RUNUSER = Path("/usr/sbin/runuser")' in start_runuser
        and 'TRUSTED_ENV = Path("/usr/local/libexec/secpal-control/rocky-start-env")'
        in start_runuser
        and 'REAL_ENV = Path("/usr/bin/env")' in start_env
        and 'TRUSTED_SYSTEMCTL = Path(' in start_env
        and '"/usr/local/libexec/secpal-control/rocky-start-systemctl"'
        in start_env
        and 'REAL_SYSTEMCTL = Path("/usr/bin/systemctl")' in start_systemctl
        and all(
            source.startswith("#!/usr/bin/python3 -I\n")
            for source in (start_runuser, start_env, start_systemctl)
        )
        and "shell=True" not in start_runuser + start_env + start_systemctl
        and "MAX_PROTOCOL_BYTES = 2_048" in start_runuser
        and "MAX_PROTOCOL_BYTES = 2_048" in start_env
        and "MAX_PROPERTY_BYTES = 1_024" in start_systemctl
        and "START_STAGE_DECISIONS" in target_failure_classifier
        and "validate_admitted_quadlet_start_diagnostic" in target_failure_classifier
        and "validate_admitted_quadlet_start_diagnostic" in rocky_control
        and '--start-observation "$start_observation"' in target_runner
        and '6>"$start_observation"' not in target_runner
        and 'start_observation="$evidence_root/quadlet-start-observation.json"'
        in target_runner
        and 'exec 6>/var/lib/secpal-rocky/evidence/quadlet-start-observation.json'
        in target_failure_trace
        and "start_runuser" in main
        and "start_env" in main
        and "start_systemctl" in main
        and "rocky-start-runuser" in bootstrap
        and "rocky-start-env" in bootstrap
        and "rocky-start-systemctl" in bootstrap
        and "0:0:700" in bootstrap
        and "0:0:555" in bootstrap,
        "Quadlet start must retain one closed absolute-executable diagnostic boundary",
    )
    require(
        "/opt/secpal-control/libexec/rocky-active-runuser" in target_failure_trace
        and "SECPAL_ACTIVE_EXACT_CALL" not in target_failure_trace + active_runuser
        and '"$#" -eq 16' in target_failure_trace
        and '"${14}" == is-active' in target_failure_trace
        and '"${15}" == --quiet' in target_failure_trace
        and 'REAL_RUNUSER = Path("/usr/sbin/runuser")' in active_runuser
        and 'TRUSTED_ENV = Path("/usr/local/libexec/secpal-control/rocky-active-env")'
        in active_runuser
        and 'REAL_ENV = Path("/usr/bin/env")' in active_env
        and 'TRUSTED_SYSTEMCTL = Path(' in active_env
        and '"/usr/local/libexec/secpal-control/rocky-active-systemctl"'
        in active_env
        and 'REAL_SYSTEMCTL = Path("/usr/bin/systemctl")' in active_systemctl
        and all(
            source.startswith("#!/usr/bin/python3 -I\n")
            for source in (active_runuser, active_env, active_systemctl)
        )
        and "shell=True" not in active_runuser + active_env + active_systemctl
        and "dict(os.environ)" not in active_runuser + active_env + active_systemctl
        and "MAX_PROTOCOL_BYTES = 2_048" in active_runuser
        and "MAX_PROTOCOL_BYTES = 2_048" in active_env
        and "ACTIVE_STAGE_DECISIONS" in target_failure_classifier
        and "validate_admitted_quadlet_active_diagnostic"
        in target_failure_classifier
        and "validate_admitted_quadlet_active_diagnostic" in rocky_control
        and '--active-observation "$active_observation"' in target_runner
        and '7>"$active_observation"' not in target_runner
        and "SECPAL_ACTIVE_OBSERVATION_PATH"
        not in target_failure_trace + target_runner + active_runuser
        and 'active_observation="$evidence_root/quadlet-active-observation.json"'
        in target_runner
        and 'exec 7>/var/lib/secpal-rocky/evidence/quadlet-active-observation.json'
        in target_failure_trace
        and "active_runuser" in main
        and "active_env" in main
        and "active_systemctl" in main
        and "rocky-active-runuser" in bootstrap
        and "rocky-active-env" in bootstrap
        and "rocky-active-systemctl" in bootstrap,
        "Quadlet active-state must retain one closed absolute-executable diagnostic boundary",
    )
    require(
        '/opt/secpal-control/libexec/rocky-primary-runuser "$@"'
        in target_failure_trace
        and '"$#" -eq 29' in target_failure_trace
        and '"${12}" == podman' in target_failure_trace
        and '"${13}" == run' in target_failure_trace
        and "SECPAL_PRIMARY_OBSERVATION_PATH"
        not in target_failure_trace + target_runner + primary_runuser
        and '/usr/sbin/runuser "$@"' in target_failure_trace
        and "SECPAL_PRIMARY_EXACT_CALL" not in target_failure_trace
        and "SECPAL_PRIMARY_BRANCH" not in target_failure_trace
        and "SECPAL_PRIMARY_MARKER" not in target_failure_trace
        and 'REAL_RUNUSER = Path("/usr/sbin/runuser")' in primary_runuser
        and 'RUNTIME_HELPER = Path(' in primary_runuser
        and '"/usr/local/libexec/secpal-control/rocky-primary-runtime"'
        in primary_runuser
        and 'REAL_PODMAN = Path("/usr/bin/podman")' in primary_runtime
        and all(
            source.startswith("#!/usr/bin/python3 -I\n")
            for source in (primary_runuser, primary_runtime)
        )
        and "shell=True" not in primary_runuser + primary_runtime
        and "dict(os.environ)" not in primary_runuser + primary_runtime
        and "MAX_PROTOCOL_BYTES = 512" in primary_runuser
        and '"LC_ALL": "C"' in primary_runuser
        and "O_NOFOLLOW" in primary_runuser
        and "Once the exact primary request starts" in primary_runuser
        and "PRIMARY_STAGE_DECISIONS" in target_failure_classifier
        and "validate_admitted_primary_workload_diagnostic"
        in target_failure_classifier
        and "validate_admitted_primary_workload_diagnostic" in rocky_control
        and '--primary-observation "$primary_observation"' in target_runner
        and 'primary_observation="$evidence_root/primary-workload-observation.json"'
        in target_runner
        and 'OBSERVATION_PATH = Path(' in primary_runuser
        and '"/var/lib/secpal-rocky/evidence/primary-workload-observation.json"'
        in primary_runuser
        and "primary_runuser" in main
        and "primary_runtime" in main
        and "rocky-primary-runuser" in bootstrap
        and "rocky-primary-runtime" in bootstrap
        and not (root / "scripts/ci-cloud/rocky-primary-env.py").exists()
        and not (root / "scripts/ci-cloud/rocky-primary-podman.py").exists(),
        "the primary workload must use one exact direct closed helper boundary",
    )
    require(
        "SECPAL_QUADLET_RELOAD_FAILURE_V3:%s:%s:%s:%s:%s:%s"
        in target_failure_trace
        and "/opt/secpal-control/libexec/rocky-reload-runuser"
        in target_failure_trace
        and "/usr/sbin/runuser" in target_failure_trace
        and 'export PATH="/opt/secpal-control/libexec:$PATH"'
        not in target_failure_trace
        and 'TRUSTED_SYSTEMCTL = (\n    "/usr/local/libexec/secpal-control/rocky-reload-systemctl"'
        in reload_runuser
        and 'REAL_RUNUSER = "/usr/sbin/runuser"' in reload_runuser
        and "os.dup2(ACK_FD, 0, inheritable=True)" in reload_runuser
        and "os.dup2(RECORD_FD, 1, inheritable=True)" in reload_runuser
        and "os.closerange(3" in reload_runuser
        and "SECPAL_QUADLET_RELOAD_CLIENT_V1" in reload_systemctl
        and 'REAL_SYSTEMCTL = "/usr/bin/systemctl"' in reload_systemctl
        and "os.getresuid() == (runtime.pw_uid,) * 3" in reload_systemctl
        and "os.getresgid() == (runtime.pw_gid,) * 3" in reload_systemctl
        and "os.execv(REAL_SYSTEMCTL" in reload_systemctl
        and "os.execve(REAL_RUNUSER" in reload_runuser
        and '"$status" "$$" "$secpal_reload_run_space_bytes"'
        in target_failure_trace
        and '"$secpal_reload_audit_baseline" "$secpal_reload_journal_cursor"'
        in target_failure_trace
        and '[[ "$BASH_COMMAND" == "user_systemctl daemon-reload" ]]'
        in target_failure_trace
        and "SECPAL_RELOAD_EXACT_CALL"
        not in target_failure_trace + reload_runuser + reload_systemctl
        and '"$#" -eq 14' in target_failure_trace
        and '"${14}" == daemon-reload' in target_failure_trace
        and "timeout --signal=KILL 2s journalctl --no-pager --quiet --show-cursor --lines=0"
        in target_failure_trace
        and "timeout --signal=KILL 1s stat --file-system --format='%a %S' -- /run/systemd"
        in target_failure_trace
        and "timeout --signal=KILL 1s date -u '+%Y%m%d%H%M%S'"
        in target_failure_trace
        and "10#$frame == 614" in target_failure_trace
        and "trap - ERR" in target_failure_trace
        and "read -r -t 25 -u 5" in target_failure_trace
        and "return \"$status\"" in target_failure_trace
        and 'mkfifo -m 0600 "$reload_event" "$reload_ack"' in target_runner
        and '"$target_sha" == "$expected_target_sha"'
        in target_runner
        and '"$qualification_harness_sha256" == "$expected_harness_sha256"'
        in target_runner
        and target_runner.index("observe-rocky-quadlet-reload-adjacency.py")
        < target_runner.index('bash "$work_root/scripts/qualify-production-host.sh"')
        < target_runner.index(
            '\npipeline_statuses=("${PIPESTATUS[@]}")\n',
            target_runner.index("observe-rocky-quadlet-reload-adjacency.py"),
        )
        < target_runner.index(
            "wait \"$observer_pid\"",
            target_runner.index("observe-rocky-quadlet-reload-adjacency.py"),
        )
        and "--reload-adjacency \"$reload_adjacency\"" in target_runner
        and "reload_observer" in main
        and "reload_runuser" in main
        and "reload_systemctl" in main
        and "observe-rocky-quadlet-reload-adjacency.py" in bootstrap
        and "rocky-reload-runuser" in bootstrap
        and "/usr/local/libexec/secpal-control/rocky-reload-systemctl" in bootstrap
        and "chmod 0555 /usr/local/libexec/secpal-control/rocky-reload-systemctl"
        in bootstrap
        and "for trusted_directory in / /opt /opt/secpal-control"
        in bootstrap
        and "/opt/secpal-control/libexec /opt/secpal-control/scripts"
        in bootstrap
        and "/opt/secpal-control/scripts/ci-cloud /usr /usr/local /usr/local/libexec"
        in bootstrap
        and '[[ -d "$trusted_directory" && ! -L "$trusted_directory" ]]'
        in bootstrap
        and "(( (8#$trusted_mode & 8#022) == 0 ))" in bootstrap
        and "0:0:700" in bootstrap
        and "0:0:555" in bootstrap
        and "ln -f /opt/secpal-control/scripts/ci-cloud/rocky-target-qualification-trace.sh"
        not in bootstrap
        and "pwd.error" not in reload_adjacency_observer
        and "or 614 not in frames" in reload_adjacency_observer
        and "or 242 not in frames" not in reload_adjacency_observer,
        "daemon-reload adjacency must execute through the bounded pre-cleanup ERR seam",
    )
    require(
        literal_constant(reload_adjacency_observer, "MAX_INPUT_BYTES") == 4_096
        and literal_constant(reload_adjacency_observer, "MAX_COMMAND_BYTES") == 65_536
        and literal_constant(reload_adjacency_observer, "MAX_GENERATOR_RECORD_BYTES")
        == 2_048
        and literal_constant(
            reload_adjacency_observer, "MAX_GENERATOR_CANDIDATE_RECORDS"
        )
        == 3
        and literal_constant(reload_adjacency_observer, "MAX_RELOAD_RECORD_BYTES")
        == 2_048
        and literal_constant(
            reload_adjacency_observer, "MAX_RELOAD_CANDIDATE_RECORDS"
        )
        == 8
        and literal_constant(reload_adjacency_observer, "MAX_OBSERVATION_BYTES")
        == 8_192
        and literal_constant(reload_adjacency_observer, "COMMAND_TIMEOUT_SECONDS") == 3
        and literal_constant(
            reload_adjacency_observer, "MANAGER_CONTINUITY_TIMEOUT_SECONDS"
        )
        == 2
        and literal_constant(
            reload_adjacency_observer, "PACKAGE_QUERY_TIMEOUT_SECONDS"
        )
        == 1
        and literal_constant(
            reload_adjacency_observer, "RELOAD_JOURNAL_TIMEOUT_SECONDS"
        )
        == 1
        and literal_constant(reload_adjacency_observer, "GENERATOR_TIMEOUT_SECONDS") == 8
        and literal_constant(reload_adjacency_observer, "CAPTURE_DEADLINE_SECONDS")
        == 22
        and 2
        * literal_constant(reload_adjacency_observer, "COMMAND_TIMEOUT_SECONDS")
        + 2
        * literal_constant(
            reload_adjacency_observer, "MANAGER_CONTINUITY_TIMEOUT_SECONDS"
        )
        + literal_constant(
            reload_adjacency_observer, "PACKAGE_QUERY_TIMEOUT_SECONDS"
        )
        + literal_constant(
            reload_adjacency_observer, "RELOAD_JOURNAL_TIMEOUT_SECONDS"
        )
        + literal_constant(reload_adjacency_observer, "GENERATOR_TIMEOUT_SECONDS")
        < literal_constant(reload_adjacency_observer, "CAPTURE_DEADLINE_SECONDS")
        and "time.monotonic() > deadline" in reload_adjacency_observer
        and "write_document(arguments.output, document, deadline)"
        in reload_adjacency_observer
        and 'raise ObservationError("adjacency command could not execute")'
        in reload_adjacency_observer
        and "except (OSError, subprocess.TimeoutExpired)" in reload_adjacency_observer
        and "os.O_NOFOLLOW" in reload_adjacency_observer
        and "os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW"
        in reload_adjacency_observer
        and "stat.S_ISFIFO" in reload_adjacency_observer
        and "metadata.st_uid != 0" in reload_adjacency_observer
        and "metadata.st_gid != 0" in reload_adjacency_observer
        and "stat.S_IMODE(metadata.st_mode) != 0o600" in reload_adjacency_observer
        and 'Path(f"/etc/containers/systemd/users/{runtime_uid}")'
        in reload_adjacency_observer
        and "directory_metadata = directory.lstat()" in reload_adjacency_observer
        and "not stat.S_ISLNK(directory_metadata.st_mode)"
        in reload_adjacency_observer
        and "directory_metadata.st_uid == 0" in reload_adjacency_observer
        and "directory_metadata.st_gid == 0" in reload_adjacency_observer
        and "not directory_metadata.st_mode & 0o022" in reload_adjacency_observer
        and "directory.resolve(strict=True) == directory"
        in reload_adjacency_observer
        and "stat.S_ISLNK(link_metadata.st_mode)" in reload_adjacency_observer
        and "parent_resolved != path.parent" in reload_adjacency_observer
        and "metadata.st_mode & 0o111 == 0" in reload_adjacency_observer
        and '"owner_uid": metadata.st_uid' in reload_adjacency_observer
        and '"owner_gid": metadata.st_gid' in reload_adjacency_observer
        and 'f"{stat.S_IMODE(metadata.st_mode):04o}"' in reload_adjacency_observer
        and "hashlib.sha256(payload).hexdigest()" in reload_adjacency_observer
        and 'f"QUADLET_UNIT_DIRS={input_path.parent}"' in reload_adjacency_observer
        and '"--user",\n                "--dryrun"' in reload_adjacency_observer
        and "direct_user_show_environment" in reload_adjacency_observer
        and "RUNTIME_ACCOUNT, runtime_uid, runtime.pw_dir"
        in reload_adjacency_observer
        and "--machine=" not in reload_adjacency_observer
        and '"show-environment"' in direct_user_systemd
        and "manager_state_observed and bus_state_observed and control_status != 125"
        in reload_adjacency_observer
        and 'GENERATOR_CODE_FUNC = "do_execute"' in reload_adjacency_observer
        and 'GENERATOR_CODE_FILE = "../src/shared/exec-util.c"'
        in reload_adjacency_observer
        and 'GENERATOR_OUTPUT_FIELDS = "_UID,_BOOT_ID,CODE_FUNC,CODE_FILE,MESSAGE"'
        in reload_adjacency_observer
        and 'f"CODE_FUNC={GENERATOR_CODE_FUNC}"' in reload_adjacency_observer
        and 'f"CODE_FILE={GENERATOR_CODE_FILE}"' in reload_adjacency_observer
        and reload_adjacency_observer.count(
            'f"--boot={boot_id.replace(\'-\', \'\')}"'
        )
        == 2
        and 'f"--output-fields={GENERATOR_OUTPUT_FIELDS}"'
        in reload_adjacency_observer
        and "max_bytes=MAX_GENERATOR_JOURNAL_BYTES"
        in reload_adjacency_observer
        and '"journal-output-bound-exceeded"' in reload_adjacency_observer
        and '"candidate-generator-unadmitted"' in reload_adjacency_observer
        and '"candidate-count-exceeded"' in reload_adjacency_observer
        and 'ROCKY_SYSTEMD_SOURCE_RPM = "systemd-257-23.el10_2.2.rocky.0.1.src.rpm"'
        in reload_adjacency_observer
        and '"systemd-257-23.el10_2.2.rocky.0.1.aarch64"'
        in reload_adjacency_observer
        and '"systemd-257-23.el10_2.2.rocky.0.1.x86_64"'
        in reload_adjacency_observer
        and "RELOAD_SPACE_MINIMUM_BYTES = 16 * 1024 * 1024"
        in reload_adjacency_observer
        and 'RELOAD_OUTPUT_FIELDS = "_PID,_BOOT_ID,CODE_FUNC,CODE_FILE,MESSAGE"'
        in reload_adjacency_observer
        and 'f"--output-fields={RELOAD_OUTPUT_FIELDS}"'
        in reload_adjacency_observer
        and 'f"_PID={manager_pid}"' in reload_adjacency_observer
        and 'f"--after-cursor={journal_cursor}"' in reload_adjacency_observer
        and 'reasons.add("request-client-unbound")' in reload_adjacency_observer
        and '"rpm",\n            "-q",' in reload_adjacency_observer
        and '("../src/core/dbus-manager.c", "log_caller")'
        in reload_adjacency_observer
        and '("../src/core/dbus-manager.c", "method_reload")'
        in reload_adjacency_observer
        and '("../src/core/main.c", "invoke_main_loop")'
        in reload_adjacency_observer
        and '("../src/core/manager.c", "manager_reload")'
        in reload_adjacency_observer
        and '("../src/core/dbus.c", "bus_send_pending_reload_message")'
        in reload_adjacency_observer
        and "max_bytes=MAX_RELOAD_JOURNAL_BYTES" in reload_adjacency_observer
        and 'os.statvfs("/run/systemd")' in reload_adjacency_observer
        and '"tclass=system"' in reload_adjacency_observer
        and 'r"avc:\\s+denied\\s+\\{\\s*reload\\s*\\}"'
        in reload_adjacency_observer
        and "reload_access_avc(audit, expected_client_pid)"
        in reload_adjacency_observer
        and '"daemon-reload"' not in reload_adjacency_observer
        and 'comm="systemd"' not in reload_adjacency_observer
        and all(
            operation not in reload_adjacency_observer
            for operation in ('"start"', '"restart"', '"stop"', '"reset-failed"')
        ),
        "daemon-reload adjacency observation must remain bounded, closed, and non-mutating",
    )
    require(
        "def admit_daemon_reload_adjacency(" in target_failure_classifier
        and '"manager-continuity-lost"' in target_failure_classifier
        and '"target-input-invalid"' in target_failure_classifier
        and '"podman-generator-rejected"' in target_failure_classifier
        and '"other-generator-failed"' in target_failure_classifier
        and '"selinux-reload-denied"' in target_failure_classifier
        and '"manager-reload-transaction-failed"' not in target_failure_classifier
        and '"reload-run-space-rejected"' in target_failure_classifier
        and '"reload-selinux-access-denied"' in target_failure_classifier
        and '"reload-authorization-denied"' in target_failure_classifier
        and '"reload-rate-limited"' in target_failure_classifier
        and '"reload-manager-serialization-failed"' in target_failure_classifier
        and '"reload-reply-transport-failed"' in target_failure_classifier
        and '"reload-stage-evidence-contradictory"'
        in target_failure_classifier
        and '"manager-continuity-observation-unavailable"'
        in target_failure_classifier
        and 'observation, "manager_continuity_observed"'
        in target_failure_classifier
        and '"reload-completion-not-observed"' in target_failure_classifier
        and '"diagnostic-unavailable"' in target_failure_classifier
        and "captured_before_cleanup" in target_failure_classifier
        and '_closed_boolean(observation, "captured_before_cleanup")'
        in target_failure_classifier
        and "failure_event_sha256" in target_failure_classifier
        and 're.fullmatch(r"[0-9a-f]{64}", str(observation["failure_event_sha256"]))'
        in target_failure_classifier
        and "generator_failure_ambiguous" in target_failure_classifier
        and '_closed_boolean(\n            observation, "generator_failure_ambiguous"\n        )'
        in target_failure_classifier
        and "generator_observation_reason" in target_failure_classifier
        and target_failure_classifier.count(
            'generator_ambiguous != (generator_reason != "none")'
        )
        == 2
        and target_failure_classifier.count(
            'reload_access_avc["source_type"]'
        )
        == 2
        and target_failure_classifier.count(
            'reload_access_avc["target_type"]'
        )
        == 2
        and 'reload-selinux-context-observation-unavailable'
        in target_failure_classifier
        and "selinux_avc_ambiguous" in target_failure_classifier,
        "daemon-reload adjacency admission must preserve the closed fail-safe decision tree",
    )
    require(
        'INSTALLED_TARGET_FAILURE_CLASSIFIER = Path(\n    "/usr/local/sbin/secpal-classify-rocky-target-failure"\n)'
        in rocky_control
        and "SourceFileLoader" in rocky_control
        and "spec_from_loader(loader.name, loader)" in rocky_control
        and "TARGET_FAILURE_CLASSIFIER_SYMBOL" in rocky_control
        and "classifier_path.lstat()" in rocky_control
        and "metadata.st_mode & 0o022" in rocky_control
        and "metadata.st_uid != CLASSIFIER_TRUSTED_UID" in rocky_control
        and "stat.S_IMODE(metadata.st_mode) != 0o700" in rocky_control
        and "spec_from_file_location" not in rocky_control,
        "Rocky control must load only the admitted extensionless installed classifier",
    )
    require(
        'INSTALLED_TARGET_REPLAY_VERIFIER = Path(\n    "/usr/local/sbin/secpal-verify-rocky-target-replay"\n)'
        in rocky_control
        and "TARGET_REPLAY_VERIFIER_SYMBOL" in rocky_control
        and "verifier_path.lstat()" in rocky_control
        and 'replayed = b"\\0".join(' in target_replay_verifier
        and 'document["diagnostic_input_sha256"]' in target_replay_verifier
        and "classifier.classify_failure(" in target_replay_verifier
        and "classifier.replay_line_rules(" in target_replay_verifier
        and "HISTORICAL_PRE_269_LINE_RULES" in target_failure_classifier
        and "(HISTORICAL_273_TARGET_SHA, HISTORICAL_273_HARNESS_SHA256)"
        in target_failure_classifier
        and 'payload.endswith(b"\\n")' in target_failure_classifier
        and 'payload[:-1].decode("ascii").split("\\n")'
        in target_failure_classifier
        and 'payload.endswith(b"\\n")' in target_replay_verifier
        and 'payload[:-1].decode("ascii").split("\\n")'
        in target_replay_verifier
        and "object_pairs_hook=unique_json_object" in target_failure_classifier
        and "parse_constant=reject_json_constant" in target_failure_classifier
        and "object_pairs_hook=unique_json_object" in target_replay_verifier
        and "parse_constant=reject_json_constant" in target_replay_verifier
        and "classifier.replay_start_observation_admitted"
        in target_replay_verifier
        and "classifier.replay_active_observation_admitted"
        in target_replay_verifier
        and "classifier.replay_primary_observation_admitted"
        in target_replay_verifier
        and "target_replay_verifier" in bootstrap
        and "target_replay_verifier" in main,
        "Rocky replay verifier must independently close exact classifier input",
    )
    require(
        target_text.index("Retrieve and validate bounded target-qualification failure")
        < target_text.index("Enforce exact target execution")
        < target_text.index("Retrieve and validate target-owned qualification evidence")
        and "steps.target_execution.outcome == 'success'" in target_text,
        "negative target diagnostics must be transported before failure enforcement and never grant success",
    )
    require(
        text.count("create_credentials_file: false") == 4
        and text.count("export_environment_variables: false") == 4,
        "Rocky WIF must stay in-memory and step-scoped",
    )
    require(
        "credentials_json" not in text and "service_account_key" not in text,
        "static GCP keys are forbidden",
    )
    variables = read(root, "infra/ci-cloud/gcp-rocky/variables.tf")
    versions = read(root, "infra/ci-cloud/gcp-rocky/versions.tf")
    require(
        'required_version = "= 1.12.5"' in versions
        and 'version = "= 7.40.0"' in versions,
        "Rocky OpenTofu and Google provider versions must be exact",
    )
    require(
        re.search(r'image\s*=\s*var\.exact_image_self_link', main) is not None
        and 'data "google_compute_image"' not in main
        and "discovery_family" not in main,
        "OpenTofu may consume only the pre-resolved exact image identity",
    )
    require(
        'var.profile == "gcp-rocky-10-2-arm64"' in variables
        and 'var.machine_type == "c4a-standard-4"' in variables
        and 'var.profile == "gcp-rocky-10-2-x86-64"' in variables
        and 'var.machine_type == "c3-standard-4"' in variables
        and "rocky-linux-10-[a-z0-9-]*arm64[a-z0-9-]*" in variables
        and "rocky-linux-10-v[0-9]{8}" in variables,
        "OpenTofu profile, machine, image, and architecture admission disagree",
    )
    require(
        "rocky-linux-cloud/global/images/" in variables
        and main.count('resource "google_compute_instance"') == 1
        and re.search(r"\bcount\s*=", main) is None,
        "Rocky image and instance count are outside the closed contract",
    )
    for schema_name in (
        "rocky-cloud-discovery-evidence.schema.json",
        "rocky-cloud-continuation.schema.json",
        "rocky-cloud-preparation-evidence.schema.json",
        "rocky-cloud-qualification-evidence.schema.json",
        "rocky-cloud-qualification-readiness.schema.json",
        "rocky-cloud-qualification-readiness-failure.schema.json",
        "rocky-cloud-target-source-failure.schema.json",
        "rocky-cloud-target-qualification-failure.schema.json",
    ):
        try:
            schema = json.loads(read(root, f"schemas/{schema_name}"))
            Draft202012Validator.check_schema(schema)
        except (json.JSONDecodeError, SchemaError):
            raise ContractError(f"Rocky evidence schema is invalid: {schema_name}") from None
        require(
            schema.get("additionalProperties") is False,
            f"Rocky evidence schema is not closed: {schema_name}",
        )


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
        and "workload_admission_failures" in evidence_assembler
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


def validate_instance_transport_workflow(root: Path) -> None:
    """Diagnostic failure never replaces apply, reconciliation or exact cleanup."""
    workflow = yaml.safe_load(read(root, ".github/workflows/rocky-cloud-qualification.yml"))
    provision = workflow["jobs"]["provision"]
    steps = provision["steps"]
    ids = {step.get("id"): step for step in steps if "id" in step}
    apply = ids["apply"]
    admission = ids.get("transport_admission", {})
    fresh = next((step for step in steps if step["name"] ==
                  "Freshly authenticate protected main before diagnostic and provider authority"), {})
    fresh_run = fresh.get("run", "")
    require(all(fragment in fresh_run for fragment in (
        '"$GITHUB_REPOSITORY" == SecPal/deployment', '"$GITHUB_REF" == refs/heads/main',
        'gh api repos/SecPal/deployment/branches/main', '.protected',
        '.commit.sha', '.commit.commit.verification.verified',
        '"$(git rev-parse HEAD)" == "$GITHUB_SHA"',
        '"$accepted_control" == "$(printf',
    )), "transport observation requires freshly authenticated protected main")
    require(steps.index(fresh) < steps.index(ids["provision_auth"]) < steps.index(apply),
            "fresh transport control authentication must precede provider credentials")
    run = apply["run"]
    require('python3 "$GITHUB_WORKSPACE/scripts/ci-cloud/observe-instance-transport.py"' in run
            and run.count("tofu apply --auto-approve --input=false") == 1
            and "--output \"$RUNNER_TEMP/rocky-cloud/instance-transport.json\"" in run
            and '--trusted-control-sha "$GITHUB_SHA"' in run
            and '--target-sha "$TARGET_SHA"' in run
            and '--workflow-run-id "$GITHUB_RUN_ID"' in run
            and '--workflow-run-attempt "$GITHUB_RUN_ATTEMPT"' in run,
            "existing apply must use bounded trusted transport observation with exact identities")
    require(apply.get("continue-on-error") is True
            and admission.get("if") == "${{ always() }}"
            and admission.get("continue-on-error") is True
            and "--admit" in admission.get("run", "")
            and not CREDENTIAL_KEYS & set(admission.get("env", {})),
            "independent transport admission must not block cleanup or receive provider credentials")
    artifact = next((step for step in steps if step["name"] ==
                     "Retain admitted diagnostic transport evidence"), {})
    require(artifact.get("if") == "${{ always() && steps.transport_admission.outcome == 'success' }}"
            and artifact.get("continue-on-error") is True
            and artifact.get("with", {}).get("path") == "${{ runner.temp }}/rocky-cloud/instance-transport.json",
            "transport publication admits only the sanitized document and cannot suppress cleanup")
    transition = ids["identity_transition"].get("if", "")
    require(all(fragment in transition for fragment in (
        "steps.apply.outcome == 'success'", "steps.transport_admission.outcome == 'success'",
        "steps.transport_publication.outcome == 'success'")),
        "diagnostic failure must stop continuation without authorizing provider success")
    reconcile = next(step for step in steps if step["name"] ==
                     "Reconcile failed instance creation without continuing qualification")
    require(reconcile.get("if") == "${{ steps.apply.outcome == 'failure' }}"
            and reconcile.get("continue-on-error") is True
            and "gcp-rocky-janitor.py" in reconcile["run"]
            and "--exact-action reconcile" in reconcile["run"],
            "transport evidence cannot replace exact ambiguous-create reconciliation")
    require(steps.index(apply) < steps.index(admission) < steps.index(reconcile)
            and "needs.provision.result == 'failure'" in workflow["jobs"]["cleanup"]["if"]
            and "always()" in workflow["jobs"]["cleanup"]["if"],
            "collector failure must retain independent mandatory cleanup reachability")


def main(arguments: list[str]) -> int:
    root = Path(arguments[0]).resolve() if arguments else Path.cwd()
    try:
        validate(root)
        validate_instance_transport_workflow(root)
    except (ContractError, OSError, UnicodeError) as error:
        print(f"FAIL: cloud CI contract: {error}", file=sys.stderr)
        return 1
    print("Cloud CI static trust-boundary contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
