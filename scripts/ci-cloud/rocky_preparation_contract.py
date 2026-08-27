#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure normalization, admission, and assembly for Rocky host evidence.

This module deliberately has no process, filesystem, network, environment, or
clock capability.  The external collector supplies bounded raw observations.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any


RESPONSIBILITY = "normalization,admission,assembly"
INVARIANT_OWNERS = {
    "fixture-arm64-child": "rocky_preparation_contract.admit_fixture_identity",
    "rocky-package-signing-key": "rocky_preparation_contract.admit_rocky_signing_key",
    "runtime-cgroup": "rocky_preparation_contract.admit_runtime_cgroup",
    "runtime-container-host-absence": "rocky_preparation_contract.admit_runtime_container_host_absence",
    "runtime-network-backend": "rocky_preparation_contract.admit_runtime_network_backend",
    "runtime-oci-runtime": "rocky_preparation_contract.admit_runtime_oci_runtime",
    "runtime-podman-version": "rocky_preparation_contract.admit_runtime_podman_version",
    "runtime-remote-socket-absence": "rocky_preparation_contract.admit_runtime_remote_socket_absence",
    "runtime-rootless": "rocky_preparation_contract.admit_runtime_rootless",
    "runtime-seccomp": "rocky_preparation_contract.admit_runtime_seccomp",
    "runtime-socket-path-absence": "rocky_preparation_contract.admit_runtime_socket_path_absence",
    "runtime-socket-unit-disabled": "rocky_preparation_contract.admit_runtime_socket_unit_disabled",
    "runtime-systemd-user": "rocky_preparation_contract.admit_runtime_systemd_user",
}
PACKAGES = (
    "podman", "conmon", "crun", "netavark", "aardvark-dns", "passt",
    "shadow-utils-subid", "systemd", "container-selinux", "audit",
    "policycoreutils", "policycoreutils-python-utils",
    "selinux-policy-targeted", "curl", "dnf", "git", "jq", "nftables",
    "openssh-server", "sudo", "python3-jsonschema", "dnf-plugins-core",
)
REPOSITORIES = frozenset({"baseos", "appstream", "extras"})
FIXTURE = (
    "docker.io/library/alpine@sha256:"
    "4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
)
ARM_CHILD = "sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192"
FIXTURE_REPOSITORY = FIXTURE.partition("@")[0]
FIXTURE_DIGEST_IDENTITY_MAX = 8
FIXTURE_DIGEST_METADATA_MAX_BYTES = 1024
ROCKY_FINGERPRINT = "fc226859c0860bf0ddb95b085b106c736fedfc85"
ROCKY_KEY_PACKAGE = "gpg-pubkey-6fedfc85-682ae1a9"
ROCKY_KEY_VERSION = "6fedfc85"
# The Rocky RPMDB contract test independently maps this exact OpenPGP packet to
# ROCKY_FINGERPRINT; production admission needs no second crypto implementation.
ROCKY_KEY_PACKET_SHA256 = (
    "1f09530c1d1fdcbe03279b565e9b7ff1ec4d6fccd663ac2710d0b2f0119dbb7e"
)
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO_DIGEST = re.compile(
    rf"^{re.escape(FIXTURE_REPOSITORY)}@sha256:[0-9a-f]{{64}}$"
)
IMAGE = re.compile(
    r"^https://www\.googleapis\.com/compute/v1/projects/rocky-linux-cloud/"
    r"global/images/rocky-linux-10-[a-z0-9-]{1,50}$"
)
PAYLOAD_DIGEST = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
NEVRA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:~^-]{2,255}$")
HEADER_SIGNATURE = re.compile(
    r"^RSA/SHA256, [ -~]{1,128}, Key ID [0-9a-f]{16}$",
    re.IGNORECASE,
)
VERIFIED_HEADER_LINES = frozenset(
    {
        "Header V4 RSA/SHA256 Signature, key ID 6fedfc85: OK",
        "Header SHA256 digest: OK",
        "Header SHA1 digest: OK",
    }
)


class ContractError(RuntimeError):
    """A closed semantic failure, safe to convert to bounded diagnostics."""

    def __init__(
        self,
        layer: str,
        operation: str,
        reason: str,
        subject: str | None = None,
    ) -> None:
        super().__init__(f"{layer}:{operation}:{reason}")
        self.layer = layer
        self.operation = operation
        self.reason = reason
        self.subject = subject


def reject(layer: str, operation: str, reason: str, subject: str | None = None) -> None:
    raise ContractError(layer, operation, reason, subject)


def normalize_os_release(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "VERSION_ID"}:
            if key in result:
                reject("normalization", "normalize-os-release", "duplicate-observation")
            result[key] = value.strip('"')
    if set(result) != {"ID", "VERSION_ID"}:
        reject("normalization", "normalize-os-release", "representation-invalid")
    return result


def normalize_repository_ids(raw: str) -> list[str]:
    ids = sorted(
        line.split()[0]
        for line in raw.splitlines()
        if line and not line.lower().startswith("repo id")
    )
    if (
        len(ids) > 16
        or len(set(ids)) != len(ids)
        or any(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", item) is None for item in ids)
    ):
        reject("normalization", "normalize-repositories", "representation-invalid")
    return ids


def normalize_subids(raw: str, account: str, operation: str) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        name, separator, tail = line.partition(":")
        start, separator2, count = tail.partition(":")
        if not separator or not separator2 or not start.isdecimal() or not count.isdecimal():
            reject("normalization", operation, "representation-invalid")
        if name == account:
            matches.append((int(start), int(count)))
    if len(matches) != 1:
        reject("normalization", operation, "cardinality-invalid")
    return matches[0]


def normalize_all_subid_ranges(raw: str, operation: str) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        _, separator, tail = line.partition(":")
        start, separator2, count = tail.partition(":")
        if not separator or not separator2 or not start.isdecimal() or not count.isdecimal():
            reject("normalization", operation, "representation-invalid")
        result.append((int(start), int(count)))
    return result


def normalize_fixture_repo_digests(raw: str) -> tuple[str, ...]:
    if len(raw.encode("utf-8")) > FIXTURE_DIGEST_METADATA_MAX_BYTES:
        reject("normalization", "normalize-fixture-repo-digests", "observation-limit-exceeded")
    try:
        identities = json.loads(raw)
    except json.JSONDecodeError:
        reject("normalization", "normalize-fixture-repo-digests", "representation-invalid")
    if not isinstance(identities, list) or not 1 <= len(identities) <= FIXTURE_DIGEST_IDENTITY_MAX:
        reject("normalization", "normalize-fixture-repo-digests", "cardinality-invalid")
    if not all(isinstance(identity, str) for identity in identities):
        reject("normalization", "normalize-fixture-repo-digests", "wrong-type")
    if len(set(identities)) != len(identities):
        reject("normalization", "normalize-fixture-repo-digests", "duplicate-observation")
    if not all(REPO_DIGEST.fullmatch(identity) for identity in identities):
        reject("normalization", "normalize-fixture-repo-digests", "representation-invalid")
    return tuple(identities)


def admit_fixture_identity(identities: tuple[str, ...]) -> str:
    expected = f"{FIXTURE_REPOSITORY}@{ARM_CHILD}"
    if expected not in identities:
        reject("admission", "admit-fixture-arm64-child", "invariant-failed")
    return ARM_CHILD


def admit_fixture_repo_digests(raw: str) -> str:
    return admit_fixture_identity(normalize_fixture_repo_digests(raw))


def assemble_fixture_evidence(resolved_child: str) -> dict[str, Any]:
    return {"input": FIXTURE, "resolved_arm64_child": resolved_child, "pre_staged": True}


def validate_fixture_evidence(document: dict[str, Any]) -> None:
    if document != assemble_fixture_evidence(ARM_CHILD):
        reject("admission", "validate-fixture-evidence", "invariant-failed")


def normalize_memory_bytes(raw: str) -> int:
    values = [line.split() for line in raw.splitlines() if line.startswith("MemTotal:")]
    if len(values) != 1 or len(values[0]) < 2 or not values[0][1].isdecimal():
        reject("normalization", "normalize-memory", "representation-invalid")
    return int(values[0][1]) * 1024


def normalize_podman(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > 262_144:
        reject("normalization", "normalize-podman-info", "observation-limit-exceeded")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        reject("normalization", "normalize-podman-info", "representation-invalid")
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("host"), dict)
        or not isinstance(value.get("store"), dict)
    ):
        reject("normalization", "normalize-podman-info", "wrong-type")
    host = value["host"]
    if any(
        not isinstance(host.get(field), dict)
        for field in ("security", "ociRuntime", "remoteSocket")
    ):
        reject("normalization", "normalize-podman-info", "wrong-type")
    if not isinstance(value["store"].get("graphRoot"), str):
        reject("normalization", "normalize-podman-info", "wrong-type")
    return value


def normalize_label_configuration(texts: list[str]) -> bool:
    if len(texts) > 2 or any(not isinstance(text, str) or len(text.encode("utf-8")) > 65_536 for text in texts):
        reject("normalization", "normalize-container-label-config", "observation-limit-exceeded")
    disabled = any(
        re.search(r"(?im)^\s*label\s*=\s*(?:false|['\"]?disable)", text)
        for text in texts
    )
    return not disabled


def normalize_unit_statuses(statuses: list[int], expected_count: int) -> list[bool]:
    if not isinstance(statuses, list) or any(
        type(status) is not int or not 0 <= status <= 5 for status in statuses
    ) or len(statuses) != expected_count:
        reject("normalization", "normalize-unit-status", "representation-invalid")
    return [status == 0 for status in statuses]


def normalize_sudo_authority(raw: dict[str, Any]) -> bool:
    if (
        not isinstance(raw, dict)
        or type(raw.get("status")) is not int
        or not 0 <= raw["status"] <= 255
        or not isinstance(raw.get("output"), str)
        or len(raw["output"].encode("utf-8")) > 16_384
    ):
        reject("normalization", "normalize-sudo-authority", "representation-invalid")
    return raw["status"] == 0 and "not allowed to run sudo" not in raw["output"].lower()


def normalize_quadlet_authority(status: int) -> bool:
    if type(status) is not int or status not in {0, 1}:
        reject("normalization", "normalize-quadlet-authority", "representation-invalid")
    return status == 0


def normalize_rocky_signing_key(raw: str) -> dict[str, str]:
    if not isinstance(raw, str):
        reject("normalization", "normalize-rocky-signing-key", "wrong-type")
    if len(raw.encode("utf-8")) > 4096:
        reject("normalization", "normalize-rocky-signing-key", "observation-limit-exceeded")
    lines = raw.splitlines()
    if len(lines) < 2 or lines[0] != ROCKY_KEY_VERSION:
        reject("normalization", "normalize-rocky-signing-key", "representation-invalid")
    encoded = "".join(lines[1:])
    try:
        packet = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        reject("normalization", "normalize-rocky-signing-key", "representation-invalid")
    if not 1 <= len(packet) <= 2048:
        reject("normalization", "normalize-rocky-signing-key", "cardinality-invalid")
    return {
        "version": lines[0],
        "packet_sha256": hashlib.sha256(packet).hexdigest(),
    }


def admit_rocky_signing_key(fact: dict[str, str]) -> str:
    if fact != {
        "version": ROCKY_KEY_VERSION,
        "packet_sha256": ROCKY_KEY_PACKET_SHA256,
    }:
        reject("admission", "admit-rocky-signing-key", "invariant-failed")
    return ROCKY_FINGERPRINT


def normalize_package(raw: dict[str, Any]) -> dict[str, Any]:
    name = raw.get("name")
    if name not in PACKAGES:
        reject("normalization", "normalize-package-evidence", "subject-invalid")
    repositories = raw.get("repositories")
    if not isinstance(repositories, list) or not all(isinstance(item, str) for item in repositories):
        reject("normalization", "normalize-package-evidence", "wrong-type", name)
    if any(
        not isinstance(raw.get(field), str)
        or len(raw[field].encode("utf-8")) > 4096
        for field in ("nevra", "signed_header", "verification")
    ):
        reject("normalization", "normalize-package-evidence", "wrong-type", name)
    if (
        NEVRA.fullmatch(raw["nevra"]) is None
        or not raw["nevra"].startswith(f"{name}-")
    ):
        reject("normalization", "normalize-package-evidence", "representation-invalid", name)
    header = raw["signed_header"].splitlines()
    verification_lines = raw["verification"].splitlines()
    verification = frozenset(
        line for line in verification_lines if line.startswith("Header ")
    )
    if (
        len(header) != 5
        or not header[0]
        or PAYLOAD_DIGEST.fullmatch(header[1]) is None
        or header[2] != "8"
        or PAYLOAD_DIGEST.fullmatch(header[3]) is None
        or HEADER_SIGNATURE.fullmatch(header[4]) is None
        or not header[4].lower().endswith("5b106c736fedfc85")
        or verification != VERIFIED_HEADER_LINES
        or any(
            line.startswith("Header ") and line not in VERIFIED_HEADER_LINES
            for line in verification_lines
        )
    ):
        reject("normalization", "normalize-installed-signed-header", "representation-invalid", name)
    return {
        "name": name,
        "nevra": raw["nevra"],
        "repositories": repositories,
        "header_nevra": header[0],
        "payload_digest": header[1].lower(),
        "payload_digest_algorithm": header[2],
        "header_sha256": header[3].lower(),
        "header_signature": header[4][:-16] + header[4][-16:].lower(),
    }


def admit_package(fact: dict[str, Any], signer_fingerprint: str) -> dict[str, Any]:
    name = fact["name"]
    official = fact["repositories"]
    if len(official) != 1 or official[0] not in REPOSITORIES:
        reject("admission", "admit-package-repository", "cardinality-invalid", name)
    if signer_fingerprint != ROCKY_FINGERPRINT:
        reject("admission", "admit-package-signature", "invariant-failed", name)
    if fact["header_nevra"] != fact["nevra"]:
        reject("admission", "admit-package-identity", "invariant-failed", name)
    return {
        "name": name,
        "nevra": fact["nevra"],
        "resolved_repository": official[0],
        "signature_verified": True,
        "signer_fingerprint": ROCKY_FINGERPRINT,
        "payload_digest": fact["payload_digest"],
    }


def subids_independent(
    selected: tuple[int, int],
    ranges: list[tuple[int, int]],
    effective_ids: list[int],
) -> bool:
    start, count = selected
    stop = start + count
    identical = sum(item_start == start and item_start + item_count == stop for item_start, item_count in ranges)
    return (
        identical == 2
        and all(
            (item_start == start and item_start + item_count == stop)
            or stop <= item_start
            or start >= item_start + item_count
            for item_start, item_count in ranges
        )
        and all(not start <= identifier < stop for identifier in effective_ids)
    )


def normalize_observations(raw: dict[str, Any]) -> dict[str, Any]:
    account = raw["account"]
    if not isinstance(account, dict) or account.get("name") != "secpal-runtime":
        reject("normalization", "normalize-service-account", "representation-invalid")
    subuid = normalize_subids(raw["subuid"], account["name"], "normalize-subuid")
    subgid = normalize_subids(raw["subgid"], account["name"], "normalize-subgid")
    ranges = normalize_all_subid_ranges(raw["subuid"], "normalize-subuid-population")
    ranges += normalize_all_subid_ranges(raw["subgid"], "normalize-subgid-population")
    podman = normalize_podman(raw["podman_info"])
    return {
        **raw,
        "release": normalize_os_release(raw["os_release"]),
        "repositories_normalized": normalize_repository_ids(raw["repositories"]),
        "subuid_normalized": subuid,
        "subgid_normalized": subgid,
        "subids_independent_normalized": subids_independent(
            subuid, ranges, raw["effective_ids"]
        ),
        "podman_normalized": podman,
        "fixture_identities": normalize_fixture_repo_digests(
            raw["fixture_repo_digests"]
        ),
        "packages_normalized": [normalize_package(item) for item in raw["packages"]],
        "rocky_signing_key_normalized": normalize_rocky_signing_key(
            raw["rocky_signing_key"]
        ),
        "memory_bytes": normalize_memory_bytes(raw["meminfo"]),
        "label_disable_absent": normalize_label_configuration(
            raw["container_configs"]
        ),
        "automatic_units": normalize_unit_statuses(
            raw["automatic_unit_statuses"], 4
        ),
        "podman_socket_enabled": normalize_unit_statuses(
            [raw["podman_socket_status"]], 1
        )[0],
        "sudo_authorized": normalize_sudo_authority(raw["sudo_observation"]),
        "quadlet_writable": normalize_quadlet_authority(raw["quadlet_status"]),
    }


def admit_runtime_rootless(host: dict[str, Any]) -> None:
    if not bool(host.get("security", {}).get("rootless")):
        reject("admission", "admit-runtime-rootless", "invariant-failed")


def admit_runtime_oci_runtime(host: dict[str, Any]) -> None:
    if host.get("ociRuntime", {}).get("name") != "crun":
        reject("admission", "admit-runtime-oci-runtime", "invariant-failed")


def admit_runtime_network_backend(host: dict[str, Any]) -> None:
    if host.get("networkBackend") != "netavark":
        reject("admission", "admit-runtime-network-backend", "invariant-failed")


def admit_runtime_seccomp(host: dict[str, Any]) -> None:
    if not bool(host.get("security", {}).get("seccompEnabled")):
        reject("admission", "admit-runtime-seccomp", "invariant-failed")


def admit_runtime_cgroup(facts: dict[str, Any]) -> None:
    if facts["cgroup_filesystem"] != "cgroup2fs":
        reject("admission", "admit-runtime-cgroup", "invariant-failed")


def admit_runtime_systemd_user(facts: dict[str, Any]) -> None:
    if facts["systemd_user"] != "active":
        reject("admission", "admit-runtime-systemd-user", "invariant-failed")


def admit_runtime_socket_path_absence(facts: dict[str, Any]) -> None:
    if facts["socket_exists"]:
        reject(
            "admission", "admit-runtime-socket-path-absence", "invariant-failed"
        )


def admit_runtime_socket_unit_disabled(facts: dict[str, Any]) -> None:
    if facts["podman_socket_enabled"]:
        reject(
            "admission", "admit-runtime-socket-unit-disabled", "invariant-failed"
        )


def admit_runtime_container_host_absence(facts: dict[str, Any]) -> None:
    if facts["container_host_present"]:
        reject(
            "admission", "admit-runtime-container-host-absence", "invariant-failed"
        )


def admit_runtime_remote_socket_absence(host: dict[str, Any]) -> None:
    if bool(host.get("remoteSocket", {}).get("exists")):
        reject(
            "admission", "admit-runtime-remote-socket-absence", "invariant-failed"
        )


def admit_runtime_podman_version(facts: dict[str, Any]) -> None:
    if not isinstance(facts["podman_version"], str) or not facts["podman_version"]:
        reject("admission", "admit-runtime-podman-version", "invariant-failed")


def admit_runtime(facts: dict[str, Any]) -> None:
    """Admit each runtime invariant in one stable semantic order."""
    host = facts["podman_normalized"]["host"]
    admit_runtime_rootless(host)
    admit_runtime_oci_runtime(host)
    admit_runtime_network_backend(host)
    admit_runtime_seccomp(host)
    admit_runtime_cgroup(facts)
    admit_runtime_systemd_user(facts)
    admit_runtime_socket_path_absence(facts)
    admit_runtime_socket_unit_disabled(facts)
    admit_runtime_container_host_absence(facts)
    admit_runtime_remote_socket_absence(host)
    admit_runtime_podman_version(facts)


def admit_facts(facts: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    if SHA.fullmatch(str(options.get("target_sha", ""))) is None or SHA.fullmatch(
        str(options.get("control_sha", ""))
    ) is None:
        reject("admission", "admit-immutable-shas", "invariant-failed")
    if IMAGE.fullmatch(str(options.get("image", ""))) is None:
        reject("admission", "admit-provider-image", "invariant-failed")
    if (
        re.fullmatch(r"[1-9][0-9]{0,19}", str(options.get("run_id", ""))) is None
        or re.fullmatch(r"[1-9][0-9]{0,2}", str(options.get("run_attempt", "")))
        is None
        or type(options.get("expires_at")) is not int
        or not 1_600_000_000 <= options["expires_at"] <= 4_102_444_800
    ):
        reject("admission", "admit-run-identity", "invariant-failed")
    if facts["release"] != {"ID": "rocky", "VERSION_ID": "10.2"} or facts[
        "architecture"
    ] != "aarch64":
        reject("admission", "admit-guest-identity", "invariant-failed")
    dnf_lines = facts["dnf_version"].splitlines()
    if (
        not dnf_lines
        or re.match(r"^4(?:\.|$)", dnf_lines[0]) is None
        or facts["releasever"] != "10"
        or any(facts["automatic_units"])
    ):
        reject("admission", "admit-update-contract", "invariant-failed")
    if (
        facts["getenforce"] != "Enforcing"
        or facts["selinux_enabled"] is not True
        or "targeted" not in facts["sestatus"]
        or not facts["label_disable_absent"]
    ):
        reject("admission", "admit-selinux", "invariant-failed")
    repositories = facts["repositories_normalized"]
    if set(repositories) != REPOSITORIES or len(repositories) != 3:
        reject("admission", "admit-repositories", "invariant-failed")
    account = facts["account"]
    if (
        type(account.get("uid")) is not int
        or type(account.get("gid")) is not int
        or not 1 <= account["uid"] <= 4_294_967_294
        or not 1 <= account["gid"] <= 4_294_967_294
    ):
        reject("admission", "admit-service-account", "invariant-failed")
    subuid = facts["subuid_normalized"]
    subgid = facts["subgid_normalized"]
    if subuid != subgid or subuid[1] != 65536:
        reject("admission", "admit-subids", "invariant-failed")
    host = facts["podman_normalized"]["host"]
    store = facts["podman_normalized"]["store"]
    graphroot = facts["graphroot"]
    home = facts["account_home"]
    if (
        not isinstance(graphroot, str)
        or store.get("graphRoot") != graphroot
        or not isinstance(home, str)
        or not graphroot.startswith(home.rstrip("/") + "/")
    ):
        reject("admission", "admit-rootless-graphroot", "invariant-failed")
    resolved_fixture = admit_fixture_identity(facts["fixture_identities"])
    if not facts["fixture_present"]:
        reject("admission", "admit-fixture-present", "invariant-failed")
    if facts["boot_id"] == options["first_boot_id"]:
        reject("admission", "admit-reboot-persistence", "invariant-failed")
    signer_fingerprint = admit_rocky_signing_key(
        facts["rocky_signing_key_normalized"]
    )
    packages = [
        admit_package(item, signer_fingerprint)
        for item in facts["packages_normalized"]
    ]
    if [item["name"] for item in packages] != list(PACKAGES):
        reject("admission", "admit-package-set", "invariant-failed")
    if (
        facts["cpu_count"] != 4
        or not 15_000_000_000 <= facts["memory_bytes"] <= 20_000_000_000
        or not 110_000_000_000
        <= facts["root_filesystem_bytes"]
        <= 130_000_000_000
    ):
        reject("admission", "admit-hardware", "invariant-failed")
    admit_runtime(facts)
    if (
        account.get("shell") != "/usr/sbin/nologin"
        or facts["supplementary_groups"] != [account["gid"]]
        or facts["sudo_authorized"]
        or not facts["subids_independent_normalized"]
        or not facts["linger"]
        or facts["quadlet_writable"]
    ):
        reject("admission", "admit-service-account", "invariant-failed")
    if not facts["cloud_identity_marker"] or facts["google_credentials_present"]:
        reject("admission", "admit-cloud-identity", "invariant-failed")
    return {
        **facts,
        "packages_admitted": packages,
        "resolved_fixture": resolved_fixture,
        "admission_decisions": frozenset(
            {
                "cloud-identity", "fixture", "guest", "hardware", "packages",
                "repositories", "reboot", "run", "runtime", "selinux",
                "service-account", "subids", "updates",
            }
        ),
    }


def assemble_preparation_evidence(
    facts: dict[str, Any], options: dict[str, Any]
) -> dict[str, Any]:
    required_decisions = {
        "cloud-identity", "fixture", "guest", "hardware", "packages",
        "repositories", "reboot", "run", "runtime", "selinux",
        "service-account", "subids", "updates",
    }
    if facts.get("admission_decisions") != frozenset(required_decisions):
        reject("assembly", "assemble-evidence", "internal-error")
    release = facts["release"]
    account = facts["account"]
    subuid = facts["subuid_normalized"]
    subgid = facts["subgid_normalized"]
    host = facts["podman_normalized"]["host"]
    return {
        "schema_version": 1,
        "target_sha": options["target_sha"],
        "run": {
            "repository": "SecPal/deployment",
            "trusted_control_sha": options["control_sha"],
            "profile": "gcp-rocky-10-2-arm64",
            "run_id": options["run_id"],
            "run_attempt": options["run_attempt"],
            "expires_at": options["expires_at"],
        },
        "image": {"project": "rocky-linux-cloud", "exact_self_link": options["image"]},
        "guest": {"id": release["ID"], "version_id": release["VERSION_ID"], "uname_machine": facts["architecture"]},
        "hardware": {"cpu_count": facts["cpu_count"], "memory_bytes": facts["memory_bytes"], "root_filesystem_bytes": facts["root_filesystem_bytes"]},
        "repositories": {"enabled": facts["repositories_normalized"], "external_enabled": False},
        "updates": {"mechanism": "dnf4", "releasever": facts["releasever"], "automatic": False, "automatic_reboot": False},
        "packages": facts["packages_admitted"],
        "selinux": {"enabled": True, "mode": "Enforcing", "policy": "targeted", "container_selinux_installed": True, "label_disable_absent": facts["label_disable_absent"]},
        "runtime": {
            "podman": facts["podman_version"],
            "rootless": bool(host.get("security", {}).get("rootless")),
            "graphroot": facts["graphroot"],
            "oci_runtime": host.get("ociRuntime", {}).get("name"),
            "cgroup_version": 2,
            "systemd_user": True,
            "network_backend": host.get("networkBackend"),
            "seccomp_available": bool(host.get("security", {}).get("seccompEnabled")),
            "socket_absent": True,
            "api_dependency_absent": True,
        },
        "service_account": {
            "name": account["name"], "uid": account["uid"], "gid": account["gid"],
            "home": account["home"], "shell": account["shell"], "sudo": False,
            "privileged_supplementary_groups": False,
            "subuid_start": subuid[0], "subuid_count": subuid[1],
            "subgid_start": subgid[0], "subgid_count": subgid[1],
            "subids_non_overlapping": True, "linger": True,
            "quadlet_authority_writable": False,
        },
        "fixture": assemble_fixture_evidence(facts["resolved_fixture"]),
        "persistence": {"rebooted": True, "boot_id_changed": True, "survived_reboot": True},
        "cloud_identity": {
            "control_service_account_absent": True,
            "credential_file_absent": True,
            "metadata_token_unavailable": True,
            "useful_project_authority_absent": True,
        },
    }


def assemble_collection_diagnostic(
    layer: str, operation: str, reason: str, subject: str | None = None
) -> dict[str, str]:
    result = {"layer": layer, "operation": operation, "reason": reason}
    if subject is not None:
        result["subject"] = subject
    return result


def normalize_and_admit(raw: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Pure orchestration across the three separately owned responsibility surfaces."""

    facts = normalize_observations(raw)
    admitted = admit_facts(facts, options)
    return assemble_preparation_evidence(admitted, options)
