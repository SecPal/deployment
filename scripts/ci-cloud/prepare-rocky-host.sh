#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly expected_os_id=rocky
readonly expected_version='VERSION_ID=10.2'
readonly expected_architecture=aarch64
readonly runtime_account=secpal-runtime
readonly fixture='docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1'
readonly arm_child='sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192'
readonly state_root=/var/lib/secpal-rocky
readonly profile_path=/opt/secpal-control/config/ci-cloud/gcp-rocky-10-2-arm64.json
readonly final_repositories=(appstream baseos extras)
readonly failure_evidence_max_bytes=4096
readonly enabled_repository_max=16
readonly available_repository_definition_max=64

if [[ "$#" -ne 7 ]]; then
  printf 'usage: prepare-rocky-host.sh TARGET_SHA CONTROL_SHA RUN_ID RUN_ATTEMPT EXPIRES_AT IMAGE_SELF_LINK EVIDENCE_OUTPUT\n' >&2
  exit 64
fi
readonly target_sha="$1"
readonly control_sha="$2"
readonly run_id="$3"
readonly run_attempt="$4"
readonly expires_at="$5"
readonly image_self_link="$6"
readonly evidence_output="$7"
readonly failure_output="$state_root/evidence/preparation-failure.json"
[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$control_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$run_id" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$run_attempt" =~ ^[1-9][0-9]{0,2}$ ]]
[[ "$evidence_output" == "$state_root/evidence/preparation.json" ]]
current_phase="guest-identity"
reboot_requested=false
repository_failure_evidence=''
repository_diagnostic_evidence=''
repository_enabled=()
repository_unexpected=()
repository_missing=()
provider_repositories=()

read_release_value() {
  local key="$1"
  awk -F= -v wanted="$key" '$1 == wanted {value=substr($0,index($0,"=")+1); gsub(/^"|"$/, "", value); print value; exit}' /etc/os-release
}

safe_guest_fact() {
  local value="$1"
  if [[ "$value" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
    printf '%s' "$value"
  else
    printf '%s' unavailable
  fi
}

write_failure_evidence() {
  local status="$1" temporary guest_id guest_version guest_architecture base_record
  set +e
  trap - EXIT
  [[ "$status" =~ ^[1-9][0-9]{0,2}$ ]] || status=1
  case "$current_phase" in
    guest-identity|repositories|packages|selinux|runtime-account|subids|systemd-user|quadlet-authority|fixture|pre-reboot|post-reboot-identity|post-reboot-selinux|cloud-identity|evidence-collection|evidence-validation) ;;
    *) current_phase=evidence-collection ;;
  esac
  guest_id="$(safe_guest_fact "$(read_release_value ID 2>/dev/null || true)")"
  guest_version="$(safe_guest_fact "$(read_release_value VERSION_ID 2>/dev/null || true)")"
  guest_architecture="$(safe_guest_fact "$(uname -m 2>/dev/null || true)")"
  install -d -o root -g secpal-cloud -m 0710 "$state_root" || return 0
  install -d -o root -g secpal-cloud -m 0750 "$state_root/evidence" || return 0
  if [[ "$evidence_output" == "$state_root/evidence/preparation.json" ]]; then
    rm -f -- "$evidence_output"
  fi
  temporary="$(mktemp "$state_root/evidence/.preparation-failure.XXXXXX")" || return 0
  chown root:root "$temporary" || { rm -f -- "$temporary"; return 0; }
  chmod 0600 "$temporary" || { rm -f -- "$temporary"; return 0; }
  base_record="$(printf '{"schema_version":1,"target_sha":"%s","trusted_control_sha":"%s","run_id":"%s","run_attempt":"%s","phase":"%s","exit_status":%s,"guest":{"id":"%s","version_id":"%s","uname_machine":"%s"}}' \
    "$target_sha" "$control_sha" "$run_id" "$run_attempt" "$current_phase" "$status" \
    "$guest_id" "$guest_version" "$guest_architecture")"
  if ! write_failure_document "$base_record" "$repository_failure_evidence" "$repository_diagnostic_evidence" "$temporary"; then
    rm -f -- "$temporary"
    return 0
  fi
  chown root:secpal-cloud "$temporary" && chmod 0440 "$temporary" && mv -T -- "$temporary" "$failure_output"
}

preparation_exit() {
  local status="$1"
  trap - EXIT
  if [[ "$status" -ne 0 && "$reboot_requested" != true ]]; then
    write_failure_evidence "$status"
  fi
  exit "$status"
}

trap 'preparation_exit "$?"' EXIT

prepare_evidence_transport() {
  install -d -o root -g secpal-cloud -m 0710 "$state_root"
  install -d -o root -g secpal-cloud -m 0750 "$state_root/evidence"
  [[ ! -L "$failure_output" ]]
  rm -f -- "$failure_output"
}

assert_guest_identity() {
  [[ "$(read_release_value ID)" == "$expected_os_id" ]]
  [[ "$(read_release_value VERSION_ID)" == "${expected_version#VERSION_ID=}" ]]
  [[ "$(uname -m)" == "$expected_architecture" ]]
}

run_as_runtime() {
  local uid home
  uid="$(id -u "$runtime_account")"
  home="$(getent passwd "$runtime_account" | awk -F: '{print $6}')"
  [[ "$home" == /* && -d "$home" ]]
  runuser --user "$runtime_account" -- env \
    HOME="$home" \
    XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    "$@"
}

block_metadata_credentials() {
  nft add table inet secpal_metadata 2>/dev/null || true
  nft 'add chain inet secpal_metadata output { type filter hook output priority -150; policy accept; }' 2>/dev/null || true
  if ! nft list chain inet secpal_metadata output | grep -Fq 'ip daddr 169.254.169.254 reject'; then
    nft add rule inet secpal_metadata output ip daddr 169.254.169.254 reject
  fi
}

configure_subids() {
  local start path temporary
  start="$(/usr/local/sbin/secpal-allocate-rocky-subids /etc/subuid /etc/subgid)"
  for path in /etc/subuid /etc/subgid; do
    temporary="$(mktemp --tmpdir=/etc ".${path##*/}.XXXXXX")"
    chmod 0600 "$temporary"
    awk -F: -v account="$runtime_account" '$1 != account' "$path" >"$temporary"
    printf '%s:%s:65536\n' "$runtime_account" "$start" >>"$temporary"
    chown root:root "$temporary"
    chmod 0644 "$temporary"
    mv -T -- "$temporary" "$path"
  done
}

read_repository_ids() {
  local operation="$1" mode="$2" maximum="$3" output ids
  [[ "$maximum" =~ ^[1-9][0-9]{0,2}$ ]]
  set_repository_diagnostic "$operation" command-failed
  if ! output="$(dnf4 --quiet repolist "$mode")"; then
    printf 'ERROR: dnf4 repository observation failed.\n' >&2
    return 1
  fi
  set_repository_diagnostic "$operation" parse-failed
  if ! ids="$(printf '%s\n' "$output" | awk '
    NF && tolower($1) != "repo" {print $1}
  ' | LC_ALL=C sort -u)"; then
    printf 'ERROR: repository ID parsing failed.\n' >&2
    return 1
  fi
  REPLY=()
  while IFS= read -r repository; do
    [[ -z "$repository" ]] && continue
    set_repository_diagnostic "$operation" invalid-repository-id
    [[ "$repository" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || {
      printf 'ERROR: repository ID is outside the closed syntax.\n' >&2
      return 1
    }
    REPLY+=("$repository")
  done <<<"$ids"
  set_repository_diagnostic "$operation" observation-limit-exceeded
  [[ "${#REPLY[@]}" -le "$maximum" ]] || {
    printf 'ERROR: repository observation exceeds the bounded limit.\n' >&2
    return 1
  }
}

provider_bootstrap_repositories() {
  python3 - "$profile_path" <<'PY'
import json
import re
import sys

try:
    document = json.load(open(sys.argv[1], encoding="utf-8"))
    repositories = document["repositories"]
    final = repositories["final_enabled_repositories"]
    allowed = repositories["pre_admission_provider_repositories"]
except (OSError, KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
if final != ["appstream", "baseos", "extras"]:
    raise SystemExit(1)
if not isinstance(allowed, list) or not allowed or len(allowed) > 16:
    raise SystemExit(1)
if len(set(allowed)) != len(allowed) or any(
    not isinstance(item, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", item) is None
    for item in allowed
):
    raise SystemExit(1)
print("\n".join(sorted(allowed)))
PY
}

repository_json_array() {
  local item first=true
  printf '['
  for item in "$@"; do
    [[ "$first" == true ]] || printf ','
    first=false
    printf '"%s"' "$item"
  done
  printf ']'
}

write_failure_document() {
  local base_record="$1" repository_record="$2" diagnostic_record="$3" output="$4"
  local document="$base_record"
  if [[ -n "$repository_record" ]]; then
    document="${base_record%?},\"repositories\":$repository_record}"
  fi
  if [[ -n "$diagnostic_record" ]]; then
    document="${document%?},\"repository_diagnostic\":$diagnostic_record}"
  fi
  printf '%s\n' "$document" >"$output" || return 1
  if [[ "$(wc -c <"$output")" -gt "$failure_evidence_max_bytes" && -n "$repository_record" ]]; then
    document="$base_record"
    if [[ -n "$diagnostic_record" ]]; then
      document="${base_record%?},\"repository_diagnostic\":$diagnostic_record}"
    fi
    printf '%s\n' "$document" >"$output" || return 1
  fi
  if [[ "$(wc -c <"$output")" -gt "$failure_evidence_max_bytes" && -n "$diagnostic_record" ]]; then
    printf '%s\n' "$base_record" >"$output" || return 1
  fi
  [[ "$(wc -c <"$output")" -le "$failure_evidence_max_bytes" ]]
}

clear_repository_failure() {
  repository_failure_evidence=''
  repository_diagnostic_evidence=''
  repository_enabled=()
  repository_unexpected=()
  repository_missing=()
}

set_repository_diagnostic() {
  local operation="$1" reason="$2" repository_id="${3:-}"
  [[ "$operation" =~ ^(validate-dnf4|load-reviewed-provider-repositories|observe-initial-enabled-repositories|validate-initial-pre-admission|observe-available-repository-definitions|validate-required-repository-definitions|install-repository-management-prerequisite|enable-required-rocky-repository|observe-normalized-pre-removal-state|validate-normalized-pre-removal-state|disable-reviewed-provider-repository|observe-final-repository-state|validate-final-repository-state)$ ]]
  [[ "$reason" =~ ^(command-failed|parse-failed|observation-limit-exceeded|invalid-repository-id|required-repository-definition-unavailable|package-transaction-failed|repository-mutation-failed|postcondition-failed|profile-invalid)$ ]]
  if [[ -n "$repository_id" ]]; then
    [[ "$repository_id" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]
    repository_diagnostic_evidence="$(printf '{\"operation\":\"%s\",\"reason\":\"%s\",\"repository_id\":\"%s\"}' "$operation" "$reason" "$repository_id")"
  else
    repository_diagnostic_evidence="$(printf '{\"operation\":\"%s\",\"reason\":\"%s\"}' "$operation" "$reason")"
  fi
}

record_repository_failure() {
  local stage="$1"
  repository_failure_evidence="$(
    printf '{"stage":"%s","enabled":%s,"unexpected_enabled":%s,"missing_required":%s}' \
      "$stage" \
      "$(repository_json_array "${repository_enabled[@]}")" \
      "$(repository_json_array "${repository_unexpected[@]}")" \
      "$(repository_json_array "${repository_missing[@]}")"
  )"
}

contains_repository() {
  local wanted="$1"
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$wanted" ]] && return 0
  done
  return 1
}

observe_enabled_repositories() {
  local operation="$1" stage="$2" repository
  clear_repository_failure
  if ! read_repository_ids "$operation" --enabled "$enabled_repository_max"; then
    return 1
  fi
  repository_enabled=("${REPLY[@]}")
  repository_unexpected=()
  repository_missing=()
  for repository in "${repository_enabled[@]}"; do
    if ! contains_repository "$repository" "${final_repositories[@]}" && {
      [[ "$stage" == final-admission ]] || ! contains_repository "$repository" "${provider_repositories[@]}"
    }; then
      repository_unexpected+=("$repository")
    fi
  done
  for repository in "${final_repositories[@]}"; do
    if ! contains_repository "$repository" "${repository_enabled[@]}"; then
      repository_missing+=("$repository")
    fi
  done
  record_repository_failure "$stage"
}

admit_repositories() {
  local dnf_version repository provider_output
  local -a available_repos missing_before_enable enabled_before_disable
  set_repository_diagnostic validate-dnf4 command-failed
  dnf_version="$(dnf4 --version)"
  set_repository_diagnostic validate-dnf4 postcondition-failed
  [[ "${dnf_version%%$'\n'*}" =~ ^4(\.|$) ]] || {
    printf 'ERROR: repository admission requires DNF4.\n' >&2
    return 1
  }
  set_repository_diagnostic load-reviewed-provider-repositories profile-invalid
  if ! provider_output="$(provider_bootstrap_repositories)"; then
    printf 'ERROR: provider repository profile is invalid.\n' >&2
    return 1
  fi
  mapfile -t provider_repositories <<<"$provider_output"
  if ! observe_enabled_repositories observe-initial-enabled-repositories pre-admission; then
    return 1
  fi
  set_repository_diagnostic validate-initial-pre-admission postcondition-failed
  [[ "${#repository_unexpected[@]}" -eq 0 ]] || {
    printf 'ERROR: enabled repositories include an unreviewed provider or external repository.\n' >&2
    return 1
  }
  if [[ "${#repository_missing[@]}" -eq 0 ]] && [[ "${#repository_enabled[@]}" -eq "${#final_repositories[@]}" ]]; then
    clear_repository_failure
    return 0
  fi
  local provider_present=false
  for repository in "${provider_repositories[@]}"; do
    if contains_repository "$repository" "${repository_enabled[@]}"; then
      provider_present=true
    fi
  done
  set_repository_diagnostic validate-initial-pre-admission postcondition-failed
  [[ "$provider_present" == true ]] || {
    printf 'ERROR: required final repositories are missing without a reviewed provider bootstrap repository.\n' >&2
    return 1
  }
  if ! read_repository_ids observe-available-repository-definitions --all "$available_repository_definition_max"; then
    return 1
  fi
  available_repos=("${REPLY[@]}")
  for repository in "${final_repositories[@]}"; do
    set_repository_diagnostic validate-required-repository-definitions required-repository-definition-unavailable "$repository"
    contains_repository "$repository" "${available_repos[@]}" || {
      printf 'ERROR: a required Rocky repository definition is unavailable.\n' >&2
      return 1
    }
  done
  set_repository_diagnostic install-repository-management-prerequisite package-transaction-failed
  dnf4 --assumeyes --releasever=10 --disablerepo='*' \
    --enablerepo=baseos,appstream,extras install dnf-plugins-core
  missing_before_enable=("${repository_missing[@]}")
  clear_repository_failure
  for repository in "${missing_before_enable[@]}"; do
    set_repository_diagnostic enable-required-rocky-repository repository-mutation-failed "$repository"
    dnf4 config-manager --set-enabled "$repository"
  done
  if ! observe_enabled_repositories observe-normalized-pre-removal-state pre-admission; then
    return 1
  fi
  set_repository_diagnostic validate-normalized-pre-removal-state postcondition-failed
  [[ "${#repository_unexpected[@]}" -eq 0 && "${#repository_missing[@]}" -eq 0 ]] || {
    printf 'ERROR: required final repositories are not all enabled before provider repository removal.\n' >&2
    return 1
  }
  enabled_before_disable=("${repository_enabled[@]}")
  clear_repository_failure
  for repository in "${provider_repositories[@]}"; do
    if contains_repository "$repository" "${enabled_before_disable[@]}"; then
      set_repository_diagnostic disable-reviewed-provider-repository repository-mutation-failed "$repository"
      dnf4 config-manager --set-disabled "$repository"
    fi
  done
  if ! observe_enabled_repositories observe-final-repository-state final-admission; then
    return 1
  fi
  set_repository_diagnostic validate-final-repository-state postcondition-failed
  [[ "${#repository_unexpected[@]}" -eq 0 && "${#repository_missing[@]}" -eq 0 && "${#repository_enabled[@]}" -eq "${#final_repositories[@]}" ]] || {
    printf 'ERROR: final enabled repositories must be exactly appstream,baseos,extras.\n' >&2
    return 1
  }
  clear_repository_failure
}

install_policy() {
  current_phase="guest-identity"
  assert_guest_identity
  current_phase="repositories"
  admit_repositories
  current_phase="packages"
  dnf4 --assumeyes --releasever=10 --disablerepo='*' \
    --enablerepo=baseos,appstream,extras install \
    podman conmon crun netavark aardvark-dns passt shadow-utils-subid systemd \
    container-selinux audit policycoreutils policycoreutils-python-utils \
    selinux-policy-targeted curl dnf git jq nftables openssh-server sudo \
    python3-jsonschema dnf-plugins-core
  current_phase="guest-identity"
  assert_guest_identity
  current_phase="selinux"
  [[ "$(getenforce)" == Enforcing ]]
  sestatus | grep -Eq '^Loaded policy name:[[:space:]]+targeted$'

  systemctl disable --now dnf-automatic.timer dnf-automatic-install.timer \
    dnf-automatic-download.timer dnf-automatic-notifyonly.timer 2>/dev/null || true
  systemctl mask podman.socket podman.service

  current_phase="runtime-account"
  if ! getent passwd "$runtime_account" >/dev/null; then
    useradd --system --user-group --create-home \
      --shell /usr/sbin/nologin "$runtime_account"
  fi
  usermod --shell /usr/sbin/nologin "$runtime_account"
  [[ "$(id -Gn "$runtime_account")" == "$runtime_account" ]]
  current_phase="subids"
  configure_subids
  current_phase="systemd-user"
  loginctl enable-linger "$runtime_account"
  local runtime_uid
  runtime_uid="$(id -u "$runtime_account")"
  current_phase="quadlet-authority"
  install -d -o root -g root -m 0755 "/etc/containers/systemd/users/$runtime_uid"
  if run_as_runtime test -w "/etc/containers/systemd/users/$runtime_uid"; then
    printf 'ERROR: runtime account can write administrator Quadlet authority.\n' >&2
    exit 1
  fi
  systemctl start "user@$runtime_uid.service"
  run_as_runtime systemctl --user mask podman.socket podman.service
  current_phase="fixture"
  run_as_runtime podman pull "$fixture"
  run_as_runtime podman image exists "$fixture"
  resolved_child="$(run_as_runtime podman image inspect --format '{{.Digest}}' "$fixture")"
  [[ "$resolved_child" == "$arm_child" ]]

  cat >/etc/sudoers.d/secpal-cloud-rocky <<'SECPAL_CLOUD_SUDO'
secpal-cloud ALL=(root) NOPASSWD: /usr/local/sbin/secpal-run-rocky-target-qualification [0-9a-f]*
SECPAL_CLOUD_SUDO
  chown root:root /etc/sudoers.d/secpal-cloud-rocky
  chmod 0440 /etc/sudoers.d/secpal-cloud-rocky
  visudo --check --file=/etc/sudoers.d/secpal-cloud-rocky

  current_phase="pre-reboot"
  install -d -o root -g secpal-cloud -m 0710 "$state_root"
  cat /proc/sys/kernel/random/boot_id >"$state_root/first-boot-id"
  chmod 0600 "$state_root/first-boot-id"
  install -o root -g root -m 0600 /dev/null "$state_root/reboot-pending"
  if ! systemctl reboot; then
    return 1
  fi
  reboot_requested=true
  exit 0
}

collect_after_reboot() {
  current_phase="post-reboot-identity"
  assert_guest_identity
  current_phase="post-reboot-selinux"
  [[ "$(getenforce)" == Enforcing ]]
  [[ -f "$state_root/reboot-pending" ]]
  [[ "$(cat "$state_root/first-boot-id")" != "$(cat /proc/sys/kernel/random/boot_id)" ]]
  rm -f -- "$state_root/reboot-pending"

  # The target must not be able to reach any metadata credential endpoint.
  current_phase="cloud-identity"
  block_metadata_credentials
  if curl --noproxy '*' --fail --silent --max-time 2 \
    -H 'Metadata-Flavor: Google' \
    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
    >/dev/null 2>&1; then
    printf 'ERROR: metadata credentials remain reachable.\n' >&2
    exit 1
  fi
  [[ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]
  [[ -z "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]

  current_phase="evidence-collection"
  /usr/local/sbin/secpal-collect-rocky-preparation \
    --target-sha "$target_sha" \
    --control-sha "$control_sha" \
    --run-id "$run_id" \
    --run-attempt "$run_attempt" \
    --expires-at "$expires_at" \
    --image "$image_self_link" \
    --first-boot-id "$(cat "$state_root/first-boot-id")" \
    --output "$evidence_output"
  current_phase="evidence-validation"
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-evidence preparation "$evidence_output"
  chown root:secpal-cloud "$evidence_output"
  chmod 0440 "$evidence_output"
  install -o root -g root -m 0600 /dev/null "$state_root/prepared"
}

prepare_evidence_transport
if [[ -e "$state_root/prepared" ]]; then
  current_phase="guest-identity"
  assert_guest_identity
  current_phase="cloud-identity"
  block_metadata_credentials
elif [[ -e "$state_root/reboot-pending" ]]; then
  collect_after_reboot
else
  install_policy
fi
