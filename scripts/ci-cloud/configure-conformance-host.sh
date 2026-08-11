#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

diagnostic_dir=/run/secpal-ci-evidence
failure_writer=/usr/local/sbin/secpal-ci-host-setup-failure
staged_ssh_public_key=/run/secpal-ci-authorized-key
active_ssh_authorized_keys_dir=/run/secpal-ci-authorized-keys
active_ssh_authorized_keys="$active_ssh_authorized_keys_dir/secpal-ci"
runner_ipv4="${1:-}"
setup_stage="initialize"
snapshot_tmp=""
ssh_key_activated=false

is_ipv4() {
  local value="$1" octet
  local -a octets

  IFS=. read -r -a octets <<<"$value"
  [[ "${#octets[@]}" -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

validate_staged_operator_key() {
  local metadata owner_uid owner_gid file_mode file_size
  local key_type key_data key_comment key_extra

  if [[ ! -f "$staged_ssh_public_key" || -L "$staged_ssh_public_key" ]]; then
    printf 'ERROR: staged operator SSH key is not a regular file.\n' >&2
    return 1
  fi
  if ! metadata="$(stat -c '%u:%g:%a:%s' -- "$staged_ssh_public_key")"; then
    printf 'ERROR: unable to inspect staged operator SSH key.\n' >&2
    return 1
  fi
  IFS=: read -r owner_uid owner_gid file_mode file_size <<<"$metadata"
  if [[ "$owner_uid" != 0 || "$owner_gid" != 0 || "$file_mode" != 600 ||
    ! "$file_size" =~ ^[1-9][0-9]{0,2}$ ]] || ((file_size > 512)); then
    printf 'ERROR: staged operator SSH key has unsafe metadata.\n' >&2
    return 1
  fi
  if [[ "$(wc -l <"$staged_ssh_public_key")" -ne 1 ]]; then
    printf 'ERROR: staged operator SSH key must contain exactly one line.\n' >&2
    return 1
  fi
  IFS=' ' read -r key_type key_data key_comment key_extra \
    <"$staged_ssh_public_key"
  if [[ "$key_type" != ssh-ed25519 ||
    ! "$key_data" =~ ^[A-Za-z0-9+/]+={0,2}$ ||
    -z "$key_comment" || -n "$key_extra" ]]; then
    printf 'ERROR: staged operator SSH key is outside the closed format.\n' >&2
    return 1
  fi
  if ! ssh-keygen -l -E sha256 -f "$staged_ssh_public_key" >/dev/null; then
    printf 'ERROR: staged operator SSH key is invalid.\n' >&2
    return 1
  fi
}

validate_effective_sshd_config() {
  local context effective_config expected keyword route_context local_ipv4

  if ! route_context="$(ip -o -4 route get "$runner_ipv4")"; then
    printf 'ERROR: unable to resolve the SSH listener address.\n' >&2
    return 1
  fi
  if [[ ! "$route_context" =~ (^|[[:space:]])src[[:space:]]+([^[:space:]]+) ]]; then
    printf 'ERROR: SSH route omitted the listener address.\n' >&2
    return 1
  fi
  local_ipv4="${BASH_REMATCH[2]}"
  if ! is_ipv4 "$local_ipv4"; then
    printf 'ERROR: resolved SSH listener address is invalid.\n' >&2
    return 1
  fi
  local -a contexts=(
    "user=secpal-ci,host=$runner_ipv4,addr=$runner_ipv4,laddr=$local_ipv4,lport=22"
    "user=root,host=$runner_ipv4,addr=$runner_ipv4,laddr=$local_ipv4,lport=22"
  )
  local -a expected_settings=(
    "allowusers secpal-ci"
    "authenticationmethods publickey"
    "authorizedkeyscommand none"
    "authorizedkeysfile /run/secpal-ci-authorized-keys/%u"
    "authorizedprincipalscommand none"
    "authorizedprincipalsfile none"
    "kbdinteractiveauthentication no"
    "passwordauthentication no"
    "permitrootlogin no"
    "pubkeyauthentication yes"
    "trustedusercakeys none"
    "usedns no"
  )

  if ! sshd -t; then
    printf 'ERROR: refusing to activate SSH with invalid daemon configuration.\n' >&2
    return 1
  fi
  for context in "${contexts[@]}"; do
    if ! effective_config="$(sshd -T -C "$context")"; then
      printf 'ERROR: unable to inspect the effective SSH configuration.\n' >&2
      return 1
    fi
    for expected in "${expected_settings[@]}"; do
      keyword="${expected%% *}"
      if [[ "$(grep -Ec "^${keyword} " <<<"$effective_config")" -ne 1 ]] ||
        ! grep -Fqx -- "$expected" <<<"$effective_config"; then
        printf 'ERROR: effective SSH configuration violates %s.\n' \
          "$keyword" >&2
        return 1
      fi
    done
  done
}

activate_operator_ssh() {
  local authorized_keys_tmp_dir directory_metadata installed_metadata

  if [[ "$ssh_key_activated" == true ]]; then
    return 0
  fi
  validate_staged_operator_key || return 1
  validate_effective_sshd_config || return 1
  if [[ -e "$active_ssh_authorized_keys_dir" ||
    -L "$active_ssh_authorized_keys_dir" ]]; then
    printf 'ERROR: operator authorized-keys path already exists.\n' >&2
    return 1
  fi
  if ! authorized_keys_tmp_dir="$(
    mktemp -d /run/.secpal-ci-authorized-keys.XXXXXX
  )"; then
    printf 'ERROR: unable to stage the operator authorized keys.\n' >&2
    return 1
  fi
  if ! install -o root -g root -m 0600 \
    "$staged_ssh_public_key" "$authorized_keys_tmp_dir/secpal-ci"; then
    rm -f -- "$authorized_keys_tmp_dir/secpal-ci"
    rmdir -- "$authorized_keys_tmp_dir" || true
    printf 'ERROR: unable to install the operator SSH key.\n' >&2
    return 1
  fi
  if ! directory_metadata="$(
    stat -c '%u:%g:%a' -- "$authorized_keys_tmp_dir"
  )" || ! installed_metadata="$(
    stat -c '%u:%g:%a' -- "$authorized_keys_tmp_dir/secpal-ci"
  )"; then
    rm -f -- "$authorized_keys_tmp_dir/secpal-ci"
    rmdir -- "$authorized_keys_tmp_dir" || true
    printf 'ERROR: unable to inspect the installed operator SSH key.\n' >&2
    return 1
  fi
  if [[ "$directory_metadata" != 0:0:700 ||
    "$installed_metadata" != 0:0:600 ]] ||
    ! cmp -s -- "$staged_ssh_public_key" \
      "$authorized_keys_tmp_dir/secpal-ci"; then
    rm -f -- "$authorized_keys_tmp_dir/secpal-ci"
    rmdir -- "$authorized_keys_tmp_dir" || true
    printf 'ERROR: installed operator SSH key failed verification.\n' >&2
    return 1
  fi
  if ! mv -T -- "$authorized_keys_tmp_dir" \
    "$active_ssh_authorized_keys_dir"; then
    rm -f -- "$authorized_keys_tmp_dir/secpal-ci"
    rmdir -- "$authorized_keys_tmp_dir" || true
    printf 'ERROR: unable to publish the operator SSH key atomically.\n' >&2
    return 1
  fi
  if ! chmod 0644 "$active_ssh_authorized_keys" ||
    ! chmod 0755 "$active_ssh_authorized_keys_dir"; then
    rm -f -- "$active_ssh_authorized_keys"
    rmdir -- "$active_ssh_authorized_keys_dir" || true
    printf 'ERROR: unable to expose the operator authorized keys safely.\n' >&2
    return 1
  fi
  if ! directory_metadata="$(
    stat -c '%u:%g:%a' -- "$active_ssh_authorized_keys_dir"
  )" || ! installed_metadata="$(
    stat -c '%u:%g:%a' -- "$active_ssh_authorized_keys"
  )" || [[ "$directory_metadata" != 0:0:755 ||
    "$installed_metadata" != 0:0:644 ]]; then
    rm -f -- "$active_ssh_authorized_keys"
    rmdir -- "$active_ssh_authorized_keys_dir" || true
    printf 'ERROR: published operator SSH key has unsafe metadata.\n' >&2
    return 1
  fi
  if ! systemctl unmask --runtime ssh.service ssh.socket ||
    ! systemctl restart ssh.service; then
    rm -f -- "$active_ssh_authorized_keys"
    rmdir -- "$active_ssh_authorized_keys_dir" || true
    printf 'ERROR: unable to activate the trusted SSH configuration.\n' >&2
    return 1
  fi
  if ! rm -f -- "$staged_ssh_public_key"; then
    rm -f -- "$active_ssh_authorized_keys"
    rmdir -- "$active_ssh_authorized_keys_dir" || true
    printf 'ERROR: unable to remove the staged operator SSH key.\n' >&2
    return 1
  fi
  ssh_key_activated=true
}

record_setup_failure() {
  local status=$?
  trap - EXIT
  set +e
  [[ -z "$snapshot_tmp" ]] || rm -f -- "$snapshot_tmp"
  if [[ "$status" -ne 0 ]]; then
    "$failure_writer" write "$setup_stage" "$status" || true
    activate_operator_ssh || true
  fi
  exit "$status"
}

trap record_setup_failure EXIT
if [[ "$#" -ne 1 ]] || ! is_ipv4 "$runner_ipv4"; then
  printf 'ERROR: trusted runner IPv4 context is invalid.\n' >&2
  exit 1
fi
install -d -o root -g root -m 0755 "$diagnostic_dir"
rm -f -- "$diagnostic_dir/host-setup-failure.json"
install -d -o root -g root -m 0755 /etc/containers/systemd/users/20000
install -d -o secpal-ci -g secpal-ci -m 0700 /srv/secpal-ci
if [[ "$(id -G secpal-ci)" != "$(id -g secpal-ci)" ]]; then
  printf 'ERROR: disposable operator has unexpected supplementary groups.\n' >&2
  exit 1
fi

normalize_subordinate_ids() {
  local database="$1"
  local add_option="$2"
  local delete_option="$3"
  local label="$4"
  local identity_database="$5"
  local line account start count start_value count_value end_value range
  local identities identity_name identity identity_value
  local -a existing_ranges=()

  if [[ ! -e "$database" ]]; then
    install -o root -g root -m 0644 /dev/null "$database"
  elif [[ ! -f "$database" || -L "$database" ]]; then
    printf 'ERROR: subordinate %s database is not a regular file.\n' "$label" >&2
    exit 1
  fi

  if ! identities="$(getent "$identity_database")"; then
    printf 'ERROR: unable to read the host %s identity database.\n' "$label" >&2
    exit 1
  fi
  while IFS=: read -r identity_name _ identity _; do
    if [[ -z "$identity_name" || ! "$identity" =~ ^[0-9]{1,10}$ ]]; then
      printf 'ERROR: host %s identity database is malformed.\n' "$label" >&2
      exit 1
    fi
    identity_value=$((10#$identity))
    if ((identity_value > 4294967295)); then
      printf 'ERROR: host %s identity exceeds the ID space.\n' "$label" >&2
      exit 1
    elif ((identity_value >= 200000 && identity_value <= 265535)); then
      printf 'ERROR: fixed secpal-ci range overlaps a host identity in %s.\n' \
        "$label" >&2
      exit 1
    fi
  done <<<"$identities"

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] || continue
    if [[ ! "$line" =~ ^([^:]+):([1-9][0-9]{0,9}):([1-9][0-9]{0,9})$ ]]; then
      printf 'ERROR: subordinate %s database contains a malformed range.\n' \
        "$label" >&2
      exit 1
    fi
    account="${BASH_REMATCH[1]}"
    start="${BASH_REMATCH[2]}"
    count="${BASH_REMATCH[3]}"
    start_value=$((10#$start))
    count_value=$((10#$count))
    if ((start_value > 4294967295 || count_value > 4294967296 - start_value)); then
      printf 'ERROR: subordinate %s database range exceeds the ID space.\n' \
        "$label" >&2
      exit 1
    fi
    end_value=$((start_value + count_value - 1))
    if [[ "$account" == secpal-ci ]]; then
      existing_ranges+=("$start_value-$end_value")
    elif ((start_value <= 265535 && end_value >= 200000)); then
      printf 'ERROR: subordinate %s range overlaps the fixed secpal-ci range.\n' \
        "$label" >&2
      exit 1
    fi
  done <"$database"

  if [[ "${#existing_ranges[@]}" -eq 1 &&
    "${existing_ranges[0]}" == 200000-265535 ]]; then
    return
  fi
  for range in "${existing_ranges[@]}"; do
    usermod "$delete_option" "$range" secpal-ci
  done
  usermod "$add_option" 200000-265535 secpal-ci
  if [[ "$(grep -Ec '^secpal-ci:' "$database" || true)" -ne 1 ]] ||
    ! grep -Fqx 'secpal-ci:200000:65536' "$database"; then
    printf 'ERROR: unable to normalize the subordinate %s range.\n' "$label" >&2
    exit 1
  fi
}

setup_stage="subordinate-ids"
normalize_subordinate_ids /etc/subuid --add-subuids --del-subuids UID passwd
normalize_subordinate_ids /etc/subgid --add-subgids --del-subgids GID group

setup_stage="service-policy"
systemctl --global disable \
  podman.socket podman.service podman-auto-update.timer || true
systemctl disable --now podman.socket podman.service || true
loginctl enable-linger secpal-ci

setup_stage="apparmor"
systemctl enable --now apparmor.service
apparmor_status_path=/run/secpal-ci-evidence/apparmor-status
evidence_dir="${apparmor_status_path%/*}"
snapshot_tmp="$(mktemp "$evidence_dir/.apparmor-status.XXXXXX")"
loaded_profiles="$(aa-status --profiled)"
enforcing_profiles="$(aa-status --enforced)"
if [[ ! "$loaded_profiles" =~ ^[0-9]+$ ||
  ! "$enforcing_profiles" =~ ^[0-9]+$ ||
  "$enforcing_profiles" -gt "$loaded_profiles" ]]; then
  printf 'ERROR: unable to capture bounded AppArmor policy counts.\n' >&2
  exit 1
fi
printf 'loaded_profiles=%s\nenforcing_profiles=%s\n' \
  "$loaded_profiles" "$enforcing_profiles" >"$snapshot_tmp"
install -o root -g root -m 0644 \
  "$snapshot_tmp" "$apparmor_status_path"
rm -f -- "$snapshot_tmp"
snapshot_tmp=""

setup_stage="ssh"
activate_operator_ssh
trap - EXIT
