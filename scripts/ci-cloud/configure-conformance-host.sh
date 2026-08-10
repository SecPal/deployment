#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

install -d -o root -g root -m 0755 /etc/containers/systemd/users/20000
install -d -o secpal-ci -g secpal-ci -m 0700 /srv/secpal-ci

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

normalize_subordinate_ids /etc/subuid --add-subuids --del-subuids UID passwd
normalize_subordinate_ids /etc/subgid --add-subgids --del-subgids GID group

systemctl --global disable \
  podman.socket podman.service podman-auto-update.timer || true
systemctl disable --now podman.socket podman.service || true
loginctl enable-linger secpal-ci
systemctl enable --now apparmor.service

apparmor_status_path=/run/secpal-ci-evidence/apparmor-status
evidence_dir="${apparmor_status_path%/*}"
install -d -o root -g root -m 0755 "$evidence_dir"
snapshot_tmp="$(mktemp "$evidence_dir/.apparmor-status.XXXXXX")"
trap 'rm -f -- "$snapshot_tmp"' EXIT
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
trap - EXIT

sshd -t
systemctl restart ssh.service
