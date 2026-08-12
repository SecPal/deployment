#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

state_root=/var/lib/secpal-ci-bootstrap
context_file="$state_root/context"
pending_file="$state_root/pending"
failure_writer=/usr/local/sbin/secpal-ci-host-setup-failure
continuation_service=secpal-ci-bootstrap-continue.service
continuation_unit="/etc/systemd/system/$continuation_service"
staged_operator_key=/run/secpal-ci-authorized-key
failure_marker_ready=false

continuation_failure() {
  local status=$?

  trap - EXIT
  set +e
  if [[ "$status" -ne 0 && "$failure_marker_ready" == true ]] &&
    ! "$failure_writer" read >/dev/null 2>&1; then
    "$failure_writer" write kernel-reboot "$status" || true
  fi
  exit "$status"
}

trap continuation_failure EXIT

validate_state_file() {
  local path="$1"
  local maximum_size="$2"
  local metadata

  [[ -f "$path" && ! -L "$path" ]] || return 1
  metadata="$(stat -c '%u:%g:%a:%s' -- "$path")" || return 1
  [[ "$metadata" =~ ^0:0:600:([1-9][0-9]{0,3})$ ]] || return 1
  ((10#${BASH_REMATCH[1]} <= maximum_size))
}

[[ -d "$state_root" && ! -L "$state_root" ]]
[[ "$(stat -c '%u:%g:%a' -- "$state_root")" == 0:0:700 ]]
validate_state_file "$context_file" 1024
validate_state_file "$pending_file" 256

mapfile -t context <"$context_file"
mapfile -t pending <"$pending_file"
[[ "${#context[@]}" -eq 4 && "${#pending[@]}" -eq 2 ]]

ssh_public_key="${context[0]}"
runner_ipv4="${context[1]}"
run_id="${context[2]}"
run_attempt="${context[3]}"
expected_kernel="${pending[0]}"
initial_boot_id="${pending[1]}"

[[ "$expected_kernel" =~ ^6\.12\.[0-9]+[-+._A-Za-z0-9]*$ ]]
[[ "$initial_boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]

install -d -o root -g root -m 0755 /run/secpal-ci-evidence
failure_marker_ready=true
systemctl disable "$continuation_service"
/usr/local/sbin/secpal-ci-install-diagnostic-ssh \
  "$ssh_public_key" "$runner_ipv4" "$run_id" "$run_attempt"

current_boot_id="$(< /proc/sys/kernel/random/boot_id)"
[[ "$current_boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]
[[ "$current_boot_id" != "$initial_boot_id" ]]
[[ "$(uname -r)" == "$expected_kernel" ]]

install -o root -g root -m 0600 /dev/null "$staged_operator_key"
printf '%s\n' "$ssh_public_key" >"$staged_operator_key"

/usr/local/sbin/secpal-ci-configure-conformance-host "$runner_ipv4"

trap - EXIT
rm -f -- "$pending_file" "$context_file" "$continuation_unit"
systemctl daemon-reload
rmdir -- "$state_root"
