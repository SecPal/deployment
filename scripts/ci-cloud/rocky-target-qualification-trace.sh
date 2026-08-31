#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# This file is sourced by Bash before the exact target-owned harness.  It does
# not alter target predicates or success.  It records only bounded numeric
# failure call stacks for negative diagnostic classification.  The closed V2
# record contains only one status and at most eight numeric source lines.

set -E

runuser() {
  local status
  if [[ "${SECPAL_START_EXACT_CALL:-}" == 1 ]]; then
    if [[ -z "${SECPAL_START_OBSERVATION_PATH:-}" ]] ||
      ! exec 6>"${SECPAL_START_OBSERVATION_PATH}"; then
      if /usr/sbin/runuser "$@"; then
        status=0
      else
        status=$?
      fi
    elif /opt/secpal-control/libexec/rocky-start-runuser "$@" 6>&6; then
      status=0
    else
      status=$?
    fi
    exec 6>&- 2>/dev/null || :
    unset SECPAL_START_EXACT_CALL
    unset SECPAL_START_OBSERVATION_PATH
    return "$status"
  elif [[ "${SECPAL_ACTIVE_EXACT_CALL:-}" == 1 ]]; then
    if [[ -z "${SECPAL_ACTIVE_OBSERVATION_PATH:-}" ]] ||
      ! exec 7>"${SECPAL_ACTIVE_OBSERVATION_PATH}"; then
      if /usr/sbin/runuser "$@"; then
        status=0
      else
        status=$?
      fi
    elif /opt/secpal-control/libexec/rocky-active-runuser "$@" 7>&7; then
      status=0
    else
      status=$?
    fi
    exec 7>&- 2>/dev/null || :
    unset SECPAL_ACTIVE_EXACT_CALL
    unset SECPAL_ACTIVE_OBSERVATION_PATH
    return "$status"
  elif [[ "${SECPAL_RELOAD_EXACT_CALL:-}" == 1 ]]; then
    if /opt/secpal-control/libexec/rocky-reload-runuser "$@"; then
      status=0
    else
      status=$?
    fi
    unset SECPAL_RELOAD_EXACT_CALL
    return "$status"
  else
    /opt/secpal-control/libexec/rocky-primary-runuser "$@"
  fi
}

secpal_reload_journal_cursor=unavailable
secpal_reload_run_space_bytes=unavailable
secpal_reload_audit_baseline=unavailable

secpal_reload_precall() {
  local available_blocks=""
  local block_size=""
  local cursor_output=""
  local timestamp=""
  if [[ "$BASHPID" == "$$" && "${SECPAL_RELOAD_EXACT_CALL:-}" == 1 ]]; then
    unset SECPAL_RELOAD_EXACT_CALL
  fi
  if [[ "$BASHPID" == "$$" && "${SECPAL_START_EXACT_CALL:-}" == 1 ]]; then
    unset SECPAL_START_EXACT_CALL
    unset SECPAL_START_OBSERVATION_PATH
  fi
  if [[ "$BASHPID" == "$$" && "${SECPAL_ACTIVE_EXACT_CALL:-}" == 1 ]]; then
    unset SECPAL_ACTIVE_EXACT_CALL
    unset SECPAL_ACTIVE_OBSERVATION_PATH
  fi
  if [[ "${BASH_LINENO[0]:-}" == 238 ]] &&
    [[ "$BASH_COMMAND" == "user_systemctl start \"\${unit_name}.service\"" ]]; then
    export SECPAL_START_EXACT_CALL=1
  elif [[ "${BASH_LINENO[0]:-}" == 239 ]] &&
    [[ "$BASH_COMMAND" == "user_systemctl is-active --quiet \"\${unit_name}.service\"" ]]; then
    export SECPAL_ACTIVE_EXACT_CALL=1
  elif [[ "${BASH_LINENO[0]:-}" == 237 ]] &&
    [[ "$BASH_COMMAND" == "user_systemctl daemon-reload" ]]; then
    trap - DEBUG
    export SECPAL_RELOAD_EXACT_CALL=1
    if cursor_output="$(timeout --signal=KILL 2s journalctl --no-pager --quiet --show-cursor --lines=0 2>/dev/null)" &&
      [[ "$cursor_output" =~ ^--\ cursor:\ ([A-Za-z0-9=\;._-]{1,384})$ ]]; then
      secpal_reload_journal_cursor="${BASH_REMATCH[1]}"
    fi
    if read -r available_blocks block_size < <(
      timeout --signal=KILL 1s stat --file-system --format='%a %S' -- /run/systemd 2>/dev/null
    ) && [[ "$available_blocks" =~ ^[0-9]{1,16}$ ]] &&
      [[ "$block_size" =~ ^[1-9][0-9]{0,9}$ ]] &&
      ((10#$available_blocks <= 9223372036854775807 / 10#$block_size)); then
      secpal_reload_run_space_bytes=$((10#$available_blocks * 10#$block_size))
    fi
    if timestamp="$(timeout --signal=KILL 1s date -u '+%Y%m%d%H%M%S')" &&
      [[ "$timestamp" =~ ^[0-9]{14}$ ]]; then
      secpal_reload_audit_baseline="$timestamp"
    fi
    trap secpal_reload_precall DEBUG
  fi
  return 0
}

secpal_target_qualification_err() {
  local status=$?
  local adjacency_ack=""
  local daemon_reload_frame=false
  local frame
  local frames=""
  local frame_count=0
  trap - ERR
  unset SECPAL_RELOAD_EXACT_CALL
  unset SECPAL_START_EXACT_CALL
  unset SECPAL_ACTIVE_EXACT_CALL
  for frame in "${BASH_LINENO[@]}"; do
    if ((frame_count >= 8)); then
      break
    fi
    if [[ "$frame" =~ ^[0-9]{1,4}$ ]] && ((10#$frame >= 1 && 10#$frame <= 9999)); then
      if [[ -n "$frames" ]]; then
        frames+=,
      fi
      frames+="$frame"
      frame_count=$((frame_count + 1))
      if ((10#$frame == 237)); then
        daemon_reload_frame=true
      fi
    fi
  done
  if ! printf 'SECPAL_TARGET_ERR_V2:%s:%s\n' "$status" "$frames" >&3; then
    :
  fi
  if [[ "$daemon_reload_frame" == true ]] &&
    { : >&4; } 2>/dev/null && { : <&5; } 2>/dev/null; then
    if ! printf 'SECPAL_QUADLET_RELOAD_FAILURE_V3:%s:%s:%s:%s:%s:%s\n' \
      "$status" "$$" "$secpal_reload_run_space_bytes" \
      "$secpal_reload_audit_baseline" "$secpal_reload_journal_cursor" \
      "$frames" >&4; then
      :
    fi
    if ! IFS= read -r -t 25 -u 5 adjacency_ack; then
      :
    elif [[ ! "$adjacency_ack" =~ ^SECPAL_RELOAD_ADJACENCY_(CAPTURED|FAILED)_V1$ ]]; then
      :
    fi
  fi
  return "$status"
}

if { : >&3; } 2>/dev/null; then
  trap secpal_target_qualification_err ERR
fi
if { : >&4; } 2>/dev/null && { : <&5; } 2>/dev/null; then
  trap secpal_reload_precall DEBUG
fi
