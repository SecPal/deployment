#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# This file is sourced by Bash before the exact target-owned harness.  It does
# not alter target predicates or success.  It records only bounded numeric
# failure call stacks for negative diagnostic classification.  The closed V2
# record contains only one status and at most eight numeric source lines.
set -E

secpal_target_qualification_err() {
  local status=$?
  local adjacency_ack=""
  local daemon_reload_frame=false
  local frame
  local frames=""
  local frame_count=0
  trap - ERR
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
      if ((10#$frame == 242)); then
        daemon_reload_frame=true
      fi
    fi
  done
  if ! printf 'SECPAL_TARGET_ERR_V2:%s:%s\n' "$status" "$frames" >&3; then
    :
  fi
  if [[ "$daemon_reload_frame" == true ]] &&
    { : >&4; } 2>/dev/null && { : <&5; } 2>/dev/null; then
    if ! printf 'SECPAL_QUADLET_RELOAD_FAILURE_V1:%s:%s\n' \
      "$status" "$frames" >&4; then
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
