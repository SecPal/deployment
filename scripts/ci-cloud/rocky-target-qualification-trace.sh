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
  local frame
  local frames=""
  local frame_count=0
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
    fi
  done
  printf 'SECPAL_TARGET_ERR_V2:%s:%s\n' "$status" "$frames" >&3
  return "$status"
}

if { : >&3; } 2>/dev/null; then
  trap secpal_target_qualification_err ERR
fi
