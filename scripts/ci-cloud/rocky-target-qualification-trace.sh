#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# This file is sourced by Bash before the exact target-owned harness.  It does
# not alter target predicates or success.  It records only bounded numeric
# failure locations for negative diagnostic classification.
set -E

secpal_target_qualification_err() {
  local status=$?
  printf 'SECPAL_TARGET_ERR_V1:%s:%s\n' "${BASH_LINENO[0]}" "$status" >&3
  return "$status"
}

if { : >&3; } 2>/dev/null; then
  trap secpal_target_qualification_err ERR
fi
