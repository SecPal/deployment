#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
temporary_root="$(mktemp -d)"
trap 'rm -rf -- "$temporary_root"' EXIT

for signal_case in HUP:129 INT:130 TERM:143; do
  signal="${signal_case%%:*}"
  expected_status="${signal_case##*:}"
  fixture_root="${temporary_root}/fixture-${signal}"
  output="${temporary_root}/output-${signal}"
  mkdir -m 0700 "$fixture_root"
  set +e
  bash -c '
    source "$1/scripts/qualify-production-host.sh"
    fixture_root="$2"
    qualification_success_marker="${fixture_root}/qualification.success"
    unit_path=""
    container_a=""
    container_b=""
    unit_name=""
    dontaudit_disabled=false
    install_cleanup_traps
    printf "partial_step=PASS\n"
    :
    kill -s "$3" "$$"
    printf "PASS: Rocky Linux 10.2 target workload contract\n"
  ' _ "$ROOT_DIR" "$fixture_root" "$signal" >"$output" 2>&1
  status=$?
  set -e
  if [[ "$status" -ne "$expected_status" ]]; then
    printf 'FAIL: %s returned %s instead of %s\n' \
      "$signal" "$status" "$expected_status" >&2
    exit 1
  fi
  if [[ -e "$fixture_root" ]]; then
    printf 'FAIL: %s did not perform fixture cleanup\n' "$signal" >&2
    exit 1
  fi
  if grep -Fq 'PASS: Rocky Linux 10.2 target workload contract' "$output"; then
    printf 'FAIL: %s emitted the qualification success marker\n' "$signal" >&2
    exit 1
  fi
  if ! grep -Fxq 'partial_step=PASS' "$output"; then
    printf 'FAIL: %s did not interrupt after partial successful work\n' \
      "$signal" >&2
    exit 1
  fi
done

printf 'Rocky qualification signal contract passed for HUP, INT, and TERM.\n'
