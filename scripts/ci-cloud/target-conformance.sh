#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if ! [[ "$#" -eq 2 && "$1" == v1 ]]; then
  printf 'ERROR: target lifecycle requires protocol v1 and one closed phase.\n' >&2
  exit 64
fi
phase="$2"
case "$phase" in
  host | workload-prepare-start | workload-cleanup) ;;
  *)
    printf 'ERROR: target lifecycle phase is outside the closed interface.\n' >&2
    exit 64
    ;;
esac

readonly checkout=/home/secpal-ci/deployment-target
if [[ "$PWD" != "$checkout" ]]; then
  printf 'ERROR: target lifecycle did not start in the fixed checkout.\n' >&2
  exit 1
fi

if [[ ! "${SECPAL_TARGET_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'ERROR: target conformance requires a validated full commit SHA.\n' >&2
  exit 1
fi

actual_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ "$actual_sha" != "$SECPAL_TARGET_SHA" ]]; then
  printf 'ERROR: checked-out commit does not equal the selected target SHA.\n' >&2
  exit 1
fi

if [[ ! "${SECPAL_FIXTURE_INSTANCE:-}" =~ ^[0-9a-f]{12}$ ||
  "$SECPAL_FIXTURE_INSTANCE" != "${SECPAL_TARGET_SHA:0:12}" ]]; then
  printf 'ERROR: fixture instance is not derived from the selected target SHA.\n' >&2
  exit 1
fi

for forbidden_name in \
  DIGITALOCEAN_TOKEN DIGITALOCEAN_ACCESS_TOKEN \
  GOOGLE_APPLICATION_CREDENTIALS CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE \
  GH_TOKEN GITHUB_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN; do
  if [[ -v "$forbidden_name" ]]; then
    printf 'ERROR: cloud or GitHub credential environment reached target code.\n' >&2
    exit 1
  fi
done

run_host_contract_command() {
  local command_status
  local phase_timeout="$1"
  shift
  set +e
  timeout --signal=TERM --kill-after=15s "$phase_timeout" "$@"
  command_status=$?
  set -e
  if [[ "$command_status" -ne 0 ]]; then
    printf '%s%s:%s:%s\n' \
      'SECPAL_TARGET_DIAGNOSTIC_FAILURE_V1:' \
      'host-contract' 'command-exit' "$command_status" >&2
    return "$command_status"
  fi
}

case "$phase" in
  workload-prepare-start)
    printf 'SECPAL_TARGET_DIAGNOSTIC_V1:workload-target-entrypoint\n' >&2
    python3 scripts/quadlet-integration.py --cloud-phase prepare
    ;;
  workload-cleanup)
    printf 'SECPAL_TARGET_DIAGNOSTIC_V1:workload-cleanup\n' >&2
    python3 scripts/quadlet-integration.py --cloud-phase cleanup
    ;;
  host)
    printf 'SECPAL_TARGET_DIAGNOSTIC_V1:host-contract\n' >&2
    run_host_contract_command 8m \
      python3 tests/production-contract-regressions.py
    run_host_contract_command 8m \
      python3 tests/production-inventory-contract.py
    run_host_contract_command 3m \
      bash tests/production-host-contract.sh
    printf 'Exact target SHA completed the bounded production-host contract suite.\n'
    ;;
esac
