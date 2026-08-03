#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "${1:-}" = */scripts/fetch-oci-attestation.py ]]; then
  output_path="${2:?}"
  printf '%s\t\t\t\t\t\tpython3 fetch-oci-attestation %s\t%s\t%s\n' \
    "${SECPAL_TEST_RUN_ID:-unknown}" \
    "$output_path" \
    "${DOCKER_CONFIG:-}" \
    "${GH_CONFIG_DIR:-}" >>"${SECPAL_TEST_COMMAND_LOG:?}"
  if [ "${SECPAL_TEST_FAIL_ATTESTATION_FETCH:-0}" -eq 1 ]; then
    printf 'fixture rejected the anonymous OCI attestation fetch\n' >&2
    exit 80
  fi
  (umask 077 && printf '{"fixture":"offline-attestation"}\n' >"$output_path")
  chmod 0600 "$output_path"
  exit 0
fi

exec /usr/bin/python3 "$@"
