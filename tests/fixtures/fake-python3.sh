#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "${1:-}" = */scripts/fetch-oci-attestation.py ]]; then
  subject_path="${2:?}"
  bundle_path="${3:?}"
  canonical_image="${4:?}"
  canonical_digest="${5:?}"
  expected_registry_path="${6:?}"
  image_kind=
  case "$canonical_image $canonical_digest $expected_registry_path" in
    'ghcr.io/secpal/api sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e secpal/api')
      image_kind=API
      ;;
    'ghcr.io/secpal/frontend sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077 secpal/frontend')
      image_kind=FRONTEND
      ;;
    *)
      printf 'fixture rejected an unreviewed OCI identity\n' >&2
      exit 79
      ;;
  esac
  printf '%s\t\t\t\t\t\tpython3 fetch-oci-attestation %s %s %s %s %s\t%s\t%s\n' \
    "${SECPAL_TEST_RUN_ID:-unknown}" \
    "$subject_path" \
    "$bundle_path" \
    "$canonical_image" \
    "$canonical_digest" \
    "$expected_registry_path" \
    "${DOCKER_CONFIG:-}" \
    "${GH_CONFIG_DIR:-}" >>"${SECPAL_TEST_COMMAND_LOG:?}"
  if [ "${SECPAL_TEST_FAIL_ATTESTATION_FETCH:-0}" -eq 1 ]; then
    printf 'fixture rejected the anonymous OCI attestation fetch\n' >&2
    exit 80
  fi
  failure_variable="SECPAL_TEST_FAIL_${image_kind}_ATTESTATION_FETCH"
  if [ "${!failure_variable:-0}" -eq 1 ]; then
    printf 'fixture rejected the anonymous %s OCI attestation fetch\n' "${image_kind,,}" >&2
    exit 80
  fi
  (umask 077 && printf '{"fixture":"oci-index"}\n' >"$subject_path")
  (umask 077 && printf '{"fixture":"offline-attestation"}\n' >"$bundle_path")
  chmod 0600 "$subject_path" "$bundle_path"
  exit 0
fi

exec /usr/bin/python3 "$@"
