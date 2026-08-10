#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ ! "${SECPAL_TARGET_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'ERROR: target conformance requires a validated full commit SHA.\n' >&2
  exit 1
fi

actual_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ "$actual_sha" != "$SECPAL_TARGET_SHA" ]]; then
  printf 'ERROR: checked-out commit does not equal the selected target SHA.\n' >&2
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

timeout --signal=TERM --kill-after=15s 8m \
  python3 tests/production-contract-regressions.py
timeout --signal=TERM --kill-after=15s 8m \
  python3 tests/production-inventory-contract.py
timeout --signal=TERM --kill-after=15s 3m \
  bash tests/production-host-contract.sh

printf 'Exact target SHA completed the bounded production-host contract suite.\n'
