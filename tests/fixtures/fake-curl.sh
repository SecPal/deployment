#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

url="${*: -1}"
printf '%s\t%s\n' "${SECPAL_TEST_RUN_ID:-unknown}" "$*" >>"${SECPAL_TEST_CURL_LOG:?}"

case "$url" in
  */health/live)
    printf '{"status":"alive"}\n'
    ;;
  */runtime-config.js)
    printf 'apiBaseUrl: "%s",\n' "${url%/runtime-config.js}"
    ;;
  */)
    printf '<!doctype html>\n'
    ;;
  *)
    exit 1
    ;;
esac
