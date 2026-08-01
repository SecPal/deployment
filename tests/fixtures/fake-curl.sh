#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

url="${*: -1}"
printf '%s\t%s\n' "${SECPAL_TEST_RUN_ID:-unknown}" "$*" >>"${SECPAL_TEST_CURL_LOG:?}"

output_path=
write_out=
previous=
for argument in "$@"; do
  case "$previous" in
    --output) output_path="$argument" ;;
    --write-out) write_out="$argument" ;;
  esac
  previous="$argument"
done

case "$url" in
  */health/live)
    printf '{"status":"alive"}\n'
    ;;
  */runtime-config.js)
    printf 'apiBaseUrl: "https://api.secpal.example.invalid:%s",\n' "${SECPAL_PHASE_B_PORT:?}"
    ;;
  */v1/auth/login)
    if [[ " $* " == *"Origin: https://app.secpal.example.invalid:"* ]]; then
      printf 'HTTP/2 204\r\naccess-control-allow-origin: https://app.secpal.example.invalid:%s\r\naccess-control-allow-credentials: true\r\n\r\n' "${SECPAL_PHASE_B_PORT:?}"
    else
      printf 'HTTP/2 204\r\n\r\n'
    fi
    ;;
  */v1/phase-b-not-an-api-route)
    if [ -n "$output_path" ] && [ "$output_path" != /dev/null ]; then
      printf 'not found\n' >"$output_path"
    fi
    if [ -n "$write_out" ]; then
      printf '404'
    fi
    ;;
  */)
    if [[ "$url" == https://api.secpal.example.invalid:* ]]; then
      printf '{"message":"not found"}\n'
    else
      printf '<!doctype html>\n'
    fi
    ;;
  *)
    exit 1
    ;;
esac
