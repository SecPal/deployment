#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [ "${1:-}" = compose ] && [ "${2:-}" = version ]; then
  printf 'Docker Compose version v2.26.1\n'
  exit 0
fi

printf '%s\t%s\t%s\t%s\t%s\n' \
  "${SECPAL_TEST_RUN_ID:-unknown}" \
  "${SECPAL_PHASE_B_API_IMAGE:-}" \
  "${SECPAL_PHASE_B_FRONTEND_IMAGE:-}" \
  "${SECPAL_PHASE_B_GATEWAY_IMAGE:-}" \
  "$*" >>"${SECPAL_TEST_COMMAND_LOG:?}"

if [[ " $* " == *" up --detach postgres valkey "* ]] &&
  [ -n "${SECPAL_TEST_PAUSE_MARKER:-}" ]; then
  : >"$SECPAL_TEST_PAUSE_MARKER"
  while [ ! -e "${SECPAL_TEST_RELEASE_MARKER:?}" ]; do
    /usr/bin/sleep 0.01
  done
fi

if [[ " $* " == *" ps --status running --services "* ]]; then
  printf '%s\n' worker-forensics scheduler
fi
