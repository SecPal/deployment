#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [ "${1:-}" = compose ] && [ "${2:-}" = version ]; then
  if [ "${SECPAL_TEST_DOCKER_COMPOSE_V2:-1}" -ne 1 ]; then
    exit 1
  fi
  printf 'Docker Compose version v2.26.1\n'
  exit 0
fi

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "${SECPAL_TEST_RUN_ID:-unknown}" \
  "${SECPAL_PHASE_B_API_IMAGE:-}" \
  "${SECPAL_PHASE_B_FRONTEND_IMAGE:-}" \
  "${SECPAL_PHASE_B_GATEWAY_IMAGE:-}" \
  "${SECPAL_PHASE_B_FORENSICS_CONTAINER_NAME:-}" \
  "${SECPAL_PHASE_B_SCHEDULER_CONTAINER_NAME:-}" \
  "$*" >>"${SECPAL_TEST_COMMAND_LOG:?}"

if [[ " $* " == *" up --detach api worker-default worker-forensics scheduler frontend gateway "* ]] &&
  [ -n "${SECPAL_TEST_PORT_ATTEMPT_LOG:-}" ]; then
  printf '%s\n' "${SECPAL_PHASE_B_PORT:-}" >>"$SECPAL_TEST_PORT_ATTEMPT_LOG"
  if [ -n "${SECPAL_TEST_FAIL_GATEWAY_ONCE_MARKER:-}" ] &&
    [ ! -e "$SECPAL_TEST_FAIL_GATEWAY_ONCE_MARKER" ]; then
    : >"$SECPAL_TEST_FAIL_GATEWAY_ONCE_MARKER"
    printf 'Error response from daemon: port is already allocated\n' >&2
    exit 75
  fi
fi

if [[ " $* " == *" up --detach postgres valkey "* ]] &&
  [ -n "${SECPAL_TEST_PAUSE_MARKER:-}" ]; then
  : >"$SECPAL_TEST_PAUSE_MARKER"
  while [ ! -e "${SECPAL_TEST_RELEASE_MARKER:?}" ]; do
    /usr/bin/sleep 0.01
  done
fi

case " $* " in
  *" ps --status running --quiet worker-forensics "*)
    printf '%s\n' "${SECPAL_TEST_RUN_ID:-unknown}-forensics"
    ;;
  *" ps --status running --quiet scheduler "*)
    printf '%s\n' "${SECPAL_TEST_RUN_ID:-unknown}-scheduler"
    ;;
esac
