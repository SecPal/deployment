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

if [ "${1:-}" = version ] && [ "${2:-}" = --format ]; then
  printf '26.1.0\n'
  exit 0
fi

docker_auth_config_state='unset'
if [ "${DOCKER_AUTH_CONFIG+x}" = x ]; then
  docker_auth_config_state='set'
fi

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "${SECPAL_TEST_RUN_ID:-unknown}" \
  '' \
  "${SECPAL_PHASE_B_FRONTEND_IMAGE:-}" \
  "${SECPAL_PHASE_B_GATEWAY_IMAGE:-}" \
  "${SECPAL_PHASE_B_HASH_CHAIN_CONTAINER_NAME:-}" \
  "${SECPAL_PHASE_B_SCHEDULER_CONTAINER_NAME:-}" \
  "$*" \
  "${DOCKER_CONFIG:-}" \
  "$docker_auth_config_state" >>"${SECPAL_TEST_COMMAND_LOG:?}"

if [ "${1:-}" = pull ]; then
  if [ "$*" != 'pull ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e' ] ||
    [ -z "${DOCKER_CONFIG:-}" ] || [ ! -d "$DOCKER_CONFIG" ] ||
    [ "$DOCKER_CONFIG" = "${HOME:-}/.docker" ] ||
    { [ -n "${SECPAL_TEST_PERSISTENT_DOCKER_CONFIG:-}" ] &&
      [ "$DOCKER_CONFIG" = "$SECPAL_TEST_PERSISTENT_DOCKER_CONFIG" ]; } ||
    [ "$(stat -c '%a' "$DOCKER_CONFIG")" != 700 ] ||
    find "$DOCKER_CONFIG" -mindepth 1 -print -quit | grep -q . ||
    [ "${DOCKER_AUTH_CONFIG+x}" = x ]; then
    exit 75
  fi
  if [ "${SECPAL_TEST_FAIL_PULL:-0}" -eq 1 ]; then
    exit 76
  fi
  exit 0
fi

if [[ " $* " == *" up --detach api worker-hash-chain worker-general scheduler frontend gateway "* ]] &&
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
  *" ps --status running --quiet worker-hash-chain "*)
    printf '%s\n' "${SECPAL_TEST_RUN_ID:-unknown}-hash-chain"
    ;;
  *" ps --status running --quiet scheduler "*)
    printf '%s\n' "${SECPAL_TEST_RUN_ID:-unknown}-scheduler"
    ;;
esac

case " $* " in
  *" exec -T worker-general hostname "*)
    printf '%s\n' "${SECPAL_TEST_RUN_ID:-unknown}-general"
    ;;
  *" exec -T worker-hash-chain hostname "*)
    printf '%s\n' "${SECPAL_TEST_RUN_ID:-unknown}-hash-chain"
    ;;
  *" exec -T worker-general cat /app/storage/app/private/phase-b-storage-probe-"*)
    probe_path="${!#}"
    printf '%s\n' "${probe_path##*/}"
    ;;
  *" exec -T worker-hash-chain stat -c %u:%g:%a /app/storage/app/private/phase-b-storage-probe-"*)
    printf '10001:10001:640\n'
    ;;
esac

if [[ " $* " == *"phase-b-runtime-probe.php cache-get phase-b-cache-"* ]] &&
  [[ " $* " =~ phase-b-cache-([a-z0-9]+) ]]; then
  printf 'phase-b-cache-value-%s' "${BASH_REMATCH[1]}"
elif [[ " $* " == *"phase-b-runtime-probe.php cache-get phase-b-queue-general-"* ]]; then
  printf '%s-general' "${SECPAL_TEST_RUN_ID:-unknown}"
elif [[ " $* " == *"phase-b-runtime-probe.php cache-get phase-b-queue-hash-chain-"* ]]; then
  printf '%s-hash-chain' "${SECPAL_TEST_RUN_ID:-unknown}"
fi

if [[ " $* " == *"phase-b-queue-general"* ]] && [ "${SECPAL_TEST_FAIL_QUEUE:-0}" -eq 1 ]; then
  exit 71
fi

if [[ " $* " == *"phase-b-storage-probe"* ]] && [ "${SECPAL_TEST_FAIL_STORAGE:-0}" -eq 1 ]; then
  exit 72
fi
