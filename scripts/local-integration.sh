#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
TEMP_DIR="$(mktemp -d -t secpal-phase-b.XXXXXXXXXX)"
project_token="${TEMP_DIR##*.}"
project_token="${project_token,,}"
PROJECT_NAME="secpal-phase-b-$project_token"
COMPOSE=()
LOCAL_IMAGES=()
cleanup_completed=0
automatic_port=0
PROBE_SCRIPT=/run/secpal/phase-b-runtime-probe.php

cleanup() {
  if [ "${#COMPOSE[@]}" -ne 0 ] && [ "$cleanup_completed" -ne 1 ]; then
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [ "${#LOCAL_IMAGES[@]}" -ne 0 ] && [ "$cleanup_completed" -ne 1 ]; then
    docker image rm "${LOCAL_IMAGES[@]}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TEMP_DIR"
}

handle_signal() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$2"
}

allocate_port() {
  python3 -c 'import socket; sock = socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()'
}

validate_port() {
  case "$SECPAL_PHASE_B_PORT" in
    '' | *[!0-9]*) fail "SECPAL_PHASE_B_PORT must be an integer from 1024 through 65535." ;;
  esac
  if [ "$SECPAL_PHASE_B_PORT" -lt 1024 ] || [ "$SECPAL_PHASE_B_PORT" -gt 65535 ]; then
    fail "SECPAL_PHASE_B_PORT must be an integer from 1024 through 65535."
  fi
}

set_origins() {
  APP_ORIGIN="https://app.secpal.example.invalid:$SECPAL_PHASE_B_PORT"
  API_ORIGIN="https://api.secpal.example.invalid:$SECPAL_PHASE_B_PORT"
  export APP_ORIGIN API_ORIGIN SECPAL_PHASE_B_PORT
}

wait_for_cache_value() {
  local key="$1"
  local expected="$2"
  local value
  local _attempt

  for _attempt in $(seq 1 60); do
    value="$("${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
      php "$PROBE_SCRIPT" cache-get "$key" 2>/dev/null || true)"
    if [ "$value" = "$expected" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

require_command docker "Docker is required."
require_command python3 "Python 3 is required."
require_command curl "curl is required."
require_command node "Node.js is required."
require_command npm "npm is required."

compose_version="$(docker compose version 2>/dev/null || true)"
case "$compose_version" in
  *" version v2."*) ;;
  *) fail "Docker Compose v2 is required." ;;
esac

node -e "require.resolve('@playwright/test')" >/dev/null 2>&1 ||
  fail "Local Playwright dependencies are missing; run npm ci first."
node -e "const fs=require('node:fs');const {chromium}=require('@playwright/test');fs.accessSync(chromium.executablePath())" \
  >/dev/null 2>&1 || fail "Playwright Chromium is not installed."

if [ -z "${SECPAL_PHASE_B_PORT:-}" ]; then
  automatic_port=1
  SECPAL_PHASE_B_PORT="$(allocate_port)"
fi
validate_port
set_origins

SECPAL_PHASE_B_API_IMAGE="$PROJECT_NAME-api:phase-b-6fead9cef910"
SECPAL_PHASE_B_FRONTEND_IMAGE="$PROJECT_NAME-frontend:phase-b-fcd427d9b55d"
SECPAL_PHASE_B_GATEWAY_IMAGE="$PROJECT_NAME-gateway:phase-b-2.10.2"
SECPAL_PHASE_B_HASH_CHAIN_CONTAINER_NAME="$PROJECT_NAME-worker-hash-chain"
SECPAL_PHASE_B_SCHEDULER_CONTAINER_NAME="$PROJECT_NAME-scheduler"
export \
  SECPAL_PHASE_B_API_IMAGE \
  SECPAL_PHASE_B_FRONTEND_IMAGE \
  SECPAL_PHASE_B_GATEWAY_IMAGE \
  SECPAL_PHASE_B_HASH_CHAIN_CONTAINER_NAME \
  SECPAL_PHASE_B_SCHEDULER_CONTAINER_NAME
LOCAL_IMAGES=(
  "$SECPAL_PHASE_B_API_IMAGE"
  "$SECPAL_PHASE_B_FRONTEND_IMAGE"
  "$SECPAL_PHASE_B_GATEWAY_IMAGE"
)
COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$ROOT_DIR/compose.yaml")

CACHE_PROBE_KEY="phase-b-cache-$project_token"
GENERAL_QUEUE_PROBE_KEY="phase-b-queue-general-$project_token"
HASH_QUEUE_PROBE_KEY="phase-b-queue-hash-chain-$project_token"
STORAGE_PROBE_NAME="phase-b-storage-probe-$project_token"
STORAGE_PROBE_PATH="/app/storage/app/private/$STORAGE_PROBE_NAME"

cd "$ROOT_DIR"

"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" build secrets-init frontend gateway
"${COMPOSE[@]}" up --detach postgres valkey
"${COMPOSE[@]}" --profile tools run --rm migrate

services_started=0
for _attempt in $(seq 1 3); do
  if "${COMPOSE[@]}" up --detach \
    api worker-hash-chain worker-general scheduler frontend gateway \
    >"$TEMP_DIR/service-start.log" 2>&1; then
    services_started=1
    break
  fi

  if [ "$automatic_port" -ne 1 ] ||
    ! grep -Eiq 'address already in use|port is already allocated|failed to bind host port|Bind for .* failed' \
      "$TEMP_DIR/service-start.log"; then
    sed -n '1,160p' "$TEMP_DIR/service-start.log" >&2
    fail "the local integration services could not be started."
  fi
  if [ "$_attempt" -eq 3 ]; then
    sed -n '1,160p' "$TEMP_DIR/service-start.log" >&2
    fail "an isolated loopback port could not be allocated after three attempts."
  fi

  previous_port="$SECPAL_PHASE_B_PORT"
  SECPAL_PHASE_B_PORT=""
  for _allocation_attempt in $(seq 1 10); do
    candidate_port="$(allocate_port)"
    if [ "$candidate_port" != "$previous_port" ]; then
      SECPAL_PHASE_B_PORT="$candidate_port"
      break
    fi
  done
  [ -n "$SECPAL_PHASE_B_PORT" ] || fail "a new isolated loopback port could not be selected."
  validate_port
  set_origins
done
[ "$services_started" -eq 1 ] || fail "the local integration services could not be started."

api_ready=0
frontend_ready=0
for _attempt in $(seq 1 90); do
  if curl --fail --silent --show-error --insecure \
    --noproxy api.secpal.example.invalid \
    --resolve "api.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
    "$API_ORIGIN/health/live" >"$TEMP_DIR/api-health.json" 2>/dev/null; then
    api_ready=1
  fi
  if curl --fail --silent --show-error --insecure \
    --noproxy app.secpal.example.invalid \
    --resolve "app.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
    "$APP_ORIGIN/health/live" >"$TEMP_DIR/frontend-health.json" 2>/dev/null; then
    frontend_ready=1
  fi
  if [ "$api_ready" -eq 1 ] && [ "$frontend_ready" -eq 1 ]; then
    break
  fi
  sleep 1
done
if [ "$api_ready" -ne 1 ] || [ "$frontend_ready" -ne 1 ]; then
  "${COMPOSE[@]}" ps >&2
  fail "the local test-only TLS origins did not become healthy."
fi
grep -Fq '"status":"alive"' "$TEMP_DIR/api-health.json" ||
  fail "the API liveness response did not satisfy the product contract."

curl --fail --silent --show-error --insecure \
  --noproxy app.secpal.example.invalid \
  --resolve "app.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$APP_ORIGIN/" >"$TEMP_DIR/frontend.html"
grep -Eiq '<!doctype html' "$TEMP_DIR/frontend.html" ||
  fail "the frontend was not served through its test-only TLS origin."

curl --fail --silent --show-error --insecure \
  --noproxy app.secpal.example.invalid \
  --resolve "app.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$APP_ORIGIN/runtime-config.js" >"$TEMP_DIR/runtime-config.js"
grep -Fq "apiBaseUrl: \"$API_ORIGIN\"," "$TEMP_DIR/runtime-config.js" ||
  fail "the frontend runtime API origin did not match the separate API origin."

cors_headers="$(curl --fail --silent --show-error --insecure --dump-header - --output /dev/null \
  --request OPTIONS \
  --header "Origin: $APP_ORIGIN" \
  --header 'Access-Control-Request-Method: POST' \
  --header 'Access-Control-Request-Headers: Content-Type,X-XSRF-TOKEN' \
  --noproxy api.secpal.example.invalid \
  --resolve "api.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$API_ORIGIN/v1/auth/login" | tr -d '\r')"
printf '%s\n' "$cors_headers" | grep -Fiqx "access-control-allow-origin: $APP_ORIGIN" ||
  fail "the API did not allow the exact frontend origin."
printf '%s\n' "$cors_headers" | grep -Fiqx 'access-control-allow-credentials: true' ||
  fail "the API did not enable credentialed CORS."
if printf '%s\n' "$cors_headers" | grep -Fiqx 'access-control-allow-origin: *'; then
  fail "credentialed CORS must never use a wildcard origin."
fi

foreign_headers="$(curl --silent --show-error --insecure --dump-header - --output /dev/null \
  --request OPTIONS \
  --header 'Origin: https://foreign.example.org' \
  --header 'Access-Control-Request-Method: POST' \
  --noproxy api.secpal.example.invalid \
  --resolve "api.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$API_ORIGIN/v1/auth/login" | tr -d '\r')"
if printf '%s\n' "$foreign_headers" | grep -Fiq 'access-control-allow-credentials: true'; then
  fail "a foreign origin received credentialed CORS approval."
fi

frontend_api_status="$(curl --silent --show-error --insecure \
  --output "$TEMP_DIR/frontend-api-route.out" \
  --write-out '%{http_code}' \
  --noproxy app.secpal.example.invalid \
  --resolve "app.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$APP_ORIGIN/v1/phase-b-not-an-api-route")"
[ "$frontend_api_status" = '404' ] ||
  fail "the frontend origin exposed an API-style route."
curl --silent --show-error --insecure --header 'Accept: application/json' \
  --noproxy api.secpal.example.invalid \
  --resolve "api.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$API_ORIGIN/" >"$TEMP_DIR/api-root.out" || true
if grep -Eiq '<!doctype html' "$TEMP_DIR/api-root.out"; then
  fail "the API origin returned the frontend SPA shell."
fi

cache_value="phase-b-cache-value-$project_token"
"${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
  php "$PROBE_SCRIPT" cache-put "$CACHE_PROBE_KEY" "$cache_value" >/dev/null
observed_cache_value="$("${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
  php "$PROBE_SCRIPT" cache-get "$CACHE_PROBE_KEY")"
[ "$observed_cache_value" = "$cache_value" ] || fail "the Valkey cache round trip failed."
"${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
  php "$PROBE_SCRIPT" cache-forget "$CACHE_PROBE_KEY" >/dev/null

general_hostname="$("${COMPOSE[@]}" exec -T worker-general hostname)"
"${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
  php "$PROBE_SCRIPT" queue-dispatch "$GENERAL_QUEUE_PROBE_KEY" default \
  >/dev/null
wait_for_cache_value "$GENERAL_QUEUE_PROBE_KEY" "$general_hostname" ||
  fail "worker-general did not process the isolated Redis default-queue probe."

hash_hostname="$("${COMPOSE[@]}" exec -T worker-hash-chain hostname)"
"${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
  php "$PROBE_SCRIPT" queue-dispatch "$HASH_QUEUE_PROBE_KEY" activity-hash-chain \
  >/dev/null
wait_for_cache_value "$HASH_QUEUE_PROBE_KEY" "$hash_hostname" ||
  fail "worker-hash-chain did not process the isolated Redis queue probe."
"${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
  php "$PROBE_SCRIPT" cache-forget "$GENERAL_QUEUE_PROBE_KEY" >/dev/null
"${COMPOSE[@]}" exec -T api /bin/bash /run/secpal/container-entrypoint.sh \
  php "$PROBE_SCRIPT" cache-forget "$HASH_QUEUE_PROBE_KEY" >/dev/null

# Positional parameters expand inside the container shell, not this runner.
# shellcheck disable=SC2016
"${COMPOSE[@]}" exec -T api sh -eu -c \
  'umask 027; printf "%s" "$2" >"$1"; chmod 0640 "$1"' \
  sh "$STORAGE_PROBE_PATH" "$STORAGE_PROBE_NAME"
storage_value="$("${COMPOSE[@]}" exec -T worker-general cat "$STORAGE_PROBE_PATH")"
[ "$storage_value" = "$STORAGE_PROBE_NAME" ] ||
  fail "worker-general could not read the API private-storage probe."
storage_metadata="$("${COMPOSE[@]}" exec -T worker-hash-chain stat -c '%u:%g:%a' "$STORAGE_PROBE_PATH")"
[ "$storage_metadata" = '10001:10001:640' ] ||
  fail "the shared private-storage probe had unexpected metadata."
"${COMPOSE[@]}" exec -T api rm -f -- "$STORAGE_PROBE_PATH"

APP_ORIGIN="$APP_ORIGIN" API_ORIGIN="$API_ORIGIN" \
  npm run test:integration:browser

for singleton in worker-hash-chain scheduler; do
  "${COMPOSE[@]}" ps --status running --quiet "$singleton" >"$TEMP_DIR/$singleton.ids"
  count="$(awk 'NF { count++ } END { print count + 0 }' "$TEMP_DIR/$singleton.ids")"
  [ "$count" -eq 1 ] || fail "singleton role $singleton did not have exactly one running container."
done

if ! "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null; then
  fail "the local integration resources could not be removed completely."
fi
if ! docker image rm "${LOCAL_IMAGES[@]}" >/dev/null; then
  fail "the project-scoped local integration images could not be removed completely."
fi
if [ -n "$(docker ps --all --quiet --filter "label=com.docker.compose.project=$PROJECT_NAME")" ] ||
  [ -n "$(docker network ls --quiet --filter "label=com.docker.compose.project=$PROJECT_NAME")" ] ||
  [ -n "$(docker volume ls --quiet --filter "label=com.docker.compose.project=$PROJECT_NAME")" ]; then
  fail "project-scoped containers, networks, or volumes remained after cleanup."
fi
cleanup_completed=1

printf 'Phase B local cross-origin integration passed.\n'
