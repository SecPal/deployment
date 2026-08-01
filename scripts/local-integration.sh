#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
TEMP_DIR="$(mktemp -d -t secpal-phase-b.XXXXXXXXXX)"
project_token="${TEMP_DIR##*.}"
PROJECT_NAME="secpal-phase-b-${project_token,,}"
COMPOSE=()
LOCAL_IMAGES=()
cleanup_completed=0

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

command -v docker >/dev/null 2>&1 || fail "Docker is required."
if [ -z "${SECPAL_PHASE_B_PORT:-}" ]; then
  command -v python3 >/dev/null 2>&1 || fail "Python 3 is required to allocate an isolated loopback port."
  SECPAL_PHASE_B_PORT="$(python3 -c 'import socket; sock = socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()')"
fi
case "$SECPAL_PHASE_B_PORT" in
  '' | *[!0-9]*) fail "SECPAL_PHASE_B_PORT must be an integer from 1024 through 65535." ;;
esac
if [ "$SECPAL_PHASE_B_PORT" -lt 1024 ] || [ "$SECPAL_PHASE_B_PORT" -gt 65535 ]; then
  fail "SECPAL_PHASE_B_PORT must be an integer from 1024 through 65535."
fi

SECPAL_PHASE_B_ORIGIN="https://secpal.example.invalid:$SECPAL_PHASE_B_PORT"
SECPAL_PHASE_B_API_IMAGE="$PROJECT_NAME-api:phase-b-6fead9cef910"
SECPAL_PHASE_B_FRONTEND_IMAGE="$PROJECT_NAME-frontend:phase-b-fcd427d9b55d"
SECPAL_PHASE_B_GATEWAY_IMAGE="$PROJECT_NAME-gateway:phase-b-2.10.2"
export \
  SECPAL_PHASE_B_API_IMAGE \
  SECPAL_PHASE_B_FRONTEND_IMAGE \
  SECPAL_PHASE_B_GATEWAY_IMAGE \
  SECPAL_PHASE_B_ORIGIN \
  SECPAL_PHASE_B_PORT
LOCAL_IMAGES=(
  "$SECPAL_PHASE_B_API_IMAGE"
  "$SECPAL_PHASE_B_FRONTEND_IMAGE"
  "$SECPAL_PHASE_B_GATEWAY_IMAGE"
)
ORIGIN="$SECPAL_PHASE_B_ORIGIN"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose --project-name "$PROJECT_NAME" --file "$ROOT_DIR/compose.yaml")
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose --project-name "$PROJECT_NAME" --file "$ROOT_DIR/compose.yaml")
else
  fail "Docker Compose v2 is required."
fi

cd "$ROOT_DIR"

"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" build secrets-init frontend gateway
"${COMPOSE[@]}" up --detach postgres valkey
"${COMPOSE[@]}" --profile tools run --rm migrate
"${COMPOSE[@]}" up --detach api worker-default worker-forensics scheduler frontend gateway

gateway_ready=0
for _attempt in $(seq 1 90); do
  if curl --fail --silent --show-error --insecure \
    --noproxy secpal.example.invalid \
    --resolve "secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
    "$ORIGIN/health/live" >"$TEMP_DIR/api-health.json" 2>/dev/null; then
    gateway_ready=1
    break
  fi
  sleep 1
done

if [ "$gateway_ready" -ne 1 ]; then
  "${COMPOSE[@]}" ps >&2
  fail "the local test-only TLS gateway did not become healthy."
fi

grep -Fq '"status":"alive"' "$TEMP_DIR/api-health.json" ||
  fail "the API liveness response did not satisfy the product contract."

curl --fail --silent --show-error --insecure \
  --noproxy secpal.example.invalid \
  --resolve "secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$ORIGIN/" >"$TEMP_DIR/frontend.html"
grep -Eiq '<!doctype html' "$TEMP_DIR/frontend.html" ||
  fail "the frontend was not served through the test-only TLS gateway."

curl --fail --silent --show-error --insecure \
  --noproxy secpal.example.invalid \
  --resolve "secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
  "$ORIGIN/runtime-config.js" >"$TEMP_DIR/runtime-config.js"
grep -Fq "apiBaseUrl: \"$ORIGIN\"," "$TEMP_DIR/runtime-config.js" ||
  fail "the frontend runtime API origin did not match the local gateway."

"${COMPOSE[@]}" ps --status running --services >"$TEMP_DIR/services"
for singleton in worker-forensics scheduler; do
  count="$(grep -Fxc "$singleton" "$TEMP_DIR/services" || true)"
  [ "$count" -eq 1 ] || fail "singleton role $singleton did not have exactly one running service."
done

if ! "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null; then
  fail "the local integration resources could not be removed completely."
fi
if ! docker image rm "${LOCAL_IMAGES[@]}" >/dev/null; then
  fail "the project-scoped local integration images could not be removed completely."
fi
cleanup_completed=1

printf 'Phase B local API/frontend integration passed.\n'
