#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
PROJECT_NAME="secpal-phase-b-$$"
TEMP_DIR="$(mktemp -d)"
ORIGIN="https://secpal.example.invalid:8443"
COMPOSE=()
cleanup_completed=0

cleanup() {
  if [ "${#COMPOSE[@]}" -ne 0 ] && [ "$cleanup_completed" -ne 1 ]; then
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "Docker is required."
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
    --resolve secpal.example.invalid:8443:127.0.0.1 \
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
  --resolve secpal.example.invalid:8443:127.0.0.1 \
  "$ORIGIN/" >"$TEMP_DIR/frontend.html"
grep -Eiq '<!doctype html' "$TEMP_DIR/frontend.html" ||
  fail "the frontend was not served through the test-only TLS gateway."

curl --fail --silent --show-error --insecure \
  --noproxy secpal.example.invalid \
  --resolve secpal.example.invalid:8443:127.0.0.1 \
  "$ORIGIN/runtime-config.js" >"$TEMP_DIR/runtime-config.js"
grep -Fq 'apiBaseUrl: "https://secpal.example.invalid:8443",' "$TEMP_DIR/runtime-config.js" ||
  fail "the frontend runtime API origin did not match the local gateway."

"${COMPOSE[@]}" ps --status running --services >"$TEMP_DIR/services"
for singleton in worker-forensics scheduler; do
  count="$(grep -Fxc "$singleton" "$TEMP_DIR/services" || true)"
  [ "$count" -eq 1 ] || fail "singleton role $singleton did not have exactly one running service."
done

if ! "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null; then
  fail "the local integration resources could not be removed completely."
fi
cleanup_completed=1

printf 'Phase B local API/frontend integration passed.\n'
