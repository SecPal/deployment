#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

supervise_integration() {
  local child_pid
  local status

  if ! command -v setsid >/dev/null 2>&1; then
    printf 'ERROR: setsid is required for reliable signal handling.\n' >&2
    return 1
  fi

  SECPAL_PHASE_B_SUPERVISED=1 setsid --wait bash "$0" "$@" &
  child_pid=$!

  # Invoked indirectly by the signal traps below.
  # shellcheck disable=SC2317,SC2329
  forward_supervisor_signal() {
    local exit_status="$1"

    trap - HUP INT TERM
    if kill -0 "$child_pid" >/dev/null 2>&1; then
      kill -TERM -- "-$child_pid" >/dev/null 2>&1 ||
        kill -TERM "$child_pid" >/dev/null 2>&1 || true
    fi
    wait "$child_pid" >/dev/null 2>&1 || true
    exit "$exit_status"
  }

  trap 'forward_supervisor_signal 129' HUP
  trap 'forward_supervisor_signal 130' INT
  trap 'forward_supervisor_signal 143' TERM

  set +e
  wait "$child_pid"
  status=$?
  set -e
  trap - HUP INT TERM
  return "$status"
}

if [ "${SECPAL_PHASE_B_SUPERVISED:-0}" -ne 1 ]; then
  supervise_integration "$@"
  exit $?
fi
unset SECPAL_PHASE_B_SUPERVISED

ROOT_DIR="$(git rev-parse --show-toplevel)"
TEMP_DIR="$(mktemp -d -t secpal-phase-b.XXXXXXXXXX)"
ANON_DOCKER_CONFIGS=()
project_token="${TEMP_DIR##*.}"
project_token="${project_token,,}"
PROJECT_NAME="secpal-phase-b-$project_token"
COMPOSE=()
LOCAL_IMAGES=()
cleanup_completed=0
automatic_port=0
PROBE_SCRIPT=/run/secpal/phase-b-runtime-probe.php
readonly EXPECTED_API_IMAGE='ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
readonly EXPECTED_API_DIGEST='sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
readonly API_SOURCE_COMMIT='87d1432389adac3a02574b399322928a77c5e67f'
readonly EXPECTED_FRONTEND_IMAGE='ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
readonly EXPECTED_FRONTEND_DIGEST='sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
readonly FRONTEND_SOURCE_COMMIT='b755ca0d0ee5a85eca5ad5688d457241f070b1b4'
readonly EXPECTED_GH_VERSION='2.97.0'
readonly ANONYMOUS_GH_CONFIG="$TEMP_DIR/anonymous-gh-config"

cleanup() {
  if [ "${#COMPOSE[@]}" -ne 0 ] && [ "$cleanup_completed" -ne 1 ]; then
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [ "${#LOCAL_IMAGES[@]}" -ne 0 ] && [ "$cleanup_completed" -ne 1 ]; then
    docker image rm "${LOCAL_IMAGES[@]}" >/dev/null 2>&1 || true
  fi
  local anonymous_docker_config
  for anonymous_docker_config in "${ANON_DOCKER_CONFIGS[@]}"; do
    rm -rf -- "$anonymous_docker_config"
  done
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

run_isolated_gh() {
  GH_CONFIG_DIR="$ANONYMOUS_GH_CONFIG" \
    GH_PROMPT_DISABLED=1 \
    GH_NO_UPDATE_NOTIFIER=1 \
    GH_NO_EXTENSION_UPDATE_NOTIFIER=1 \
    GH_TELEMETRY=false \
    env -u GH_TOKEN -u GITHUB_TOKEN -u GH_ENTERPRISE_TOKEN -u GITHUB_ENTERPRISE_TOKEN -u GH_HOST -u DOCKER_CONFIG -u DOCKER_AUTH_CONFIG \
    gh "$@"
}

verify_published_image() {
  local image_label="$1"
  local canonical_image="$2"
  local canonical_digest="$3"
  local repository="$4"
  local publisher_workflow="$5"
  local source_ref="$6"
  local source_digest="$7"
  local signer_digest="$8"
  local expected_registry_path="$9"
  local canonical_name="${canonical_image%@*}"
  local anonymous_docker_config
  local attestation_subject="$TEMP_DIR/$image_label-image-index.json"
  local attestation_bundle="$TEMP_DIR/$image_label-attestation.json"

  [ "$canonical_image" = "$canonical_name@$canonical_digest" ] ||
    fail "$image_label image reference did not match its explicit canonical digest."
  [ "$canonical_name" = "ghcr.io/$expected_registry_path" ] ||
    fail "$image_label image reference did not match its explicit registry path."

  anonymous_docker_config="$(mktemp -d -t "secpal-$image_label-anon-docker.XXXXXXXXXX")"
  chmod 0700 "$anonymous_docker_config"
  ANON_DOCKER_CONFIGS+=("$anonymous_docker_config")

  env -u DOCKER_AUTH_CONFIG \
    DOCKER_CONFIG="$anonymous_docker_config" \
    docker pull "$canonical_image"

  if ! env -u GH_TOKEN -u GITHUB_TOKEN -u GH_ENTERPRISE_TOKEN -u GITHUB_ENTERPRISE_TOKEN -u GH_HOST -u DOCKER_CONFIG -u DOCKER_AUTH_CONFIG \
    python3 "$ROOT_DIR/scripts/fetch-oci-attestation.py" \
      "$attestation_subject" \
      "$attestation_bundle" \
      "$canonical_name" \
      "$canonical_digest" \
      "$expected_registry_path"; then
    fail "anonymous $image_label OCI attestation bundle retrieval failed."
  fi

  if ! run_isolated_gh attestation verify \
    "$attestation_subject" \
    --bundle "$attestation_bundle" \
    --repo "$repository" \
    --signer-workflow "$publisher_workflow" \
    --signer-digest "$signer_digest" \
    --source-ref "$source_ref" \
    --source-digest "$source_digest" \
    --deny-self-hosted-runners \
    --hostname github.com; then
    fail "public token-free $image_label artifact attestation verification failed."
  fi

  rm -rf -- "$anonymous_docker_config"
  printf 'Verified %s image: %s\n' "$image_label" "$canonical_image"
  printf 'Verified %s source commit: %s\n' "$image_label" "$source_digest"
}

verify_api_image() {
  verify_published_image \
    api \
    "$API_IMAGE" \
    "$EXPECTED_API_DIGEST" \
    SecPal/api \
    SecPal/api/.github/workflows/publish-container.yml \
    refs/heads/main \
    "$API_SOURCE_COMMIT" \
    "$API_SOURCE_COMMIT" \
    secpal/api
}

verify_frontend_image() {
  verify_published_image \
    frontend \
    "$FRONTEND_IMAGE" \
    "$EXPECTED_FRONTEND_DIGEST" \
    SecPal/frontend \
    SecPal/frontend/.github/workflows/publish-container.yml \
    refs/heads/main \
    "$FRONTEND_SOURCE_COMMIT" \
    "$FRONTEND_SOURCE_COMMIT" \
    secpal/frontend
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
require_command gh "GitHub CLI is required for published image artifact attestation verification."
require_command node "Node.js is required."
require_command npm "npm is required."

install -d -m 0700 "$ANONYMOUS_GH_CONFIG"
if ! gh_version_output="$(run_isolated_gh version)"; then
  fail "the installed GitHub CLI version could not be determined."
fi
gh_version_line="${gh_version_output%%$'\n'*}"
case "$gh_version_line" in
  "gh version $EXPECTED_GH_VERSION" | "gh version $EXPECTED_GH_VERSION "*) ;;
  *) fail "GitHub CLI $EXPECTED_GH_VERSION is required; found $gh_version_line." ;;
esac

run_isolated_gh attestation verify --help >/dev/null 2>&1 ||
  fail "the installed GitHub CLI does not support artifact attestation verification."

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

SECPAL_PHASE_B_GATEWAY_IMAGE="$PROJECT_NAME-gateway:phase-b-2.10.2"
SECPAL_PHASE_B_HASH_CHAIN_CONTAINER_NAME="$PROJECT_NAME-worker-hash-chain"
SECPAL_PHASE_B_SCHEDULER_CONTAINER_NAME="$PROJECT_NAME-scheduler"
export \
  SECPAL_PHASE_B_GATEWAY_IMAGE \
  SECPAL_PHASE_B_HASH_CHAIN_CONTAINER_NAME \
  SECPAL_PHASE_B_SCHEDULER_CONTAINER_NAME
LOCAL_IMAGES=(
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
"${COMPOSE[@]}" --profile tools config --format json >"$TEMP_DIR/compose-config.json"
if ! resolved_images="$(node - "$TEMP_DIR/compose-config.json" "$EXPECTED_API_IMAGE" "$EXPECTED_FRONTEND_IMAGE" <<'NODE'
const fs = require('node:fs');

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const expectedApi = process.argv[3];
const expectedFrontend = process.argv[4];
const apiServices = [
  'secrets-init',
  'migrate',
  'api',
  'worker-hash-chain',
  'worker-general',
  'scheduler',
];
const images = new Set();

for (const serviceName of apiServices) {
  const service = config.services?.[serviceName];
  if (!service || service.image !== expectedApi || service.build !== undefined) {
    process.stderr.write(
      `ERROR: ${serviceName} must use only the canonical API digest.\n`,
    );
    process.exit(1);
  }
  images.add(service.image);
}

if (images.size !== 1 || [...images][0] !== expectedApi) {
  process.stderr.write('ERROR: API roles resolved to more than one image.\n');
  process.exit(1);
}

const frontend = config.services?.frontend;
if (!frontend || frontend.image !== expectedFrontend || frontend.build !== undefined) {
  process.stderr.write(
    'ERROR: frontend must use only the canonical frontend digest.\n',
  );
  process.exit(1);
}

process.stdout.write(`${expectedApi}\n${expectedFrontend}\n`);
NODE
)"; then
  fail "the resolved Compose published image contract is invalid."
fi
mapfile -t RESOLVED_IMAGES <<<"$resolved_images"
API_IMAGE="${RESOLVED_IMAGES[0]:-}"
FRONTEND_IMAGE="${RESOLVED_IMAGES[1]:-}"
[ "$API_IMAGE" = "$EXPECTED_API_IMAGE" ] || fail "the resolved API digest is not approved."
[ "$FRONTEND_IMAGE" = "$EXPECTED_FRONTEND_IMAGE" ] || fail "the resolved frontend digest is not approved."

printf 'GitHub CLI: %s\n' "$gh_version_line"
printf 'Docker Engine: %s\n' "$(docker version --format '{{.Server.Version}}')"
printf 'Docker Compose: %s\n' "$compose_version"
printf 'Host platform: %s/%s\n' "$(uname -s)" "$(uname -m)"

verify_api_image
verify_frontend_image

"${COMPOSE[@]}" build gateway
"${COMPOSE[@]}" up --detach postgres valkey
"${COMPOSE[@]}" --profile tools run --rm --no-TTY migrate

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

for rejected_frontend_path in \
  /v1/phase-b-not-an-api-route /sanctum/csrf-cookie /health/ready; do
  rejected_frontend_name="${rejected_frontend_path//\//-}"
  rejected_frontend_status="$(curl --silent --show-error --insecure \
    --output "$TEMP_DIR/frontend-route$rejected_frontend_name.out" \
    --write-out '%{http_code}' \
    --noproxy app.secpal.example.invalid \
    --resolve "app.secpal.example.invalid:$SECPAL_PHASE_B_PORT:127.0.0.1" \
    "$APP_ORIGIN$rejected_frontend_path")"
  [ "$rejected_frontend_status" = '404' ] ||
    fail "the frontend origin exposed forbidden route $rejected_frontend_path."
done
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
