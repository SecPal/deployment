#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

# Literal Compose and shell interpolations are part of the contract text.
# shellcheck disable=SC2016

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

failures=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    fail "required Phase B file is missing: $path"
  fi
}

require_text() {
  local path="$1"
  local text="$2"
  if [ ! -f "$path" ] || ! grep -Fq -- "$text" "$path"; then
    fail "$path must contain: $text"
  fi
}

for path in \
  compose.yaml \
  config/phase-b/Caddyfile \
  containers/phase-b-gateway/Dockerfile \
  package.json \
  package-lock.json \
  playwright.integration.config.js \
  scripts/container-entrypoint.sh \
  scripts/init-local-secrets.sh \
  scripts/local-integration.sh \
  scripts/phase-b-runtime-probe.php \
  tests/e2e/local-integration.spec.js \
  .github/workflows/local-integration.yml; do
  require_file "$path"
done

require_text compose.yaml "ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
require_text compose.yaml "https://github.com/SecPal/frontend.git#fcd427d9b55d7945c439c670077e12928e47ddd6"
require_text compose.yaml "127.0.0.1:\${SECPAL_PHASE_B_PORT:-8443}:8443"
# The Compose interpolation must remain literal.
# shellcheck disable=SC2016
require_text compose.yaml 'APP_URL: https://api.secpal.example.invalid:${SECPAL_PHASE_B_PORT:-8443}'
require_text compose.yaml 'APP_NAME: SecPal'
# The Compose interpolation must remain literal.
# shellcheck disable=SC2016
require_text compose.yaml 'FRONTEND_URL: https://app.secpal.example.invalid:${SECPAL_PHASE_B_PORT:-8443}'
# The Compose interpolation must remain literal.
# shellcheck disable=SC2016
require_text compose.yaml 'SECPAL_API_URL: https://api.secpal.example.invalid:${SECPAL_PHASE_B_PORT:-8443}'
require_text compose.yaml "\${SECPAL_PHASE_B_FRONTEND_IMAGE:-secpal-frontend:phase-b-fcd427d9b55d}"
require_text compose.yaml "\${SECPAL_PHASE_B_GATEWAY_IMAGE:-secpal-test-gateway:phase-b-2.10.2}"
# The Compose interpolation must remain literal.
# shellcheck disable=SC2016
require_text compose.yaml 'SANCTUM_STATEFUL_DOMAINS: app.secpal.example.invalid:${SECPAL_PHASE_B_PORT:-8443}'
require_text compose.yaml 'SESSION_DOMAIN: .secpal.example.invalid'
require_text compose.yaml 'SESSION_SECURE_COOKIE: "true"'
require_text compose.yaml 'SESSION_HTTP_ONLY: "true"'
require_text compose.yaml 'SESSION_SAME_SITE: lax'
# The Compose interpolation must remain literal.
# shellcheck disable=SC2016
require_text compose.yaml 'CORS_ALLOWED_ORIGINS: https://app.secpal.example.invalid:${SECPAL_PHASE_B_PORT:-8443}'
require_text compose.yaml 'CORS_ALLOWED_METHODS: GET,POST,PUT,PATCH,DELETE,OPTIONS'
require_text compose.yaml 'CORS_ALLOWED_HEADERS: Content-Type,Authorization,X-Requested-With,X-XSRF-TOKEN'
require_text compose.yaml 'CORS_SUPPORTS_CREDENTIALS: "true"'
require_text compose.yaml 'QUEUE_CONNECTION: redis'
require_text compose.yaml 'CACHE_STORE: redis'
require_text compose.yaml 'REDIS_CLIENT: phpredis'
require_text compose.yaml 'REDIS_HOST: valkey'
require_text compose.yaml 'REDIS_PORT: "6379"'
require_text compose.yaml 'REDIS_DB: "0"'
require_text compose.yaml 'REDIS_CACHE_DB: "1"'
require_text compose.yaml 'REDIS_QUEUE_CONNECTION: default'
require_text compose.yaml 'REDIS_QUEUE: default'
require_text compose.yaml 'SESSION_DRIVER: database'
require_text compose.yaml 'TRUSTED_PROXIES: REMOTE_ADDR'
# The Compose interpolation must remain literal.
# shellcheck disable=SC2016
require_text compose.yaml 'container_name: ${SECPAL_PHASE_B_HASH_CHAIN_CONTAINER_NAME:-secpal-phase-b-worker-hash-chain}'
# The Compose interpolation must remain literal.
# shellcheck disable=SC2016
require_text compose.yaml 'container_name: ${SECPAL_PHASE_B_SCHEDULER_CONTAINER_NAME:-secpal-phase-b-scheduler}'
require_text compose.yaml 'source: local-secrets'
require_text compose.yaml 'source: private-storage'
require_text compose.yaml 'target: /app/storage/app/private'
require_text compose.yaml 'target: /mnt/secpal-private-storage'
require_text compose.yaml 'condition: service_completed_successfully'
require_text compose.yaml 'condition: service_healthy'
require_text compose.yaml 'read_only: true'
require_text compose.yaml 'no-new-privileges:true'
require_text compose.yaml 'cap_drop:'
require_text compose.yaml 'internal: true'
require_text compose.yaml '--queue=activity-hash-chain'
require_text compose.yaml '--queue=merkle,opentimestamp,default'
require_text compose.yaml '--sleep=1'
require_text compose.yaml '--tries=3'
require_text compose.yaml '--timeout=90'
require_text compose.yaml 'org.secpal.role: activity-hash-chain'
require_text compose.yaml 'org.secpal.singleton: "true"'
require_text compose.yaml 'command: ["php", "artisan", "schedule:work"]'
require_text compose.yaml 'command: ["php", "artisan", "migrate", "--force"]'
require_text compose.yaml 'profiles: [tools]'
require_text compose.yaml 'postgres:16.10-bookworm@sha256:'
require_text compose.yaml 'valkey/valkey:9.1.1-trixie@sha256:'
require_text config/phase-b/Caddyfile 'https://app.secpal.example.invalid:8443'
require_text config/phase-b/Caddyfile 'https://api.secpal.example.invalid:8443'
require_text config/phase-b/Caddyfile 'tls internal'
require_text containers/phase-b-gateway/Dockerfile 'caddy:2.10.2-alpine@sha256:'
require_text containers/phase-b-gateway/Dockerfile 'RUN setcap -r /usr/bin/caddy'
require_text scripts/local-integration.sh '--resolve'
require_text scripts/local-integration.sh 'down --volumes --remove-orphans'
require_text scripts/local-integration.sh 'handle_signal 143'
require_text scripts/local-integration.sh 'docker image rm'
# The runner expression must remain literal.
# shellcheck disable=SC2016
require_text scripts/local-integration.sh 'APP_ORIGIN="https://app.secpal.example.invalid:$SECPAL_PHASE_B_PORT"'
# The runner expression must remain literal.
# shellcheck disable=SC2016
require_text scripts/local-integration.sh 'API_ORIGIN="https://api.secpal.example.invalid:$SECPAL_PHASE_B_PORT"'
require_text scripts/local-integration.sh 'npm run test:integration:browser'
require_text scripts/local-integration.sh 'frontend_api_status'
require_text scripts/local-integration.sh "[ \"\$frontend_api_status\" = '404' ]"
require_text scripts/local-integration.sh 'worker-general'
require_text scripts/local-integration.sh 'worker-hash-chain'
# The script expression must remain literal.
# shellcheck disable=SC2016
require_text scripts/local-integration.sh 'ps --status running --quiet "$singleton"'
require_text scripts/init-local-secrets.sh 'handle_signal 143'
require_text scripts/init-local-secrets.sh 'SECPAL_PRIVATE_STORAGE_DIR'
require_text scripts/phase-b-runtime-probe.php "->onConnection('redis')->onQueue(\$queue)"
require_text package.json '"@playwright/test": "1.62.0"'
require_text playwright.integration.config.js 'ignoreHTTPSErrors: true'
require_text tests/e2e/local-integration.spec.js 'sanctum/csrf-cookie'
require_text .github/workflows/local-integration.yml 'name: Local Integration'
require_text .github/workflows/local-integration.yml 'name: Compose Contract'
require_text .github/workflows/local-integration.yml 'contents: read'
require_text .github/workflows/local-integration.yml './scripts/local-integration.sh'

if [ -f compose.yaml ]; then
  if grep -Eq '(^|[[:space:]])privileged:[[:space:]]*true|network_mode:[[:space:]]*host|/var/run/docker\.sock|image:[[:space:]]*[^#[:space:]]*:latest([@[:space:]]|$)' compose.yaml; then
    fail "compose.yaml contains a forbidden privilege, Docker socket, host network, or latest tag"
  fi

  if grep -Eq '(^|[[:space:]])0\.0\.0\.0:' compose.yaml; then
    fail "compose.yaml must not publish a port on every interface"
  fi

  port_section_count="$(grep -Ec '^    ports:$' compose.yaml || true)"
  published_port_count="$(awk '
    /^    ports:$/ { in_ports = 1; next }
    in_ports && /^    [^ ]/ { in_ports = 0 }
    in_ports && /^      - / { count++ }
    END { print count + 0 }
  ' compose.yaml)"
  non_gateway_ports="$(awk '
    /^  [a-zA-Z0-9][a-zA-Z0-9_-]*:$/ { service = $1 }
    /^    ports:$/ && service != "gateway:" { print service }
  ' compose.yaml)"
  loopback_port_count="$(grep -Fxc "      - \"127.0.0.1:\${SECPAL_PHASE_B_PORT:-8443}:8443\"" compose.yaml || true)"
  if grep -Eq '^  ports:$' compose.yaml ||
    [ "$port_section_count" -ne 1 ] || [ "$published_port_count" -ne 1 ] ||
    [ "$loopback_port_count" -ne 1 ] || [ -n "$non_gateway_ports" ]; then
    fail "only the gateway may publish the single loopback test-TLS port"
  fi

  activity_role_count="$(grep -Ec '^  worker-hash-chain:$' compose.yaml || true)"
  if [ "$activity_role_count" -ne 1 ]; then
    fail "compose.yaml must define exactly one activity-hash-chain worker role"
  fi

  scheduler_role_count="$(grep -Ec '^  scheduler:$' compose.yaml || true)"
  if [ "$scheduler_role_count" -ne 1 ]; then
    fail "compose.yaml must define exactly one scheduler role"
  fi

  activity_consumer_count="$(grep -Fc -- '--queue=activity-hash-chain' compose.yaml || true)"
  general_consumer_count="$(grep -Fc -- '--queue=merkle,opentimestamp,default' compose.yaml || true)"
  scheduler_consumer_count="$(grep -Fc 'schedule:work' compose.yaml || true)"
  singleton_label_count="$(grep -Fc 'org.secpal.singleton: "true"' compose.yaml || true)"
  singleton_container_name_count="$(grep -Ec '^    container_name: \$\{SECPAL_PHASE_B_(HASH_CHAIN|SCHEDULER)_CONTAINER_NAME:-' compose.yaml || true)"
  if [ "$activity_consumer_count" -ne 1 ] || [ "$general_consumer_count" -ne 1 ] ||
    [ "$scheduler_consumer_count" -ne 1 ] ||
    [ "$singleton_label_count" -ne 2 ] ||
    [ "$singleton_container_name_count" -ne 2 ] ||
    grep -Eq '^[[:space:]]+(scale|replicas):' compose.yaml; then
    fail "singleton roles must each have one consumer, a scaling guard, and no multi-replica declaration"
  fi

  general_worker_section="$(sed -n '/^  worker-general:$/,/^  [a-zA-Z0-9_-]*:$/p' compose.yaml)"
  if printf '%s\n' "$general_worker_section" | grep -Eq 'container_name:|org\.secpal\.singleton:'; then
    fail "the general worker must remain scalable without singleton guards"
  fi

  for singleton_service in worker-hash-chain scheduler; do
    singleton_section="$(sed -n "/^  $singleton_service:\$/,/^  [a-zA-Z0-9_-]*:\$/p" compose.yaml)"
    if ! printf '%s\n' "$singleton_section" | grep -Fq 'org.secpal.singleton: "true"'; then
      fail "$singleton_service must retain its singleton label"
    fi
  done

  if grep -Fq 'worker-forensics' compose.yaml || grep -Fq 'worker-default' compose.yaml ||
    grep -Fq 'QUEUE_CONNECTION: database' compose.yaml || grep -Fq 'CACHE_STORE: database' compose.yaml; then
    fail "obsolete worker roles and database queue/cache fallbacks must be absent"
  fi

  private_mount_count="$(grep -Fc 'target: /app/storage/app/private' compose.yaml || true)"
  inherited_api_role_count="$(grep -Fc '<<: *api-service' compose.yaml || true)"
  if [ "$private_mount_count" -ne 1 ] || [ "$inherited_api_role_count" -lt 5 ]; then
    fail "private-storage must be mounted by every API-based role"
  fi

  if grep -Fq 'TRUSTED_PROXIES: gateway' compose.yaml; then
    fail "the API must trust the numeric immediate proxy address, not an unresolved service name"
  fi

  if grep -Fq 'SECPAL_PHASE_B_ORIGIN' compose.yaml ||
    grep -Fq 'SECPAL_PHASE_B_ORIGIN' scripts/local-integration.sh; then
    fail "the local origin must derive from the single validated port setting"
  fi

  if grep -Fq 'ps --status running --services' scripts/local-integration.sh; then
    fail "singleton validation must count container instances rather than deduplicated service names"
  fi

  host_access_count="$(grep -Fc 'host-access' compose.yaml || true)"
  if [ "$host_access_count" -ne 2 ]; then
    fail "only the gateway may reference the host-access network"
  fi
fi

if [ -f .github/workflows/local-integration.yml ]; then
  if grep -E '^[[:space:]]*uses:[[:space:]]*[^[:space:]]+' .github/workflows/local-integration.yml |
    grep -Ev '@[0-9a-f]{40}[[:space:]]+#[[:space:]]+[^[:space:]#]+$' >/dev/null; then
    fail "the hosted integration workflow must pin every action to a full commit SHA with a source tag or branch comment"
  fi
  if ! grep -Eq '^[[:space:]]*python-version: "[0-9]+\.[0-9]+\.[0-9]+"$' .github/workflows/local-integration.yml; then
    fail "the hosted integration workflow must pin an exact Python patch version"
  fi
  workflow_permission_count="$(awk '
    /^permissions:$/ { in_permissions = 1; next }
    in_permissions && /^[^[:space:]]/ { in_permissions = 0 }
    in_permissions && /^  [a-zA-Z0-9_-]+:/ { count++ }
    END { print count + 0 }
  ' .github/workflows/local-integration.yml)"
  workflow_main_trigger_count="$(grep -Fc 'branches: [main]' .github/workflows/local-integration.yml || true)"
  if ! grep -Eq '^  pull_request:$' .github/workflows/local-integration.yml ||
    ! grep -Eq '^  push:$' .github/workflows/local-integration.yml ||
    [ "$workflow_main_trigger_count" -ne 2 ] ||
    grep -Eq '^[[:space:]]*paths(-ignore)?:' .github/workflows/local-integration.yml; then
    fail "the hosted integration workflow must run for every main pull request and main push"
  fi
  if [ "$workflow_permission_count" -ne 1 ] ||
    [ "$(grep -Ec '^  contents: read$' .github/workflows/local-integration.yml || true)" -ne 1 ] ||
    grep -Eq '^permissions:[[:space:]]+(read-all|write-all)$|^[[:space:]]+[a-zA-Z0-9_-]+:[[:space:]]*write$' .github/workflows/local-integration.yml ||
    grep -Eiq 'docker[[:space:]]+login|docker[[:space:]]+push|(^|[[:space:]])secrets\.' .github/workflows/local-integration.yml; then
    fail "the hosted integration workflow must be read-only and publishing-free"
  fi
fi

if [ "$failures" -ne 0 ]; then
  printf 'Phase B contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Phase B contract passed.\n'
