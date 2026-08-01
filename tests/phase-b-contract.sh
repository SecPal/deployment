#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

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
  scripts/container-entrypoint.sh \
  scripts/init-local-secrets.sh \
  scripts/local-integration.sh; do
  require_file "$path"
done

require_text compose.yaml "https://github.com/SecPal/api.git#6fead9cef910314304048056a7ebed4f10bf5381"
require_text compose.yaml "https://github.com/SecPal/frontend.git#fcd427d9b55d7945c439c670077e12928e47ddd6"
require_text compose.yaml '127.0.0.1:8443:8443'
require_text compose.yaml 'source: local-secrets'
require_text compose.yaml 'condition: service_completed_successfully'
require_text compose.yaml 'condition: service_healthy'
require_text compose.yaml 'read_only: true'
require_text compose.yaml 'no-new-privileges:true'
require_text compose.yaml 'cap_drop:'
require_text compose.yaml 'internal: true'
require_text compose.yaml 'activity-hash-chain,merkle,opentimestamp'
require_text compose.yaml 'command: ["php", "artisan", "schedule:work"]'
require_text compose.yaml 'command: ["php", "artisan", "migrate", "--force"]'
require_text compose.yaml 'profiles: [tools]'
require_text compose.yaml 'postgres:16.10-bookworm@sha256:'
require_text compose.yaml 'valkey/valkey:9.1.1-trixie@sha256:'
require_text config/phase-b/Caddyfile 'https://secpal.example.invalid:8443'
require_text config/phase-b/Caddyfile 'tls internal'
require_text containers/phase-b-gateway/Dockerfile 'caddy:2.10.2-alpine@sha256:'
require_text containers/phase-b-gateway/Dockerfile 'RUN setcap -r /usr/bin/caddy'
require_text scripts/local-integration.sh '--resolve'
require_text scripts/local-integration.sh 'down --volumes --remove-orphans'

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
  loopback_port_count="$(grep -Fxc '      - "127.0.0.1:8443:8443"' compose.yaml || true)"
  if grep -Eq '^  ports:$' compose.yaml ||
    [ "$port_section_count" -ne 1 ] || [ "$published_port_count" -ne 1 ] ||
    [ "$loopback_port_count" -ne 1 ] || [ -n "$non_gateway_ports" ]; then
    fail "only the gateway may publish the single loopback test-TLS port"
  fi

  activity_role_count="$(grep -Ec '^  worker-forensics:$' compose.yaml || true)"
  if [ "$activity_role_count" -ne 1 ]; then
    fail "compose.yaml must define exactly one activity-hash-chain worker role"
  fi

  scheduler_role_count="$(grep -Ec '^  scheduler:$' compose.yaml || true)"
  if [ "$scheduler_role_count" -ne 1 ]; then
    fail "compose.yaml must define exactly one scheduler role"
  fi

  activity_consumer_count="$(grep -Fc -- '--queue=activity-hash-chain' compose.yaml || true)"
  scheduler_consumer_count="$(grep -Fc 'schedule:work' compose.yaml || true)"
  if [ "$activity_consumer_count" -ne 1 ] || [ "$scheduler_consumer_count" -ne 1 ] ||
    grep -Eq '^[[:space:]]+(scale|replicas):' compose.yaml; then
    fail "singleton roles must each have one consumer and no multi-replica declaration"
  fi

  host_access_count="$(grep -Fc 'host-access' compose.yaml || true)"
  if [ "$host_access_count" -ne 2 ]; then
    fail "only the gateway may reference the host-access network"
  fi
fi

if [ "$failures" -ne 0 ]; then
  printf 'Phase B contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Phase B contract passed.\n'
