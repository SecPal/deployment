#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

failures=0
checks=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  checks=$((checks + 1))
  if [ ! -f "$1" ]; then
    fail "required production contract file is missing: $1"
  fi
}

require_text() {
  local path="$1"
  local text="$2"
  checks=$((checks + 1))
  if [ ! -f "$path" ] || ! grep -Fq -- "$text" "$path"; then
    fail "$path must contain: $text"
  fi
}

require_prose() {
  local path="$1"
  local text="$2"
  local normalized=""
  checks=$((checks + 1))
  if [ -f "$path" ]; then
    normalized="$(tr '\n' ' ' <"$path")"
  fi
  if [ ! -f "$path" ] || ! grep -Fq -- "$text" <<<"$normalized"; then
    fail "$path must contain prose: $text"
  fi
}

for path in \
  docs/architecture/production-host.md \
  docs/architecture/production-inventory.md \
  config/production/inventory.example.yaml \
  schemas/production-host-facts.schema.json \
  schemas/production-inventory.schema.json \
  scripts/validate-production-contract.py \
  tests/production-inventory-contract.py \
  tests/fixtures/production-host/valid-amd64.yaml \
  tests/fixtures/production-host/valid-arm64.yaml \
  tests/fixtures/production-host/invalid-architecture.yaml \
  tests/fixtures/production-host/insufficient-disk.yaml \
  tests/fixtures/production-host/clock-unsynchronized.yaml \
  tests/fixtures/production-host/ubuntu-host.yaml \
  tests/fixtures/production-host/future-debian-major.yaml \
  tests/fixtures/production-host/floating-stable-suite.yaml \
  tests/fixtures/production-host/missing-security-suite.yaml \
  tests/fixtures/production-host/security-updates-disabled.yaml \
  tests/fixtures/production-host/automatic-reboot-enabled.yaml \
  tests/fixtures/production-host/local-kernel-source.yaml \
  tests/fixtures/production-host/kernel-backports-suite.yaml \
  tests/fixtures/production-host/wrong-docker-distribution.yaml \
  tests/fixtures/production-host/contradictory-filesystem.yaml \
  tests/fixtures/production-host/malformed-kernel-release.yaml \
  tests/fixtures/production-host/malformed-architecture.yaml \
  tests/fixtures/production-inventory/valid-amd64.yaml \
  tests/fixtures/production-inventory/valid-arm64.yaml; do
  require_file "$path"
done

require_text docs/architecture/production-host.md "single-host"
require_text docs/architecture/production-host.md "Multi-host and high availability are deferred"
require_text docs/architecture/production-host.md "Debian 13"
require_text docs/architecture/production-host.md "trixie"
require_text docs/architecture/production-host.md "linux/amd64"
require_text docs/architecture/production-host.md "linux/arm64"
require_text docs/architecture/production-host.md "Linux 6.12"
require_text docs/architecture/production-host.md "Operating-system lifecycle"
require_text docs/architecture/production-host.md "Automatic security updates are required"
require_text docs/architecture/production-host.md "Automatic reboots are forbidden"
require_text docs/architecture/production-host.md "Automatic major-release upgrades are forbidden"
require_prose docs/architecture/production-host.md "Replace/rebuild before in-place major upgrade"
require_text docs/architecture/production-host.md "cgroup v2"
require_text docs/architecture/production-host.md "Docker Engine 29.6.2"
require_text docs/architecture/production-host.md "Docker Compose 2.40.3"
require_text docs/architecture/production-host.md "Rootless Docker Engine is deferred"
require_text docs/architecture/production-host.md "Quantified minimum envelope"
require_prose docs/architecture/production-host.md "Docker daemon authority is privileged host authority"
require_text docs/architecture/production-host.md "Direct root SSH is unsupported"
require_prose docs/architecture/production-host.md "No Docker socket is mounted into a product container"
require_prose docs/architecture/production-host.md "Logs are persistent operational and security evidence"
require_prose docs/architecture/production-host.md "D.1 fixes public application storage as persistent host state"
require_text docs/architecture/production-host.md "10001:10001"
require_text docs/architecture/production-host.md "101:101"
require_text docs/architecture/production-host.md "No host was provisioned."
require_text docs/architecture/production-host.md "No production deployment was performed."

for dependency in \
  "GHCR image retrieval" \
  "GitHub artifact attestation verification" \
  "Mail delivery" \
  "OpenTimestamp calendars" \
  "Bitcoin quorum providers" \
  "Address-data imports" \
  "Android push delivery" \
  "Web Push delivery" \
  "Optional object storage"; do
  require_text docs/architecture/production-host.md "$dependency"
done

for path_name in \
  configuration \
  deployment_state \
  runtime_secrets \
  postgresql_data \
  private_application_storage \
  public_application_storage \
  edge_state \
  acme_state \
  crowdsec_state \
  logs \
  backup_staging \
  docker_data_root; do
  require_text config/production/inventory.example.yaml "$path_name:"
done

require_text docs/architecture/production-inventory.md "schema_version"
require_prose docs/architecture/production-inventory.md "Unknown schema versions fail closed"
require_text docs/architecture/production-inventory.md "must not contain secrets"
require_text docs/architecture/production-inventory.md "must not select image identities"
require_prose docs/architecture/production-inventory.md "frontend and API origins must differ"
require_text docs/architecture/production-inventory.md "reviewed migration notes"

require_text schemas/production-inventory.schema.json '"additionalProperties": false'
require_text schemas/production-inventory.schema.json '"schema_version"'
require_text schemas/production-inventory.schema.json '"single-host"'
require_text schemas/production-inventory.schema.json '"amd64"'
require_text schemas/production-inventory.schema.json '"arm64"'
require_text schemas/production-host-facts.schema.json '"additionalProperties": false'
require_text schemas/production-host-facts.schema.json '"docker-apt-repository"'
require_text schemas/production-host-facts.schema.json '"docker-compose-plugin"'
require_text schemas/production-host-facts.schema.json '"debian_release_suites"'
require_text schemas/production-host-facts.schema.json '"trixie-security"'
require_text schemas/production-host-facts.schema.json '"major_release_upgrades_automatic"'
require_text schemas/production-host-facts.schema.json '"automatic_reboot"'
require_text schemas/production-host-facts.schema.json '"debian-archive"'
require_text schemas/production-host-facts.schema.json '"/var/run/docker.sock"'

require_text CHANGELOG.md "provider-neutral production host and inventory contract"
require_text scripts/preflight.sh "python3 tests/production-inventory-contract.py"
require_text scripts/preflight.sh "bash tests/production-host-contract.sh"

readonly API_IMAGE='ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
readonly FRONTEND_IMAGE='ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
require_text compose.yaml "$API_IMAGE"
require_text compose.yaml "$FRONTEND_IMAGE"

checks=$((checks + 1))
if grep -Eiq 'host provisioning|ssh connection|terraform|ansible|cloud provider' \
  scripts/validate-production-contract.py 2>/dev/null; then
  fail "the pure production contract validator must not implement provisioning, SSH, or providers"
fi

checks=$((checks + 1))
if grep -ERin \
  'Ubuntu|ubuntu|noble|ubuntu-server|ubuntu-archive|Linux 6\.8' \
  docs/architecture/production-host.md \
  docs/architecture/production-inventory.md \
  schemas/production-host-facts.schema.json \
  schemas/production-inventory.schema.json \
  scripts/validate-production-contract.py \
  tests/fixtures/production-host/valid-amd64.yaml \
  tests/fixtures/production-host/valid-arm64.yaml \
  tests/fixtures/production-inventory \
  config/production/inventory.example.yaml; then
  fail "active D.1 contract artifacts must not retain an Ubuntu host assumption"
fi

if [ "$failures" -ne 0 ]; then
  printf 'Production host contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Production host contract passed (%d assertions).\n' "$checks"
