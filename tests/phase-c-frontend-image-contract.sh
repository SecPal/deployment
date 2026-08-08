#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# Literal Compose and shell interpolations are part of the contract text.
# shellcheck disable=SC2016

set -euo pipefail

ROOT_DIR="${SECPAL_CONTRACT_ROOT:-$(git rev-parse --show-toplevel)}"
cd "$ROOT_DIR"

readonly FRONTEND_IMAGE='ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
readonly FRONTEND_DIGEST='sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077'
readonly FRONTEND_SOURCE_COMMIT='b755ca0d0ee5a85eca5ad5688d457241f070b1b4'
readonly FRONTEND_WORKFLOW='SecPal/frontend/.github/workflows/publish-container.yml'
readonly API_IMAGE='ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
readonly POSTGRES_IMAGE='postgres:16.10-bookworm@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74'
readonly VALKEY_IMAGE='valkey/valkey:9.1.1-trixie@sha256:3acc0687f2a2e1091fae6450d7842dd658c941338cf0a873ddd9e14b9e4ea4dd'
readonly AMD64_CHILD_DIGEST='sha256:9448c394cb43f4885b269c91d8df15db21d6bc33459800392136b7dcb917dfd1'
readonly ARM64_CHILD_DIGEST='sha256:17b828013eeebd3f83b82b993a10f30b8c8957688fcf480bdd46d899e8cfe1'
readonly ATTESTATION_ARTIFACT_DIGEST='sha256:45f5e0c76e38c63efd483f2f8571c910a93aa528c31968a11b1960b330534b78'
readonly DISCOVERY_TAG='build-b755ca0d0ee5a85eca5ad5688d457241f070b1b4-31247196734-1'

failures=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  if [ ! -f "$1" ]; then
    fail "required Phase C.4 file is missing: $1"
  fi
}

require_text() {
  local path="$1"
  local text="$2"
  if [ ! -f "$path" ] || ! grep -Fq -- "$text" "$path"; then
    fail "$path must contain: $text"
  fi
}

forbid_text() {
  local path="$1"
  local pattern="$2"
  local message="${3:-$path contains forbidden text matching: $pattern}"
  if [ -f "$path" ] && grep -Eq -- "$pattern" "$path"; then
    fail "$message"
  fi
}

service_section() {
  local service="$1"
  awk -v header="  ${service}:" '
    $0 == header { active = 1; print; next }
    active && /^  [a-zA-Z0-9][a-zA-Z0-9_-]*:$/ { exit }
    active { print }
  ' compose.yaml
}

require_service_image() {
  local service="$1"
  local expected_image="$2"
  local section

  section="$(service_section "$service")"
  if ! grep -Fqx "    image: $expected_image" <<<"$section"; then
    fail "$service must use exactly $expected_image"
  fi
}

require_service_healthcheck_test() {
  local service="$1"
  local expected_test="$2"
  local section

  section="$(service_section "$service")"
  if ! awk -v expected="$expected_test" '
    $0 == "    healthcheck:" { healthcheck = 1; next }
    healthcheck && /^    [^ ]/ { healthcheck = 0 }
    healthcheck && $0 == expected { found = 1 }
    END { exit found ? 0 : 1 }
  ' <<<"$section"; then
    fail "$service must retain its exact healthcheck command"
  fi
}

require_healthy_dependency() {
  local service="$1"
  local dependency="$2"
  local section

  section="$(service_section "$service")"
  if ! awk -v dependency="$dependency" '
    $0 == "    depends_on:" { depends_on = 1; next }
    depends_on && /^    [^ ]/ { depends_on = 0 }
    depends_on && $0 == "      " dependency ":" {
      if ((getline) > 0 && $0 == "        condition: service_healthy") {
        found = 1
      }
    }
    END { exit found ? 0 : 1 }
  ' <<<"$section"; then
    fail "$service must depend explicitly on a healthy $dependency"
  fi
}

for path in \
  compose.yaml \
  scripts/local-integration.sh \
  scripts/fetch-oci-attestation.py \
  docs/frontend-image-consumption.md \
  README.md \
  CHANGELOG.md \
  docs/roadmap.md; do
  require_file "$path"
done

if [ -f compose.yaml ]; then
  frontend_anchor_count="$(grep -Fxc 'x-frontend-image: &frontend-image >-' compose.yaml || true)"
  frontend_identity_count="$(grep -Fxc "  $FRONTEND_IMAGE" compose.yaml || true)"
  if [ "$frontend_anchor_count" -ne 1 ] || [ "$frontend_identity_count" -ne 1 ]; then
    fail "compose.yaml must define the canonical frontend OCI index digest anchor exactly once"
  fi

  frontend_section="$(service_section frontend)"
  if ! grep -Fqx '    image: *frontend-image' <<<"$frontend_section" ||
    grep -Eq '^    build:' <<<"$frontend_section"; then
    fail "frontend must use only the canonical digest anchor without a build block"
  fi

  require_text compose.yaml "$API_IMAGE"
  require_service_image postgres "$POSTGRES_IMAGE"
  require_service_image valkey "$VALKEY_IMAGE"

  for required_frontend_text in \
    '    user: "101:101"' \
    '      SECPAL_API_URL: https://api.secpal.example.invalid:${SECPAL_PHASE_B_PORT:-8443}' \
    '    read_only: true' \
    '      - /tmp:rw,noexec,nosuid,nodev,uid=101,gid=101,mode=0700,size=32m' \
    '    cap_drop:' \
    '      - ALL' \
    '      - no-new-privileges:true' \
    '    networks:' \
    '      - edge'; do
    if ! grep -Fqx "$required_frontend_text" <<<"$frontend_section"; then
      fail "frontend runtime contract is missing: $required_frontend_text"
    fi
  done
  if grep -Eq '^    ports:|^      - application$|^    privileged:|^    network_mode:' <<<"$frontend_section"; then
    fail "frontend must stay edge-only without public ports or elevated networking"
  fi
  require_service_healthcheck_test frontend '      test: ["CMD", "nginx", "-t"]'

  require_healthy_dependency gateway frontend

  forbid_text compose.yaml \
    'SECPAL_PHASE_B_FRONTEND_IMAGE|SecPal/frontend\.git|fcd427d9b55d7945c439c670077e12928e47ddd6' \
    "the historical frontend source build and image override must be absent"
  forbid_text compose.yaml \
    '\$\{[^}]*FRONTEND_(IMAGE|REGISTRY|REPOSITORY)[^}]*\}|\$\{[^}]*REGISTR(Y|IES)[^}]*\}' \
    "the frontend image identity must not be configurable"
  forbid_text compose.yaml \
    'ghcr\.io/secpal/frontend:(latest|main|build-|[A-Za-z0-9._-]+)|docker\.io/.*/frontend|secpal-frontend:' \
    "the frontend must not use a tag or Docker Hub fallback"
  forbid_text compose.yaml "$AMD64_CHILD_DIGEST|$ARM64_CHILD_DIGEST|$ATTESTATION_ARTIFACT_DIGEST" \
    "child or attestation artifact digests must not be deployment inputs"

  frontend_image_uses="$(grep -Fc 'image: *frontend-image' compose.yaml || true)"
  [ "$frontend_image_uses" -eq 1 ] ||
    fail "every frontend container instance must resolve through the one canonical index digest"
fi

if [ -f scripts/local-integration.sh ]; then
  require_text scripts/local-integration.sh "readonly EXPECTED_FRONTEND_IMAGE='$FRONTEND_IMAGE'"
  require_text scripts/local-integration.sh "readonly FRONTEND_SOURCE_COMMIT='$FRONTEND_SOURCE_COMMIT'"
  require_text scripts/local-integration.sh 'verify_published_image() {'
  require_text scripts/local-integration.sh 'verify_frontend_image() {'
  require_text scripts/local-integration.sh 'verify_frontend_image'
  require_text scripts/local-integration.sh 'SecPal/frontend'
  require_text scripts/local-integration.sh "$FRONTEND_WORKFLOW"
  require_text scripts/local-integration.sh 'refs/heads/main'
  require_text scripts/local-integration.sh '--deny-self-hosted-runners'
  require_text scripts/local-integration.sh 'env -u DOCKER_AUTH_CONFIG'
  require_text scripts/local-integration.sh 'DOCKER_CONFIG="$anonymous_docker_config"'
  require_text scripts/local-integration.sh 'docker pull "$canonical_image"'
  require_text scripts/local-integration.sh 'python3 "$ROOT_DIR/scripts/fetch-oci-attestation.py"'
  require_text scripts/local-integration.sh '"$canonical_image"'
  require_text scripts/local-integration.sh '"$canonical_digest"'
  require_text scripts/local-integration.sh '"$expected_registry_path"'
  require_text scripts/local-integration.sh '"$repository"'
  require_text scripts/local-integration.sh '"$publisher_workflow"'
  require_text scripts/local-integration.sh '"$source_ref"'
  require_text scripts/local-integration.sh '"$source_digest"'
  require_text scripts/local-integration.sh '"$signer_digest"'
  require_text scripts/local-integration.sh '"${COMPOSE[@]}" build gateway'
  forbid_text scripts/local-integration.sh \
    'SECPAL_PHASE_B_FRONTEND_IMAGE|build frontend|SecPal/frontend\.git|fcd427d9b55d7945c439c670077e12928e47ddd6' \
    "the lifecycle must not build or override the frontend image"
  forbid_text scripts/local-integration.sh \
    'docker[[:space:]]+(login|logout|push)|buildx[[:space:]]+push|manifest[[:space:]]+push|GHCR_TOKEN' \
    "the frontend verifier must remain anonymous and registry-read-only"
  forbid_text scripts/local-integration.sh \
    'ghcr\.io/secpal/frontend:(latest|main|build-)|\$\{[^}]*FRONTEND_IMAGE' \
    "the lifecycle must not accept a frontend tag fallback or image override"

  frontend_verify_calls="$(grep -Ec '^verify_frontend_image$' scripts/local-integration.sh || true)"
  [ "$frontend_verify_calls" -eq 1 ] ||
    fail "frontend verification must be one blocking lifecycle gate"
  frontend_verify_line="$(grep -nFx 'verify_frontend_image' scripts/local-integration.sh | cut -d: -f1 || true)"
  secrets_line="$(grep -nF '"${COMPOSE[@]}" up --detach postgres valkey' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  frontend_start_line="$(grep -nF 'api worker-hash-chain worker-general scheduler frontend gateway' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  if [ -z "$frontend_verify_line" ] || [ -z "$secrets_line" ] || [ -z "$frontend_start_line" ] ||
    [ "$frontend_verify_line" -ge "$secrets_line" ] || [ "$frontend_verify_line" -ge "$frontend_start_line" ]; then
    fail "blocking frontend verification must finish before secrets-init and frontend startup"
  fi
fi

if [ -f scripts/fetch-oci-attestation.py ]; then
  require_text scripts/fetch-oci-attestation.py 'Docker-Content-Digest'
  require_text scripts/fetch-oci-attestation.py 'registry digest header'
  require_text scripts/fetch-oci-attestation.py 'canonical_image'
  require_text scripts/fetch-oci-attestation.py 'canonical_digest'
  require_text scripts/fetch-oci-attestation.py 'expected_registry_path'
fi

require_text docs/frontend-image-consumption.md "$FRONTEND_IMAGE"
require_text docs/frontend-image-consumption.md "$FRONTEND_DIGEST"
require_text docs/frontend-image-consumption.md "$FRONTEND_SOURCE_COMMIT"
require_text docs/frontend-image-consumption.md 'Publisher run: `31247196734` (attempt `1`)'
require_text docs/frontend-image-consumption.md 'Artifact Attestation ID: `39567451`'
require_text docs/frontend-image-consumption.md 'Phase C.4 implementation is ready for review.'
require_text docs/frontend-image-consumption.md 'Phase C remains in progress.'
require_text docs/frontend-image-consumption.md 'requires a new reviewed deployment pull request'
require_text docs/frontend-image-consumption.md 'Rollback also requires a new reviewed pull request'
require_text README.md "$FRONTEND_IMAGE"
require_text README.md 'Phase C is in progress.'
require_text docs/roadmap.md 'Phase C — Immutable image publishing (in progress)'
require_text CHANGELOG.md 'Consume Verified Frontend Image Digest'

forbid_text README.md 'Phase C is complete|complete Phase C'
forbid_text docs/roadmap.md 'Phase C — Immutable image publishing \(complete\)|complete Phase C'
forbid_text docs/frontend-image-consumption.md 'Phase C is complete|Phase D is complete|production-ready'

if [ "$failures" -ne 0 ]; then
  printf 'Phase C.4 frontend image contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

if [ "${SECPAL_SKIP_PHASE_C4_NEGATIVE:-0}" -ne 1 ]; then
  negative_temp="$(mktemp -d -t secpal-phase-c4-contract.XXXXXXXXXX)"
  trap 'rm -rf -- "$negative_temp"' EXIT HUP INT TERM

  for mutation in \
    latest discovery-tag branch-tag amd64-child arm64-child attestation-artifact \
    registry repository environment-image source-build build-context image-override \
    verification-removed verification-after-start verification-nonblocking tag-fallback \
    docker-auth-inherited registry-login api-digest postgres-digest valkey-digest \
    gateway-frontend-unhealthy frontend-healthcheck-removed; do
    fixture="$negative_temp/$mutation"
    install -d -m 0700 "$fixture/docs" "$fixture/scripts" "$fixture/tests"
    cp compose.yaml README.md CHANGELOG.md "$fixture/"
    cp docs/frontend-image-consumption.md docs/roadmap.md "$fixture/docs/"
    cp scripts/local-integration.sh scripts/fetch-oci-attestation.py "$fixture/scripts/"
    cp tests/phase-c-frontend-image-contract.sh "$fixture/tests/"

    case "$mutation" in
      latest)
        sed -i "s|$FRONTEND_IMAGE|ghcr.io/secpal/frontend:latest|" "$fixture/compose.yaml"
        ;;
      discovery-tag)
        sed -i "s|$FRONTEND_IMAGE|ghcr.io/secpal/frontend:$DISCOVERY_TAG|" "$fixture/compose.yaml"
        ;;
      branch-tag)
        sed -i "s|$FRONTEND_IMAGE|ghcr.io/secpal/frontend:main|" "$fixture/compose.yaml"
        ;;
      amd64-child)
        sed -i "s|$FRONTEND_DIGEST|$AMD64_CHILD_DIGEST|" "$fixture/compose.yaml"
        ;;
      arm64-child)
        sed -i "s|$FRONTEND_DIGEST|$ARM64_CHILD_DIGEST|" "$fixture/compose.yaml"
        ;;
      attestation-artifact)
        sed -i "s|$FRONTEND_DIGEST|$ATTESTATION_ARTIFACT_DIGEST|" "$fixture/compose.yaml"
        ;;
      registry)
        sed -i "s|$FRONTEND_IMAGE|registry.example.invalid/secpal/frontend@$FRONTEND_DIGEST|" "$fixture/compose.yaml"
        ;;
      repository)
        sed -i "s|$FRONTEND_IMAGE|ghcr.io/secpal/not-frontend@$FRONTEND_DIGEST|" "$fixture/compose.yaml"
        ;;
      environment-image)
        sed -i "s|$FRONTEND_IMAGE|\${FRONTEND_IMAGE:-$FRONTEND_IMAGE}|" "$fixture/compose.yaml"
        ;;
      source-build)
        sed -i '/^  frontend:$/a\    build: https://github.com/SecPal/frontend.git#b755ca0d0ee5a85eca5ad5688d457241f070b1b4' "$fixture/compose.yaml"
        ;;
      build-context)
        sed -i '/^  frontend:$/a\    build:\n      context: https://github.com/SecPal/frontend.git#b755ca0d0ee5a85eca5ad5688d457241f070b1b4' "$fixture/compose.yaml"
        ;;
      image-override)
        sed -i "s|$FRONTEND_IMAGE|\${SECPAL_PHASE_B_FRONTEND_IMAGE:-$FRONTEND_IMAGE}|" "$fixture/compose.yaml"
        ;;
      verification-removed)
        sed -i '/^verify_frontend_image$/d' "$fixture/scripts/local-integration.sh"
        ;;
      verification-after-start)
        sed -i '/^verify_frontend_image$/d; /api worker-hash-chain worker-general scheduler frontend gateway/a verify_frontend_image' \
          "$fixture/scripts/local-integration.sh"
        ;;
      verification-nonblocking)
        sed -i 's/^verify_frontend_image$/verify_frontend_image || true/' "$fixture/scripts/local-integration.sh"
        ;;
      tag-fallback)
        sed -i "s|readonly EXPECTED_FRONTEND_IMAGE='$FRONTEND_IMAGE'|readonly EXPECTED_FRONTEND_IMAGE=\"\${FRONTEND_IMAGE:-ghcr.io/secpal/frontend:main}\"|" \
          "$fixture/scripts/local-integration.sh"
        ;;
      docker-auth-inherited)
        sed -i '/env -u DOCKER_AUTH_CONFIG \\/d' "$fixture/scripts/local-integration.sh"
        ;;
      registry-login)
        sed -i '/docker pull "$canonical_image"/i\  docker login ghcr.io' "$fixture/scripts/local-integration.sh"
        ;;
      api-digest)
        sed -i 's/5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e/6a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e/' \
          "$fixture/compose.yaml"
        ;;
      postgres-digest)
        sed -i 's/38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74/48471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74/' \
          "$fixture/compose.yaml"
        printf '# decoy only: %s\n' "$POSTGRES_IMAGE" >>"$fixture/compose.yaml"
        ;;
      valkey-digest)
        sed -i 's/3acc0687f2a2e1091fae6450d7842dd658c941338cf0a873ddd9e14b9e4ea4dd/4acc0687f2a2e1091fae6450d7842dd658c941338cf0a873ddd9e14b9e4ea4dd/' \
          "$fixture/compose.yaml"
        printf '# decoy only: %s\n' "$VALKEY_IMAGE" >>"$fixture/compose.yaml"
        ;;
      gateway-frontend-unhealthy)
        sed -i '/^      frontend:$/,/^    healthcheck:$/ s/^        condition: service_healthy$/        condition: service_started/' \
          "$fixture/compose.yaml"
        ;;
      frontend-healthcheck-removed)
        sed -i '/^  frontend:$/,/^  gateway:$/ { /^    healthcheck:$/,/^      start_period: 5s$/d; }' \
          "$fixture/compose.yaml"
        ;;
    esac

    if SECPAL_CONTRACT_ROOT="$fixture" SECPAL_SKIP_PHASE_C4_NEGATIVE=1 \
      bash "$fixture/tests/phase-c-frontend-image-contract.sh" >/dev/null 2>&1; then
      fail "the controlled $mutation mutation was not rejected"
    fi
  done

  rm -rf -- "$negative_temp"
  trap - EXIT HUP INT TERM
fi

if [ "$failures" -ne 0 ]; then
  printf 'Phase C.4 frontend negative contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Phase C.4 frontend image contract passed.\n'
