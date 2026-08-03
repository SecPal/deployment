#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

# Literal Compose and shell interpolations are part of the contract text.
# shellcheck disable=SC2016

ROOT_DIR="${SECPAL_CONTRACT_ROOT:-$(git rev-parse --show-toplevel)}"
cd "$ROOT_DIR"

readonly API_IMAGE='ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
readonly API_DIGEST='sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
readonly API_SOURCE_COMMIT='87d1432389adac3a02574b399322928a77c5e67f'
readonly API_WORKFLOW='SecPal/api/.github/workflows/publish-container.yml'

failures=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  if [ ! -f "$1" ]; then
    fail "required Phase C API image file is missing: $1"
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

compose_section() {
  local start="$1"
  awk -v start="$start" '
    $0 == start { active = 1; print; next }
    active && /^[^[:space:]]/ { exit }
    active { print }
  ' compose.yaml
}

service_section() {
  local service="$1"
  awk -v header="  ${service}:" '
    $0 == header { active = 1; print; next }
    active && /^  [a-zA-Z0-9][a-zA-Z0-9_-]*:$/ { exit }
    active { print }
  ' compose.yaml
}

for path in \
  compose.yaml \
  scripts/local-integration.sh \
  scripts/fetch-oci-attestation.py \
  docs/api-image-consumption.md \
  README.md \
  CHANGELOG.md \
  docs/roadmap.md \
  .github/workflows/local-integration.yml; do
  require_file "$path"
done

if [ -f compose.yaml ]; then
  api_anchor_count="$(grep -Fxc "x-api-image: &api-image $API_IMAGE" compose.yaml || true)"
  [ "$api_anchor_count" -eq 1 ] ||
    fail "compose.yaml must define the canonical API digest anchor exactly once"

  digest_hex="${API_IMAGE##*@sha256:}"
  if [[ "$API_IMAGE" != ghcr.io/secpal/api@sha256:* ]] ||
    [[ "$digest_hex" =~ [^0-9a-f] ]] || [ "${#digest_hex}" -ne 64 ]; then
    fail "the canonical API image constant must be a 64-character lowercase SHA-256 digest"
  fi

  forbid_text compose.yaml 'SecPal/api\.git|x-api-build|SECPAL_(PHASE_B_)?API_IMAGE|ghcr\.io/secpal/api:' \
    "compose.yaml must not contain an API source build, image override, fallback, or tag"
  forbid_text compose.yaml '\$\{[^}]*REGISTR(Y|IES)[^}]*\}|\$\{[^}]*API_(REGISTRY|REPOSITORY)[^}]*\}' \
    "the API registry and repository path must not be configurable"

  api_service="$(compose_section 'x-api-service: &api-service')"
  if ! grep -Fqx '  image: *api-image' <<<"$api_service" ||
    grep -Eq '^[[:space:]]+build:' <<<"$api_service"; then
    fail "x-api-service must use only the API digest anchor"
  fi

  secrets_section="$(service_section secrets-init)"
  if ! grep -Fqx '    image: *api-image' <<<"$secrets_section" ||
    grep -Eq '^    build:' <<<"$secrets_section"; then
    fail "secrets-init must use only the API digest anchor"
  fi

  for service in migrate api worker-hash-chain worker-general scheduler; do
    section="$(service_section "$service")"
    if ! grep -Fqx '    <<: *api-service' <<<"$section" ||
      grep -Eq '^    (image|build):' <<<"$section"; then
      fail "$service must inherit the shared digest-only API service contract"
    fi
  done

  require_text compose.yaml 'https://github.com/SecPal/frontend.git#fcd427d9b55d7945c439c670077e12928e47ddd6'
  require_text compose.yaml 'postgres:16.10-bookworm@sha256:'
  require_text compose.yaml 'valkey/valkey:9.1.1-trixie@sha256:'
fi

# Shell expressions below are intentionally matched as literal contract text.
# shellcheck disable=SC2016
if [ -f scripts/local-integration.sh ]; then
  require_text scripts/local-integration.sh 'require_command gh "GitHub CLI is required for API artifact attestation verification."'
  require_text scripts/local-integration.sh 'readonly ANONYMOUS_GH_CONFIG="$TEMP_DIR/anonymous-gh-config"'
  require_text scripts/local-integration.sh 'run_isolated_gh() {'
  require_text scripts/local-integration.sh 'GH_CONFIG_DIR="$ANONYMOUS_GH_CONFIG"'
  require_text scripts/local-integration.sh 'env -u GH_TOKEN -u GITHUB_TOKEN -u GH_ENTERPRISE_TOKEN -u GITHUB_ENTERPRISE_TOKEN -u GH_HOST'
  require_text scripts/local-integration.sh 'gh_version_output="$(run_isolated_gh version)"'
  require_text scripts/local-integration.sh 'run_isolated_gh attestation verify --help'
  forbid_text scripts/local-integration.sh 'EXPECTED_GH_VERSION|GitHub CLI .* is required; found' \
    "the integration must gate on attestation capability rather than an exact runner CLI patch version"
  require_text scripts/local-integration.sh 'ANON_DOCKER_CONFIG="$(mktemp -d -t secpal-api-anon-docker.XXXXXXXXXX)"'
  require_text scripts/local-integration.sh 'chmod 0700 "$ANON_DOCKER_CONFIG"'
  require_text scripts/local-integration.sh 'DOCKER_CONFIG="$ANON_DOCKER_CONFIG" docker pull "$API_IMAGE"'
  require_text scripts/local-integration.sh 'install -d -m 0700 "$ANONYMOUS_GH_CONFIG"'
  require_text scripts/local-integration.sh 'ATTESTATION_BUNDLE="$TEMP_DIR/api-attestation.json"'
  require_text scripts/local-integration.sh 'python3 "$ROOT_DIR/scripts/fetch-oci-attestation.py" "$ATTESTATION_BUNDLE"'
  require_text scripts/local-integration.sh 'run_isolated_gh attestation verify'
  require_text scripts/local-integration.sh '"oci://$API_IMAGE"'
  require_text scripts/local-integration.sh '--bundle "$ATTESTATION_BUNDLE"'
  require_text scripts/local-integration.sh '--repo SecPal/api'
  require_text scripts/local-integration.sh '--hostname github.com'
  require_text scripts/local-integration.sh "--signer-workflow $API_WORKFLOW"
  require_text scripts/local-integration.sh "--signer-digest $API_SOURCE_COMMIT"
  require_text scripts/local-integration.sh '--source-ref refs/heads/main'
  require_text scripts/local-integration.sh "--source-digest $API_SOURCE_COMMIT"
  require_text scripts/local-integration.sh '--deny-self-hosted-runners'
  require_text scripts/local-integration.sh '"${COMPOSE[@]}" --profile tools config --format json'
  require_text scripts/local-integration.sh '"${COMPOSE[@]}" build frontend gateway'
  require_text scripts/local-integration.sh '"${COMPOSE[@]}" --profile tools run --rm --no-TTY migrate'

  forbid_text scripts/local-integration.sh 'SECPAL_(PHASE_B_)?API_IMAGE|docker[[:space:]]+login|docker[[:space:]]+logout|GHCR_TOKEN' \
    "the integration runner must not expose an API override or registry credential path"
  forbid_text scripts/local-integration.sh '--bundle-from-oci' \
    "the integration runner must use the anonymously retrieved offline bundle"
  forbid_text scripts/local-integration.sh 'build.*(secrets-init|migrate|api|worker-hash-chain|worker-general|scheduler)' \
    "the integration runner must not build an API-based service"

  pull_line="$(grep -nF 'DOCKER_CONFIG="$ANON_DOCKER_CONFIG" docker pull "$API_IMAGE"' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  bundle_line="$(grep -nF 'python3 "$ROOT_DIR/scripts/fetch-oci-attestation.py" "$ATTESTATION_BUNDLE"' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  verify_line="$(grep -nF 'run_isolated_gh attestation verify' scripts/local-integration.sh | tail -n 1 | cut -d: -f1 || true)"
  build_line="$(grep -nF '"${COMPOSE[@]}" build frontend gateway' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  data_line="$(grep -nF '"${COMPOSE[@]}" up --detach postgres valkey' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  migrate_line="$(grep -nF '"${COMPOSE[@]}" --profile tools run --rm --no-TTY migrate' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  services_line="$(grep -nF 'if "${COMPOSE[@]}" up --detach' scripts/local-integration.sh | head -n 1 | cut -d: -f1 || true)"
  if [ -z "$pull_line" ] || [ -z "$bundle_line" ] || [ -z "$verify_line" ] || [ -z "$build_line" ] ||
    [ -z "$data_line" ] || [ -z "$migrate_line" ] || [ -z "$services_line" ] ||
    [ "$pull_line" -ge "$bundle_line" ] || [ "$bundle_line" -ge "$verify_line" ] ||
    [ "$verify_line" -ge "$build_line" ] ||
    [ "$build_line" -ge "$data_line" ] || [ "$data_line" -ge "$migrate_line" ] ||
    [ "$migrate_line" -ge "$services_line" ]; then
    fail "pull and attestation verification must precede every API execution in the lifecycle"
  fi
fi

if [ -f scripts/fetch-oci-attestation.py ]; then
  require_text scripts/fetch-oci-attestation.py 'REGISTRY = "ghcr.io"'
  require_text scripts/fetch-oci-attestation.py 'REPOSITORY = "secpal/api"'
  require_text scripts/fetch-oci-attestation.py "sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e"
  require_text scripts/fetch-oci-attestation.py 'https://ghcr.io/token?service=ghcr.io&scope=repository%3Asecpal%2Fapi%3Apull'
  require_text scripts/fetch-oci-attestation.py 'expected exactly one SLSA Sigstore bundle referrer'
  require_text scripts/fetch-oci-attestation.py 'OCI attestation subject digest was not the reviewed API digest'
  require_text scripts/fetch-oci-attestation.py 'REGISTRY_BLOB_PATH_PATTERN = re.compile('
  require_text scripts/fetch-oci-attestation.py 'GITHUB_BLOB_PATH_PATTERN = re.compile('
  require_text scripts/fetch-oci-attestation.py 'parsed.port in {None, 443}'
  require_text scripts/fetch-oci-attestation.py 'os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600'
  require_text scripts/fetch-oci-attestation.py 'if key.lower() != "authorization"'
  forbid_text scripts/fetch-oci-attestation.py 'ghcrblobs' \
    "the OCI bundle fetcher must accept the real GHCR CDN path, not a fixture-only prefix"
  forbid_text scripts/fetch-oci-attestation.py 'os\.environ|os\.getenv|GH_TOKEN|GITHUB_TOKEN|GHCR_TOKEN|docker[[:space:]]+login' \
    "the OCI bundle fetcher must not expose configuration or credential inputs"
fi

if [ -f .github/workflows/local-integration.yml ]; then
  permission_count="$(awk '
    /^permissions:$/ { active = 1; next }
    active && /^[^[:space:]]/ { active = 0 }
    active && /^  [a-zA-Z0-9_-]+:/ { count++ }
    END { print count + 0 }
  ' .github/workflows/local-integration.yml)"
  if [ "$permission_count" -ne 1 ] ||
    [ "$(grep -Ec '^  contents: read$' .github/workflows/local-integration.yml || true)" -ne 1 ]; then
    fail "the hosted integration workflow must retain only contents: read"
  fi
  forbid_text .github/workflows/local-integration.yml \
    'packages:[[:space:]]*write|attestations:[[:space:]]*write|id-token:[[:space:]]*write|docker/login-action|docker[[:space:]]+(login|push)|(^|[[:space:]])secrets\.' \
    "the hosted integration workflow must remain credential-free and publishing-free"
fi

require_text docs/api-image-consumption.md "$API_IMAGE"
require_text docs/api-image-consumption.md "$API_DIGEST"
require_text docs/api-image-consumption.md "$API_SOURCE_COMMIT"
# Backticks are literal Markdown, not shell substitutions.
# shellcheck disable=SC2016
require_text docs/api-image-consumption.md 'Publisher run: `30833321334` (attempt `1`)'
require_text docs/api-image-consumption.md 'not a deployment reference, rollback reference, or trust anchor'
require_text docs/api-image-consumption.md 'requires a new reviewed deployment pull request'
require_text docs/api-image-consumption.md 'Rollback also requires a new reviewed pull request'
require_text docs/api-image-consumption.md 'Phase C is in progress.'
require_text docs/api-image-consumption.md 'Frontend publication remains outstanding.'
require_text docs/api-image-consumption.md 'Phase D and production host automation remain outside this change.'
require_text README.md "$API_IMAGE"
require_text README.md 'Phase C is in progress.'
require_text README.md 'The runner does not provide a GitHub token to bypass'
# Backticks are literal Markdown, not shell substitutions.
# shellcheck disable=SC2016
require_text docs/api-image-consumption.md 'invokes `gh attestation verify --bundle` with the fixed GitHub.com hostname,'
forbid_text README.md 'real runner currently succeeds only|blocked before API execution'
forbid_text docs/api-image-consumption.md 'blocked at token-free attestation|blocked fail-closed target contract'
require_text docs/roadmap.md 'Phase C — Immutable image publishing (in progress)'
require_text docs/roadmap.md 'Frontend publication remains outstanding.'
require_text CHANGELOG.md 'Consume Verified API Image Digest'

forbid_text README.md 'SecPal deployment is production-ready|complete Phase C|Phase C is complete'
forbid_text docs/roadmap.md 'Phase C — Immutable image publishing \(complete\)|complete Phase C'
forbid_text docs/api-image-consumption.md 'SecPal deployment is production-ready|Phase D is complete|Managed hosting is implemented|complete Phase C'

if [ "$failures" -ne 0 ]; then
  printf 'Phase C API image contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

if [ "${SECPAL_SKIP_PHASE_C_NEGATIVE:-0}" -ne 1 ]; then
  negative_temp="$(mktemp -d -t secpal-phase-c-contract.XXXXXXXXXX)"
  trap 'rm -rf -- "$negative_temp"' EXIT HUP INT TERM

  for mutation in \
    wrong-digest tag registry repository api-build environment-override \
    github-config-override github-host-override github-host-flag \
    bundle-fetch-bypass fetcher-wrong-digest; do
    fixture="$negative_temp/$mutation"
    install -d -m 0700 \
      "$fixture/.github/workflows" "$fixture/docs" "$fixture/scripts" "$fixture/tests"
    cp compose.yaml README.md CHANGELOG.md "$fixture/"
    cp .github/workflows/local-integration.yml "$fixture/.github/workflows/"
    cp docs/api-image-consumption.md docs/roadmap.md "$fixture/docs/"
    cp scripts/local-integration.sh scripts/fetch-oci-attestation.py "$fixture/scripts/"
    cp tests/phase-c-api-image-contract.sh "$fixture/tests/"

    case "$mutation" in
      wrong-digest)
        sed -i 's/5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e/6a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e/' \
          "$fixture/compose.yaml"
        ;;
      tag)
        sed -i "s|x-api-image: &api-image $API_IMAGE|x-api-image: \&api-image ghcr.io/secpal/api:main|" \
          "$fixture/compose.yaml"
        ;;
      registry)
        sed -i "s|x-api-image: &api-image $API_IMAGE|x-api-image: \&api-image registry.example.invalid/secpal/api@$API_DIGEST|" \
          "$fixture/compose.yaml"
        ;;
      repository)
        sed -i "s|x-api-image: &api-image $API_IMAGE|x-api-image: \&api-image ghcr.io/secpal/not-api@$API_DIGEST|" \
          "$fixture/compose.yaml"
        ;;
      api-build)
        sed -i '/^x-api-image:/a x-api-build: \&api-build\n  context: https://github.com/SecPal/api.git#87d1432389adac3a02574b399322928a77c5e67f' \
          "$fixture/compose.yaml"
        ;;
      environment-override)
        sed -i "s|x-api-image: &api-image $API_IMAGE|x-api-image: \&api-image \${SECPAL_API_IMAGE:-$API_IMAGE}|" \
          "$fixture/compose.yaml"
        ;;
      github-config-override)
        # The shell expression is intentional literal contract text.
        # shellcheck disable=SC2016
        sed -i '/GH_CONFIG_DIR="\$ANONYMOUS_GH_CONFIG"/d' \
          "$fixture/scripts/local-integration.sh"
        ;;
      github-host-override)
        sed -i 's/ -u GH_HOST//' "$fixture/scripts/local-integration.sh"
        ;;
      github-host-flag)
        sed -i '/--hostname github.com/d' "$fixture/scripts/local-integration.sh"
        ;;
      bundle-fetch-bypass)
        # The shell expressions are intentional literal contract text.
        # shellcheck disable=SC2016
        sed -i 's|python3 "\$ROOT_DIR/scripts/fetch-oci-attestation.py" "\$ATTESTATION_BUNDLE"|true|' \
          "$fixture/scripts/local-integration.sh"
        ;;
      fetcher-wrong-digest)
        sed -i 's/5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e/6a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e/' \
          "$fixture/scripts/fetch-oci-attestation.py"
        ;;
    esac

    if SECPAL_CONTRACT_ROOT="$fixture" SECPAL_SKIP_PHASE_C_NEGATIVE=1 \
      bash "$fixture/tests/phase-c-api-image-contract.sh" >/dev/null 2>&1; then
      fail "the controlled $mutation mutation was not rejected"
    fi
  done

  rm -rf -- "$negative_temp"
  trap - EXIT HUP INT TERM
fi

if [ "$failures" -ne 0 ]; then
  printf 'Phase C API image negative contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Phase C API image contract passed.\n'
