#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
TEMP_DIR="$(mktemp -d)"
FAKE_BIN="$TEMP_DIR/bin"
COMMAND_LOG="$TEMP_DIR/docker.log"
CURL_LOG="$TEMP_DIR/curl.log"
PERSISTENT_GH_CONFIG="$TEMP_DIR/persistent-gh-config"
PERSISTENT_DOCKER_CONFIG="$TEMP_DIR/persistent-docker-config"
children=()
failures=0

cleanup() {
  local child
  for child in "${children[@]}"; do
    kill "$child" >/dev/null 2>&1 || true
    wait "$child" >/dev/null 2>&1 || true
  done
  rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

wait_for_file() {
  local path="$1"
  local _attempt
  for _attempt in $(seq 1 200); do
    if [ -e "$path" ]; then
      return 0
    fi
    /usr/bin/sleep 0.01
  done
  return 1
}

wait_for_exit() {
  local pid="$1"
  local state
  local _attempt

  for _attempt in $(seq 1 200); do
    if [ ! -r "/proc/$pid/stat" ]; then
      return 0
    fi
    state="$(awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null || true)"
    if [ -z "$state" ]; then
      return 0
    fi
    if [ "$state" = Z ]; then
      return 0
    fi
    /usr/bin/sleep 0.01
  done
  return 1
}

install -d -m 0700 "$FAKE_BIN"
cp "$ROOT_DIR/tests/fixtures/fake-docker.sh" "$FAKE_BIN/docker"
cp "$ROOT_DIR/tests/fixtures/fake-curl.sh" "$FAKE_BIN/curl"
cp "$ROOT_DIR/tests/fixtures/fake-gh.sh" "$FAKE_BIN/gh"
cp "$ROOT_DIR/tests/fixtures/fake-python3.sh" "$FAKE_BIN/python3"
chmod 0700 "$FAKE_BIN/docker" "$FAKE_BIN/curl" "$FAKE_BIN/gh" "$FAKE_BIN/python3"
: >"$COMMAND_LOG"
: >"$CURL_LOG"
install -d -m 0700 "$PERSISTENT_GH_CONFIG"
printf 'credentialed configuration must remain isolated\n' >"$PERSISTENT_GH_CONFIG/hosts.yml"
install -d -m 0700 "$PERSISTENT_DOCKER_CONFIG"
printf '{"auths":{"ghcr.io":{"auth":"forbidden-file-fixture"}}}\n' \
  >"$PERSISTENT_DOCKER_CONFIG/config.json"
INHERITED_GH_ENVIRONMENT=(
  GH_CONFIG_DIR="$PERSISTENT_GH_CONFIG"
  GH_TOKEN=must-be-unset
  GITHUB_TOKEN=must-be-unset
  GH_ENTERPRISE_TOKEN=must-be-unset
  GITHUB_ENTERPRISE_TOKEN=must-be-unset
  GH_HOST=ghe.example.invalid
)
INHERITED_DOCKER_ENVIRONMENT=(
  DOCKER_CONFIG="$PERSISTENT_DOCKER_CONFIG"
  DOCKER_AUTH_CONFIG='{"auths":{"ghcr.io":{"auth":"forbidden-fixture"}}}'
  SECPAL_TEST_PERSISTENT_DOCKER_CONFIG="$PERSISTENT_DOCKER_CONFIG"
)

# The resolved Compose fixture emits the reviewed image for the API roles.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'if [ "${1:-}" = - ]; then' \
  '  while IFS= read -r _line; do :; done' \
  '  printf "%s\n%s\n" "ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e" "ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077"' \
  'fi' \
  'exit 0' \
  >"$FAKE_BIN/node"
# The fixture expands only when the generated npm script runs.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'printf "%s\t\t\t\t\t\t%s\n" "${SECPAL_TEST_RUN_ID:-unknown}" "npm $*" >>"${SECPAL_TEST_COMMAND_LOG:?}"' \
  'if [ "${SECPAL_TEST_FAIL_BROWSER:-0}" -eq 1 ]; then exit 74; fi' \
  'exit 0' \
  >"$FAKE_BIN/npm"
chmod 0700 "$FAKE_BIN/node" "$FAKE_BIN/npm"

printf '%s\n' '#!/bin/sh' 'printf "%s\n" "docker-compose version 1.29.2"' \
  >"$FAKE_BIN/docker-compose"
chmod 0700 "$FAKE_BIN/docker-compose"
legacy_output="$TEMP_DIR/legacy-compose.out"
if env \
  PATH="$FAKE_BIN:$PATH" \
  "${INHERITED_GH_ENVIRONMENT[@]}" \
  SECPAL_PHASE_B_PORT=18442 \
  SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
  SECPAL_TEST_CURL_LOG="$CURL_LOG" \
  SECPAL_TEST_DOCKER_COMPOSE_V2=0 \
  SECPAL_TEST_RUN_ID=legacy-compose \
  bash "$ROOT_DIR/scripts/local-integration.sh" >"$legacy_output" 2>&1; then
  fail "legacy Docker Compose v1 was accepted"
elif ! grep -Fq 'Docker Compose v2 is required.' "$legacy_output"; then
  fail "legacy Docker Compose v1 did not fail at the version gate"
fi
rm "$FAKE_BIN/docker-compose"

python_count="$TEMP_DIR/python-count"
port_attempts="$TEMP_DIR/port-attempts"
gateway_failure_marker="$TEMP_DIR/gateway-failed"
# Generate a fixture that expands in its own process.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'if [ "${1##*/}" = fetch-oci-attestation.py ]; then' \
  '  subject_path="${2:?}"' \
  '  bundle_path="${3:?}"' \
  '  canonical_image="${4:?}"' \
  '  canonical_digest="${5:?}"' \
  '  expected_registry_path="${6:?}"' \
  '  printf "%s\t\t\t\t\t\tpython3 fetch-oci-attestation %s %s %s %s %s\t%s\t%s\n" "${SECPAL_TEST_RUN_ID:-unknown}" "$subject_path" "$bundle_path" "$canonical_image" "$canonical_digest" "$expected_registry_path" "${DOCKER_CONFIG:-}" "${GH_CONFIG_DIR:-}" >>"${SECPAL_TEST_COMMAND_LOG:?}"' \
  '  (umask 077 && printf "{\"fixture\":\"oci-index\"}\n" >"$subject_path")' \
  '  (umask 077 && printf "{\"fixture\":\"offline-attestation\"}\n" >"$bundle_path")' \
  '  chmod 0600 "$subject_path" "$bundle_path"' \
  '  exit 0' \
  'fi' \
  'count=0' \
  'if [ -f "$SECPAL_TEST_PYTHON_COUNT" ]; then count="$(cat "$SECPAL_TEST_PYTHON_COUNT")"; fi' \
  'count=$((count + 1))' \
  'printf "%s\n" "$count" >"$SECPAL_TEST_PYTHON_COUNT"' \
  'if [ "$count" -eq 1 ]; then printf "18445\n"; else printf "18446\n"; fi' \
  >"$FAKE_BIN/python3"
chmod 0700 "$FAKE_BIN/python3"
if ! env \
  PATH="$FAKE_BIN:$PATH" \
  "${INHERITED_GH_ENVIRONMENT[@]}" \
  SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
  SECPAL_TEST_CURL_LOG="$CURL_LOG" \
  SECPAL_TEST_FAIL_GATEWAY_ONCE_MARKER="$gateway_failure_marker" \
  SECPAL_TEST_PORT_ATTEMPT_LOG="$port_attempts" \
  SECPAL_TEST_PYTHON_COUNT="$python_count" \
  SECPAL_TEST_RUN_ID=port-retry \
  bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/port-retry.out" 2>&1; then
  fail "an automatic loopback-port collision was not retried"
elif [ "$(sort -u "$port_attempts" 2>/dev/null | wc -l)" -ne 2 ]; then
  fail "the loopback-port retry did not select a new port"
fi
cp "$ROOT_DIR/tests/fixtures/fake-python3.sh" "$FAKE_BIN/python3"
chmod 0700 "$FAKE_BIN/python3"
: >"$COMMAND_LOG"
: >"$CURL_LOG"

for invalid_port in invalid 80 65536; do
  if env \
    PATH="$FAKE_BIN:$PATH" \
    "${INHERITED_GH_ENVIRONMENT[@]}" \
    SECPAL_PHASE_B_PORT="$invalid_port" \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_CURL_LOG="$CURL_LOG" \
    SECPAL_TEST_RUN_ID=invalid-port \
    bash "$ROOT_DIR/scripts/local-integration.sh" >/dev/null 2>&1; then
    fail "invalid loopback port was accepted: $invalid_port"
  fi
done

: >"$COMMAND_LOG"
if env \
  PATH="$FAKE_BIN:$PATH" \
  "${INHERITED_GH_ENVIRONMENT[@]}" \
  "${INHERITED_DOCKER_ENVIRONMENT[@]}" \
  SECPAL_PHASE_B_PORT=18441 \
  SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
  SECPAL_TEST_CURL_LOG="$CURL_LOG" \
  SECPAL_TEST_GH_VERSION=2.96.0 \
  SECPAL_TEST_RUN_ID=gh-version-mismatch \
  bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/gh-version-mismatch.out" 2>&1; then
  fail "an unreviewed GitHub CLI version was accepted"
elif ! grep -Fq 'GitHub CLI 2.97.0 is required; found gh version 2.96.0 (fixture).' \
  "$TEMP_DIR/gh-version-mismatch.out"; then
  fail "the GitHub CLI version mismatch did not fail at the exact version gate"
fi
if awk -F '\t' '$1 == "gh-version-mismatch" && $7 ~ /^pull / { found = 1 } END { exit !found }' \
  "$COMMAND_LOG"; then
  fail "an unreviewed GitHub CLI version reached the API pull"
fi

: >"$COMMAND_LOG"
if ! env \
  PATH="$FAKE_BIN:$PATH" \
  "${INHERITED_GH_ENVIRONMENT[@]}" \
  "${INHERITED_DOCKER_ENVIRONMENT[@]}" \
  SECPAL_PHASE_B_PORT=18441 \
  SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
  SECPAL_TEST_CURL_LOG="$CURL_LOG" \
  SECPAL_TEST_GH_VERSION=2.97.0 \
  SECPAL_TEST_RUN_ID=gh-version \
  bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/gh-version.out" 2>&1; then
  fail "the reviewed GitHub CLI version was rejected"
fi
if ! grep -Fq 'GitHub CLI: gh version 2.97.0 (fixture)' "$TEMP_DIR/gh-version.out"; then
  fail "the exact reviewed GitHub CLI version was not logged"
fi
if [ "$(awk -F '\t' '$1 == "gh-version" && $7 ~ /^pull / { count++ } END { print count + 0 }' "$COMMAND_LOG")" -ne 2 ]; then
  fail "the capable hosted-runner GitHub CLI did not reach both image pulls"
fi
if ! grep -Fq 'pull ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e' "$COMMAND_LOG" ||
  ! grep -Fq 'pull ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077' "$COMMAND_LOG"; then
  fail "the lifecycle did not pull both exact canonical image digests"
fi
if awk -F '\t' '$1 == "gh-version" && $7 ~ /^pull / && $9 != "unset" { found = 1 } END { exit !found }' \
  "$COMMAND_LOG"; then
  fail "caller-provided DOCKER_AUTH_CONFIG reached an image pull"
fi
mapfile -t successful_anon_configs < <(awk -F '\t' '$1 == "gh-version" && $7 ~ /^pull / { print $8 }' "$COMMAND_LOG")
if [ "${#successful_anon_configs[@]}" -ne 2 ] ||
  [ "${successful_anon_configs[0]}" = "${successful_anon_configs[1]}" ]; then
  fail "the two image pulls did not use separate anonymous Docker configurations"
fi
for successful_anon_config in "${successful_anon_configs[@]}"; do
  if [ -z "$successful_anon_config" ] || [ -e "$successful_anon_config" ]; then
    fail "a successful credential-free pull did not remove its anonymous Docker configuration"
  fi
done

for direct_image in \
  ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e \
  ghcr.io/secpal/frontend@sha256:cdccded2eade53d9300aafff3a2663a779d3d158cfa74f1e9c182e5786285077; do
  direct_anon_config="$TEMP_DIR/direct-anonymous-docker-config-${direct_image#ghcr.io/secpal/}"
  install -d -m 0700 "$direct_anon_config"
  if env \
    DOCKER_CONFIG="$direct_anon_config" \
    DOCKER_AUTH_CONFIG='{"auths":{"ghcr.io":{"auth":"forbidden-direct-fixture"}}}' \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_PERSISTENT_DOCKER_CONFIG="$PERSISTENT_DOCKER_CONFIG" \
    SECPAL_TEST_RUN_ID=docker-auth-contract-violation \
    "$FAKE_BIN/docker" pull "$direct_image"; then
    fail "fake Docker accepted an image pull with DOCKER_AUTH_CONFIG"
  fi
  rm -rf -- "$direct_anon_config"
done

: >"$COMMAND_LOG"
if env \
  PATH="$FAKE_BIN:$PATH" \
  "${INHERITED_GH_ENVIRONMENT[@]}" \
  SECPAL_PHASE_B_PORT=18441 \
  SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
  SECPAL_TEST_CURL_LOG="$CURL_LOG" \
  SECPAL_TEST_GH_ATTESTATION_UNAVAILABLE=1 \
  SECPAL_TEST_RUN_ID=gh-capability \
  bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/gh-capability.out" 2>&1; then
  fail "a GitHub CLI without attestation verification support was accepted"
elif ! grep -Fq 'the installed GitHub CLI does not support artifact attestation verification.' \
  "$TEMP_DIR/gh-capability.out"; then
  fail "the missing GitHub CLI capability did not fail at the capability gate"
fi
if awk -F '\t' '$1 == "gh-capability" && $7 ~ /^pull / { found = 1 } END { exit !found }' "$COMMAND_LOG"; then
  fail "a GitHub CLI without attestation verification support reached the API pull"
fi

for gate_case in pull bundle attestation wrong-source-commit wrong-workflow wrong-subject-digest wrong-subject-name self-hosted; do
  : >"$COMMAND_LOG"
  run_id="gate-$gate_case"
  gate_environment=(SECPAL_TEST_ATTESTATION_RESULT=success)
  if [ "$gate_case" = pull ]; then
    gate_environment=(SECPAL_TEST_FAIL_PULL=1)
  elif [ "$gate_case" = bundle ]; then
    gate_environment=(SECPAL_TEST_FAIL_ATTESTATION_FETCH=1)
  elif [ "$gate_case" != attestation ]; then
    gate_environment=("SECPAL_TEST_ATTESTATION_RESULT=$gate_case")
  else
    gate_environment=(SECPAL_TEST_ATTESTATION_RESULT=failure)
  fi

  if env \
    PATH="$FAKE_BIN:$PATH" \
    "${INHERITED_GH_ENVIRONMENT[@]}" \
    "${INHERITED_DOCKER_ENVIRONMENT[@]}" \
    SECPAL_PHASE_B_PORT=18441 \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_CURL_LOG="$CURL_LOG" \
    SECPAL_TEST_RUN_ID="$run_id" \
    "${gate_environment[@]}" \
    bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/$run_id.out" 2>&1; then
    fail "$gate_case gate failure returned success"
  fi

  expected_attestation_error=
  case "$gate_case" in
    attestation) expected_attestation_error='fixture rejected the attestation verification request' ;;
    wrong-source-commit) expected_attestation_error='fixture rejected source digest mismatch' ;;
    wrong-workflow) expected_attestation_error='fixture rejected signer workflow mismatch' ;;
    wrong-subject-digest) expected_attestation_error='fixture rejected subject digest mismatch' ;;
    wrong-subject-name) expected_attestation_error='fixture rejected subject name mismatch' ;;
    self-hosted) expected_attestation_error='fixture rejected self-hosted runner' ;;
  esac
  if [ -n "$expected_attestation_error" ] &&
    ! grep -Fq "$expected_attestation_error" "$TEMP_DIR/$run_id.out"; then
    fail "$gate_case did not exercise its distinct attestation identity failure"
  fi

  if awk -F '\t' -v run_id="$run_id" '$1 == run_id &&
    ($7 ~ /up --detach postgres valkey|--profile tools run --rm --no-TTY migrate|up --detach api|exec -T (api|worker)/) { found = 1 }
    END { exit !found }' "$COMMAND_LOG"; then
    fail "$gate_case gate failure allowed an API-based container operation"
  fi

  anon_config="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^pull / { print $8; exit }' "$COMMAND_LOG")"
  if [ -z "$anon_config" ] || [ -e "$anon_config" ]; then
    fail "$gate_case gate failure did not remove its anonymous Docker configuration"
  fi
  subject_path="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^python3 fetch-oci-attestation / { print $7; exit }' "$COMMAND_LOG" | awk '{ print $3 }')"
  bundle_path="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^python3 fetch-oci-attestation / { print $7; exit }' "$COMMAND_LOG" | awk '{ print $4 }')"
  if [ "$gate_case" != pull ] && { [ -z "$subject_path" ] || [ -e "$subject_path" ] ||
    [ -z "$bundle_path" ] || [ -e "$bundle_path" ]; }; then
    fail "$gate_case did not remove its local OCI subject and offline attestation bundle"
  fi
  if [ "$gate_case" != pull ] && [ "$gate_case" != bundle ]; then
    anonymous_gh_config="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^gh attestation verify / { print $9; exit }' "$COMMAND_LOG")"
    if [ -z "$anonymous_gh_config" ] ||
      [ "$anonymous_gh_config" = "$PERSISTENT_GH_CONFIG" ] ||
      [ -e "$anonymous_gh_config" ]; then
      fail "$gate_case did not isolate and remove its anonymous GitHub CLI configuration"
    fi
  fi
done

: >"$COMMAND_LOG"
for gate_case in \
  pull bundle attestation wrong-source-commit wrong-signer-digest wrong-workflow \
  wrong-repository wrong-source-ref wrong-subject-digest wrong-subject-name self-hosted; do
  : >"$COMMAND_LOG"
  run_id="frontend-gate-$gate_case"
  gate_environment=(SECPAL_TEST_FRONTEND_ATTESTATION_RESULT=success)
  case "$gate_case" in
    pull) gate_environment=(SECPAL_TEST_FAIL_FRONTEND_PULL=1) ;;
    bundle) gate_environment=(SECPAL_TEST_FAIL_FRONTEND_ATTESTATION_FETCH=1) ;;
    attestation) gate_environment=(SECPAL_TEST_FRONTEND_ATTESTATION_RESULT=failure) ;;
    *) gate_environment=("SECPAL_TEST_FRONTEND_ATTESTATION_RESULT=$gate_case") ;;
  esac

  if env \
    PATH="$FAKE_BIN:$PATH" \
    "${INHERITED_GH_ENVIRONMENT[@]}" \
    "${INHERITED_DOCKER_ENVIRONMENT[@]}" \
    SECPAL_PHASE_B_PORT=18441 \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_CURL_LOG="$CURL_LOG" \
    SECPAL_TEST_RUN_ID="$run_id" \
    "${gate_environment[@]}" \
    bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/$run_id.out" 2>&1; then
    fail "frontend $gate_case gate failure returned success"
  fi

  expected_attestation_error=
  case "$gate_case" in
    attestation) expected_attestation_error='fixture rejected the attestation verification request' ;;
    wrong-source-commit) expected_attestation_error='fixture rejected source digest mismatch' ;;
    wrong-signer-digest) expected_attestation_error='fixture rejected signer digest mismatch' ;;
    wrong-workflow) expected_attestation_error='fixture rejected signer workflow mismatch' ;;
    wrong-repository) expected_attestation_error='fixture rejected repository mismatch' ;;
    wrong-source-ref) expected_attestation_error='fixture rejected source ref mismatch' ;;
    wrong-subject-digest) expected_attestation_error='fixture rejected subject digest mismatch' ;;
    wrong-subject-name) expected_attestation_error='fixture rejected subject name mismatch' ;;
    self-hosted) expected_attestation_error='fixture rejected self-hosted runner' ;;
  esac
  if [ -n "$expected_attestation_error" ] &&
    ! grep -Fq "$expected_attestation_error" "$TEMP_DIR/$run_id.out"; then
    fail "frontend $gate_case did not exercise its distinct identity failure"
  fi

  if awk -F '\t' -v run_id="$run_id" '$1 == run_id &&
    ($7 ~ /up --detach postgres valkey|--profile tools run --rm --no-TTY migrate|up --detach api|exec -T (api|worker)/) { found = 1 }
    END { exit !found }' "$COMMAND_LOG"; then
    fail "frontend $gate_case gate failure allowed a container to start"
  fi
  if ! awk -F '\t' -v run_id="$run_id" '$1 == run_id &&
    $7 ~ /^gh attestation verify .*api-image-index\.json/ { found = 1 } END { exit !found }' \
    "$COMMAND_LOG"; then
    fail "frontend $gate_case did not run after successful API verification"
  fi

  while IFS= read -r anonymous_config; do
    if [ -z "$anonymous_config" ] || [ -e "$anonymous_config" ]; then
      fail "frontend $gate_case did not remove an anonymous Docker configuration"
    fi
  done < <(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^pull / { print $8 }' "$COMMAND_LOG")

  while IFS= read -r private_path; do
    if [ -z "$private_path" ] || [ -e "$private_path" ]; then
      fail "frontend $gate_case did not remove a local OCI verification file"
    fi
  done < <(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^python3 fetch-oci-attestation / { print $7 }' "$COMMAND_LOG" | awk '{ print $3; print $4 }')
done

: >"$COMMAND_LOG"
: >"$CURL_LOG"

pause_marker="$TEMP_DIR/paused"
release_marker="$TEMP_DIR/release"
env \
  PATH="$FAKE_BIN:$PATH" \
  "${INHERITED_GH_ENVIRONMENT[@]}" \
  "${INHERITED_DOCKER_ENVIRONMENT[@]}" \
  SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
  SECPAL_TEST_CURL_LOG="$CURL_LOG" \
  SECPAL_TEST_PAUSE_MARKER="$pause_marker" \
  SECPAL_TEST_RELEASE_MARKER="$release_marker" \
  SECPAL_TEST_RUN_ID=signal \
  bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/signal.out" 2>&1 &
signal_pid=$!
children+=("$signal_pid")

if ! wait_for_file "$pause_marker"; then
  fail "the signal fixture did not reach its controlled pause"
else
  kill -TERM "$signal_pid"
  if ! wait_for_exit "$signal_pid"; then
    : >"$release_marker"
    if ! wait_for_exit "$signal_pid"; then
      kill -KILL "$signal_pid" >/dev/null 2>&1 || true
    fi
    wait "$signal_pid" >/dev/null 2>&1 || true
    fail "the integration script did not interrupt a blocked child after SIGTERM"
  elif wait "$signal_pid"; then
    fail "the integration script returned success after SIGTERM"
  fi
  if ! grep -Fq -- 'down --volumes --remove-orphans' "$COMMAND_LOG"; then
    fail "the integration script did not clean up after SIGTERM"
  fi
  if grep -Fq -- '--profile tools run --rm --no-TTY migrate' "$COMMAND_LOG"; then
    fail "the integration script executed work after handling SIGTERM"
  fi
  signal_anon_config="$(awk -F '\t' '$1 == "signal" && $7 ~ /^pull / { print $8; exit }' "$COMMAND_LOG")"
  if [ -z "$signal_anon_config" ] || [ -e "$signal_anon_config" ]; then
    fail "the integration script did not remove its anonymous Docker configuration after SIGTERM"
  fi
  signal_gh_config="$(awk -F '\t' '$1 == "signal" && $7 ~ /^gh attestation verify / { print $9; exit }' "$COMMAND_LOG")"
  if [ -z "$signal_gh_config" ] || [ "$signal_gh_config" = "$PERSISTENT_GH_CONFIG" ] ||
    [ -e "$signal_gh_config" ]; then
    fail "the integration script did not isolate and remove its GitHub CLI configuration after SIGTERM"
  fi
  signal_subject="$(awk -F '\t' '$1 == "signal" && $7 ~ /^python3 fetch-oci-attestation / { print $7; exit }' "$COMMAND_LOG" | awk '{ print $3 }')"
  signal_bundle="$(awk -F '\t' '$1 == "signal" && $7 ~ /^python3 fetch-oci-attestation / { print $7; exit }' "$COMMAND_LOG" | awk '{ print $4 }')"
  if [ -z "$signal_subject" ] || [ -e "$signal_subject" ] ||
    [ -z "$signal_bundle" ] || [ -e "$signal_bundle" ]; then
    fail "the integration script did not remove its local OCI subject and offline bundle after SIGTERM"
  fi
fi
children=()

: >"$COMMAND_LOG"
: >"$CURL_LOG"
parallel_pids=()
for specification in one:18443 two:18444; do
  run_id="${specification%%:*}"
  port="${specification##*:}"
  env \
    PATH="$FAKE_BIN:$PATH" \
    "${INHERITED_GH_ENVIRONMENT[@]}" \
    SECPAL_PHASE_B_PORT="$port" \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_CURL_LOG="$CURL_LOG" \
    SECPAL_TEST_RUN_ID="$run_id" \
    bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/$run_id.out" 2>&1 &
  parallel_pids+=("$!")
done
children=("${parallel_pids[@]}")

for child in "${parallel_pids[@]}"; do
  if ! wait "$child"; then
    fail "a parallel integration fixture failed"
  fi
done
children=()

for specification in one:18443 two:18444; do
  run_id="${specification%%:*}"
  port="${specification##*:}"
  run_curl_log="$TEMP_DIR/$run_id.curl"
  grep -F "$run_id"$'\t' "$CURL_LOG" >"$run_curl_log" || true
  if ! grep -Fq "$run_id"$'\t' "$COMMAND_LOG" ||
    ! grep -Fq "app.secpal.example.invalid:$port:127.0.0.1" "$run_curl_log" ||
    ! grep -Fq "api.secpal.example.invalid:$port:127.0.0.1" "$run_curl_log"; then
    fail "parallel run $run_id did not use both isolated loopback origins"
  fi
  for rejected_frontend_path in \
    /v1/phase-b-not-an-api-route /sanctum/csrf-cookie /health/ready; do
    if ! grep -Fq "https://app.secpal.example.invalid:$port$rejected_frontend_path" \
      "$run_curl_log"; then
      fail "parallel run $run_id did not reject frontend path $rejected_frontend_path"
    fi
  done
done

one_frontend_override="$(awk -F '\t' '$1 == "one" { print $3; exit }' "$COMMAND_LOG")"
two_frontend_override="$(awk -F '\t' '$1 == "two" { print $3; exit }' "$COMMAND_LOG")"
one_gateway_image="$(awk -F '\t' '$1 == "one" { print $4; exit }' "$COMMAND_LOG")"
two_gateway_image="$(awk -F '\t' '$1 == "two" { print $4; exit }' "$COMMAND_LOG")"
if [ -n "$one_frontend_override" ] || [ -n "$two_frontend_override" ]; then
  fail "parallel runs exported a forbidden frontend image override"
fi
if [ -z "$one_gateway_image" ] || [ -z "$two_gateway_image" ] ||
  [ "$one_gateway_image" = "$two_gateway_image" ]; then
  fail "parallel runs did not use distinct project-scoped gateway image tags"
fi

one_project="$(awk -F '\t' '$1 == "one" { count = split($7, part, " "); for (position = 1; position <= count; position++) if (part[position] == "--project-name") { print part[position + 1]; exit } }' "$COMMAND_LOG")"
two_project="$(awk -F '\t' '$1 == "two" { count = split($7, part, " "); for (position = 1; position <= count; position++) if (part[position] == "--project-name") { print part[position + 1]; exit } }' "$COMMAND_LOG")"
if [ -z "$one_project" ] || [ -z "$two_project" ] || [ "$one_project" = "$two_project" ]; then
  fail "parallel runs did not use distinct random Compose projects"
fi

for specification in one:18443 two:18444; do
  run_id="${specification%%:*}"
  hash_chain_name="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id { print $5; exit }' "$COMMAND_LOG")"
  scheduler_name="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id { print $6; exit }' "$COMMAND_LOG")"
  if [ -z "$hash_chain_name" ] || [ -z "$scheduler_name" ] ||
    [ "$hash_chain_name" = "$scheduler_name" ]; then
    fail "parallel run $run_id did not configure distinct singleton container names"
  fi
done

one_hash_chain="$(awk -F '\t' '$1 == "one" { print $5; exit }' "$COMMAND_LOG")"
two_hash_chain="$(awk -F '\t' '$1 == "two" { print $5; exit }' "$COMMAND_LOG")"
one_scheduler="$(awk -F '\t' '$1 == "one" { print $6; exit }' "$COMMAND_LOG")"
two_scheduler="$(awk -F '\t' '$1 == "two" { print $6; exit }' "$COMMAND_LOG")"
if [ "$one_hash_chain" = "$two_hash_chain" ] || [ "$one_scheduler" = "$two_scheduler" ]; then
  fail "parallel runs did not isolate singleton container names"
fi

for run_id in one two; do
  run_commands="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id { print $7 }' "$COMMAND_LOG")"
  general_key="$(printf '%s\n' "$run_commands" | grep -Eo 'phase-b-queue-general-[a-z0-9-]+' | head -n 1 || true)"
  hash_key="$(printf '%s\n' "$run_commands" | grep -Eo 'phase-b-queue-hash-chain-[a-z0-9-]+' | head -n 1 || true)"
  storage_probe="$(printf '%s\n' "$run_commands" | grep -Eo 'phase-b-storage-probe-[a-z0-9-]+' | head -n 1 || true)"
  if [ -z "$general_key" ] || [ -z "$hash_key" ] || [ -z "$storage_probe" ]; then
    fail "parallel run $run_id did not use isolated queue and storage probes"
  fi

  general_line="$(grep -n -E "^${run_id}"$'\t'".*phase-b-queue-general-" "$COMMAND_LOG" | head -n 1 | cut -d: -f1 || true)"
  hash_line="$(grep -n -E "^${run_id}"$'\t'".*phase-b-queue-hash-chain-" "$COMMAND_LOG" | head -n 1 | cut -d: -f1 || true)"
  storage_line="$(grep -n -E "^${run_id}"$'\t'".*phase-b-storage-probe-" "$COMMAND_LOG" | head -n 1 | cut -d: -f1 || true)"
  browser_line="$(grep -n -E "^${run_id}"$'\t'".*npm run test:integration:browser" "$COMMAND_LOG" | head -n 1 | cut -d: -f1 || true)"
  if [ -z "$browser_line" ] || [ -z "$general_line" ] || [ -z "$hash_line" ] ||
    [ -z "$storage_line" ] || [ "$browser_line" -le "$general_line" ] ||
    [ "$browser_line" -le "$hash_line" ] || [ "$browser_line" -le "$storage_line" ]; then
    fail "parallel run $run_id did not execute the browser after all runtime probes"
  fi

  api_pull_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^pull ghcr\.io\/secpal\/api@/ { print NR; exit }' "$COMMAND_LOG")"
  api_bundle_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^python3 fetch-oci-attestation .*api-image-index\.json/ { print NR; exit }' "$COMMAND_LOG")"
  api_verify_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^gh attestation verify .*api-image-index\.json/ { print NR; exit }' "$COMMAND_LOG")"
  frontend_pull_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^pull ghcr\.io\/secpal\/frontend@/ { print NR; exit }' "$COMMAND_LOG")"
  frontend_bundle_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^python3 fetch-oci-attestation .*frontend-image-index\.json/ { print NR; exit }' "$COMMAND_LOG")"
  frontend_verify_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^gh attestation verify .*frontend-image-index\.json/ { print NR; exit }' "$COMMAND_LOG")"
  build_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ / build gateway$/ { print NR; exit }' "$COMMAND_LOG")"
  secrets_line="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ / up --detach postgres valkey$/ { print NR; exit }' "$COMMAND_LOG")"
  if [ -z "$api_pull_line" ] || [ -z "$api_bundle_line" ] || [ -z "$api_verify_line" ] ||
    [ -z "$frontend_pull_line" ] || [ -z "$frontend_bundle_line" ] ||
    [ -z "$frontend_verify_line" ] || [ -z "$build_line" ] || [ -z "$secrets_line" ] ||
    [ "$api_pull_line" -ge "$api_bundle_line" ] ||
    [ "$api_bundle_line" -ge "$api_verify_line" ] ||
    [ "$api_verify_line" -ge "$frontend_pull_line" ] ||
    [ "$frontend_pull_line" -ge "$frontend_bundle_line" ] ||
    [ "$frontend_bundle_line" -ge "$frontend_verify_line" ] ||
    [ "$frontend_verify_line" -ge "$build_line" ] || [ "$build_line" -ge "$secrets_line" ]; then
    fail "parallel run $run_id did not verify API and frontend before secrets-init"
  fi

  mapfile -t anon_configs < <(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^pull / { print $8 }' "$COMMAND_LOG")
  if [ "${#anon_configs[@]}" -ne 2 ] || [ "${anon_configs[0]}" = "${anon_configs[1]}" ]; then
    fail "parallel run $run_id did not isolate both anonymous image pulls"
  fi
  for anon_config in "${anon_configs[@]}"; do
    if [ -z "$anon_config" ] || [ -e "$anon_config" ]; then
      fail "parallel run $run_id did not remove an anonymous Docker configuration"
    fi
  done
  if awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^gh attestation verify / && $8 != "" { found = 1 } END { exit !found }' \
    "$COMMAND_LOG"; then
    fail "parallel run $run_id exposed Docker configuration to local verification"
  fi
  anonymous_gh_config="$(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^gh attestation verify / { print $9; exit }' "$COMMAND_LOG")"
  if [ -z "$anonymous_gh_config" ] ||
    [ "$anonymous_gh_config" = "$PERSISTENT_GH_CONFIG" ] ||
    [ -e "$anonymous_gh_config" ]; then
    fail "parallel run $run_id did not isolate and remove its anonymous GitHub CLI configuration"
  fi
  while IFS= read -r private_path; do
    if [ -z "$private_path" ] || [ -e "$private_path" ]; then
      fail "parallel run $run_id did not remove a local OCI verification file"
    fi
  done < <(awk -F '\t' -v run_id="$run_id" '$1 == run_id && $7 ~ /^python3 fetch-oci-attestation / { print $7 }' "$COMMAND_LOG" | awk '{ print $3; print $4 }')
done

one_commands="$(awk -F '\t' '$1 == "one" { print $7 }' "$COMMAND_LOG")"
two_commands="$(awk -F '\t' '$1 == "two" { print $7 }' "$COMMAND_LOG")"
if [ "$(printf '%s\n' "$one_commands" | grep -Eo 'phase-b-queue-general-[a-z0-9-]+' | head -n 1 || true)" = \
  "$(printf '%s\n' "$two_commands" | grep -Eo 'phase-b-queue-general-[a-z0-9-]+' | head -n 1 || true)" ]; then
  fail "parallel runs reused a queue probe key"
fi
if [ "$(printf '%s\n' "$one_commands" | grep -Eo 'phase-b-queue-hash-chain-[a-z0-9-]+' | head -n 1 || true)" = \
  "$(printf '%s\n' "$two_commands" | grep -Eo 'phase-b-queue-hash-chain-[a-z0-9-]+' | head -n 1 || true)" ] ||
  [ "$(printf '%s\n' "$one_commands" | grep -Eo 'phase-b-storage-probe-[a-z0-9-]+' | head -n 1 || true)" = \
    "$(printf '%s\n' "$two_commands" | grep -Eo 'phase-b-storage-probe-[a-z0-9-]+' | head -n 1 || true)" ]; then
  fail "parallel runs reused a hash-queue or storage probe name"
fi

for failure_case in queue storage browser frontend_route; do
  : >"$COMMAND_LOG"
  failure_variable="SECPAL_TEST_FAIL_${failure_case^^}"
  if env \
    PATH="$FAKE_BIN:$PATH" \
    "${INHERITED_GH_ENVIRONMENT[@]}" \
    SECPAL_PHASE_B_PORT=18447 \
    SECPAL_TEST_COMMAND_LOG="$COMMAND_LOG" \
    SECPAL_TEST_CURL_LOG="$CURL_LOG" \
    SECPAL_TEST_RUN_ID="fail-$failure_case" \
    "$failure_variable"=1 \
    bash "$ROOT_DIR/scripts/local-integration.sh" >"$TEMP_DIR/fail-$failure_case.out" 2>&1; then
    fail "$failure_case probe failure returned success"
  elif ! grep -Fq 'down --volumes --remove-orphans' "$COMMAND_LOG"; then
    fail "$failure_case probe failure did not trigger project cleanup"
  fi
done

if grep -Eiq 'docker-compose|system prune|image prune|volume prune|docker login|docker push' "$COMMAND_LOG"; then
  fail "the lifecycle used a forbidden Compose fallback, prune, login, or push operation"
fi

if grep -Fq -- '--profile tools run --rm migrate' "$COMMAND_LOG"; then
  fail "the lifecycle requested an interactive TTY for migration"
fi

if awk -F '\t' '$7 ~ /^image rm / && $7 ~ /ghcr\.io\/secpal\/api/ { found = 1 } END { exit !found }' "$COMMAND_LOG"; then
  fail "the published API digest was treated as a local cleanup image"
fi
if awk -F '\t' '$7 ~ /^image rm / && $7 ~ /ghcr\.io\/secpal\/frontend/ { found = 1 } END { exit !found }' "$COMMAND_LOG"; then
  fail "the published frontend digest was treated as a local cleanup image"
fi

if [ ! -f "$PERSISTENT_GH_CONFIG/hosts.yml" ]; then
  fail "the lifecycle modified the caller's persistent GitHub CLI configuration"
fi
if [ ! -f "$PERSISTENT_DOCKER_CONFIG/config.json" ]; then
  fail "the lifecycle modified the caller's persistent Docker configuration"
fi

if [ "$failures" -ne 0 ]; then
  printf '%s\n' '--- curl.log' >&2
  sed -n '1,120p' "$CURL_LOG" >&2
  for output in "$TEMP_DIR"/*.out; do
    if [ -f "$output" ]; then
      printf '%s\n' "--- ${output##*/}" >&2
      sed -n '1,120p' "$output" >&2
    fi
  done
  printf 'Local integration lifecycle contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Local integration lifecycle contract passed.\n'
