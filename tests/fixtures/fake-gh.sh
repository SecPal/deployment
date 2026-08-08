#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

if [ "${1:-}" = attestation ] && [ "${2:-}" = verify ] && [ "${3:-}" = --help ]; then
  if [ "${SECPAL_TEST_GH_ATTESTATION_UNAVAILABLE:-0}" -eq 1 ]; then
    exit 1
  fi
  exit 0
fi

if [ "${1:-}" = version ] || [ "${1:-}" = --version ]; then
  printf 'gh version %s (fixture)\n' "${SECPAL_TEST_GH_VERSION:-2.97.0}"
  exit 0
fi

printf '%s\t\t\t\t\t\tgh %s\t%s\t%s\n' \
  "${SECPAL_TEST_RUN_ID:-unknown}" \
  "$*" \
  "${DOCKER_CONFIG:-}" \
  "${GH_CONFIG_DIR:-}" >>"${SECPAL_TEST_COMMAND_LOG:?}"

if [ "${1:-}" != attestation ] || [ "${2:-}" != verify ]; then
  exit 70
fi

actual_args=("${@:3}")
subject_path="${actual_args[0]:-}"
bundle_path="${actual_args[2]:-}"
image_kind=
case "${subject_path##*/}" in
  api-image-index.json)
    image_kind=API
    source_commit='87d1432389adac3a02574b399322928a77c5e67f'
    repository='SecPal/api'
    workflow='SecPal/api/.github/workflows/publish-container.yml'
    bundle_name='api-attestation.json'
    ;;
  frontend-image-index.json)
    image_kind=FRONTEND
    source_commit='b755ca0d0ee5a85eca5ad5688d457241f070b1b4'
    repository='SecPal/frontend'
    workflow='SecPal/frontend/.github/workflows/publish-container.yml'
    bundle_name='frontend-attestation.json'
    ;;
  *) exit 71 ;;
esac
expected_args=(
  "$subject_path"
  --bundle
  "$bundle_path"
  --repo
  "$repository"
  --signer-workflow
  "$workflow"
  --signer-digest
  "$source_commit"
  --source-ref
  refs/heads/main
  --source-digest
  "$source_commit"
  --deny-self-hosted-runners
  --hostname
  github.com
)
if [ "${actual_args[*]}" != "${expected_args[*]}" ]; then
  exit 71
fi

if [ -n "${GH_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ] ||
  [ -n "${GH_ENTERPRISE_TOKEN:-}" ] || [ -n "${GITHUB_ENTERPRISE_TOKEN:-}" ]; then
  printf 'fixture rejected inherited GitHub token variables\n' >&2
  exit 72
fi

if [ "${DOCKER_CONFIG+x}" = x ] || [ "${DOCKER_AUTH_CONFIG+x}" = x ]; then
  printf 'fixture rejected Docker registry configuration in local verification\n' >&2
  exit 72
fi

if [ -n "${GH_HOST:-}" ]; then
  printf 'fixture rejected inherited GitHub host selection\n' >&2
  exit 72
fi

if [ "${GH_PROMPT_DISABLED:-}" != 1 ] || [ "${GH_NO_UPDATE_NOTIFIER:-}" != 1 ] ||
  [ "${GH_NO_EXTENSION_UPDATE_NOTIFIER:-}" != 1 ] || [ "${GH_TELEMETRY:-}" != false ]; then
  printf 'fixture rejected non-deterministic GitHub CLI environment\n' >&2
  exit 72
fi

if [ -z "${GH_CONFIG_DIR:-}" ] || [ ! -d "$GH_CONFIG_DIR" ] ||
  [ "$(stat -c '%a' "$GH_CONFIG_DIR")" != 700 ] ||
  find "$GH_CONFIG_DIR" -mindepth 1 -print -quit | grep -q .; then
  printf 'fixture rejected non-empty or inherited GitHub CLI configuration\n' >&2
  exit 73
fi

if [ ! -f "$subject_path" ] ||
  [ "$(stat -c '%a' "$subject_path")" != 600 ] ||
  [ ! -s "$subject_path" ]; then
  printf 'fixture rejected a missing or insecure local OCI subject\n' >&2
  exit 74
fi

if [ "${bundle_path##*/}" != "$bundle_name" ] ||
  [ ! -f "$bundle_path" ] ||
  [ "$(stat -c '%a' "$bundle_path")" != 600 ] ||
  [ ! -s "$bundle_path" ]; then
  printf 'fixture rejected a missing or insecure offline attestation bundle\n' >&2
  exit 74
fi

observed_source_commit="$source_commit"
observed_signer_commit="$source_commit"
observed_workflow="$workflow"
observed_repository="$repository"
observed_source_ref='refs/heads/main'
observed_runner='github-hosted'

result="${SECPAL_TEST_ATTESTATION_RESULT:-success}"
if [ "$image_kind" = API ] && [ -n "${SECPAL_TEST_API_ATTESTATION_RESULT:-}" ]; then
  result="$SECPAL_TEST_API_ATTESTATION_RESULT"
elif [ "$image_kind" = FRONTEND ] && [ -n "${SECPAL_TEST_FRONTEND_ATTESTATION_RESULT:-}" ]; then
  result="$SECPAL_TEST_FRONTEND_ATTESTATION_RESULT"
fi

case "$result" in
  success) ;;
  failure)
    printf 'fixture rejected the attestation verification request\n' >&2
    exit 75
    ;;
  wrong-source-commit)
    observed_source_commit="f${source_commit:1}"
    ;;
  wrong-workflow)
    observed_workflow="${repository}/.github/workflows/untrusted.yml"
    ;;
  wrong-repository)
    observed_repository='SecPal/untrusted'
    ;;
  wrong-source-ref)
    observed_source_ref='refs/heads/untrusted'
    ;;
  wrong-signer-digest)
    observed_signer_commit="f${source_commit:1}"
    ;;
  wrong-subject-digest)
    printf 'fixture rejected subject digest mismatch\n' >&2
    exit 76
    ;;
  wrong-subject-name)
    printf 'fixture rejected subject name mismatch\n' >&2
    exit 76
    ;;
  self-hosted)
    observed_runner='self-hosted'
    ;;
  *) exit 76 ;;
esac

if [ "${actual_args[4]}" != "$observed_repository" ]; then
  printf 'fixture rejected repository mismatch\n' >&2
  exit 77
fi
if [ "${actual_args[6]}" != "$observed_workflow" ]; then
  printf 'fixture rejected signer workflow mismatch\n' >&2
  exit 77
fi
if [ "${actual_args[8]}" != "$observed_signer_commit" ]; then
  printf 'fixture rejected signer digest mismatch\n' >&2
  exit 78
fi
if [ "${actual_args[10]}" != "$observed_source_ref" ]; then
  printf 'fixture rejected source ref mismatch\n' >&2
  exit 78
fi
if [ "${actual_args[12]}" != "$observed_source_commit" ]; then
  printf 'fixture rejected source digest mismatch\n' >&2
  exit 78
fi
if [ "$observed_runner" = self-hosted ] && [ "${actual_args[13]}" = --deny-self-hosted-runners ]; then
  printf 'fixture rejected self-hosted runner\n' >&2
  exit 79
fi

exit 0
