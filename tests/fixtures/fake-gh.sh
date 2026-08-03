#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly API_IMAGE='ghcr.io/secpal/api@sha256:5a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
readonly SOURCE_COMMIT='87d1432389adac3a02574b399322928a77c5e67f'

if [ "${1:-}" = attestation ] && [ "${2:-}" = verify ] && [ "${3:-}" = --help ]; then
  exit 0
fi

if [ "${1:-}" = version ] || [ "${1:-}" = --version ]; then
  printf 'gh version 2.97.0 (fixture)\n'
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

expected_args=(
  "oci://$API_IMAGE"
  --bundle-from-oci
  --repo
  SecPal/api
  --signer-workflow
  SecPal/api/.github/workflows/publish-container.yml
  --signer-digest
  "$SOURCE_COMMIT"
  --source-ref
  refs/heads/main
  --source-digest
  "$SOURCE_COMMIT"
  --deny-self-hosted-runners
)
actual_args=("${@:3}")
if [ "${actual_args[*]}" != "${expected_args[*]}" ]; then
  exit 71
fi

if [ -n "${GH_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ]; then
  printf 'fixture rejected inherited GitHub token\n' >&2
  exit 72
fi

if [ -z "${GH_CONFIG_DIR:-}" ] || [ ! -d "$GH_CONFIG_DIR" ] ||
  [ "$(stat -c '%a' "$GH_CONFIG_DIR")" != 700 ] ||
  find "$GH_CONFIG_DIR" -mindepth 1 -print -quit | grep -q .; then
  printf 'fixture rejected non-empty or inherited GitHub CLI configuration\n' >&2
  exit 73
fi

observed_subject="$API_IMAGE"
observed_source_commit="$SOURCE_COMMIT"
observed_workflow='SecPal/api/.github/workflows/publish-container.yml'
observed_runner='github-hosted'

case "${SECPAL_TEST_ATTESTATION_RESULT:-success}" in
  success) ;;
  failure)
    printf 'fixture rejected the attestation verification request\n' >&2
    exit 74
    ;;
  wrong-source-commit)
    observed_source_commit='97d1432389adac3a02574b399322928a77c5e67f'
    ;;
  wrong-workflow)
    observed_workflow='SecPal/api/.github/workflows/untrusted.yml'
    ;;
  wrong-subject-digest)
    observed_subject='ghcr.io/secpal/api@sha256:6a095b27105691139b161ac0578ceae86e68b6821afadf7cb455fb86c8009c0e'
    ;;
  self-hosted)
    observed_runner='self-hosted'
    ;;
  *) exit 75 ;;
esac

if [ "${actual_args[0]}" != "oci://$observed_subject" ]; then
  printf 'fixture rejected subject digest mismatch\n' >&2
  exit 76
fi
if [ "${actual_args[5]}" != "$observed_workflow" ]; then
  printf 'fixture rejected signer workflow mismatch\n' >&2
  exit 77
fi
if [ "${actual_args[11]}" != "$observed_source_commit" ]; then
  printf 'fixture rejected source digest mismatch\n' >&2
  exit 78
fi
if [ "$observed_runner" = self-hosted ] && [ "${actual_args[12]}" = --deny-self-hosted-runners ]; then
  printf 'fixture rejected self-hosted runner\n' >&2
  exit 79
fi

exit 0
