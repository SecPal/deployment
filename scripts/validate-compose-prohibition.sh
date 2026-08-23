#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="${1:-$(git rev-parse --show-toplevel)}"
ROOT_DIR="$(realpath "$ROOT_DIR")"
LIST_DIR="$(mktemp -d -t secpal-compose-scan.XXXXXXXXXX)"
trap 'rm -rf -- "$LIST_DIR"' EXIT HUP INT TERM

readonly VALIDATOR_PATH="$ROOT_DIR/scripts/validate-compose-prohibition.sh"
readonly COMMAND_PATTERN='(^|[;&|(){}[:space:]])docker[[:space:]]+compose([;&|(){}[:space:]]|$)|(^|[;&|(){}[:space:]])docker-compose([;&|(){}[:space:]]|$)'
readonly PYTHON_PATTERN="[\"']docker[\"'][[:space:]]*,[[:space:]]*[\"']compose[\"']|\\[[[:space:]]*[\"']docker-compose[\"']|(run|call|check_call|check_output|Popen|system|popen)[[:space:]]*\\([^#]*(docker[[:space:]]+compose|docker-compose)"

failures=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

scan_list() {
  local list="$1"
  local pattern="$2"
  local path
  local content
  local status

  while IFS= read -r -d '' path; do
    if [ "$path" = "$VALIDATOR_PATH" ]; then
      continue
    fi
    if content="$(grep -Ev '^[[:space:]]*#' "$path")"; then
      :
    else
      status=$?
      if [ "$status" -ne 1 ]; then
        printf 'ERROR: unable to inspect current executable surface: %s\n' \
          "${path#"$ROOT_DIR"/}" >&2
        exit 2
      fi
    fi
    if grep -Eiq -- "$pattern" <<<"$content"; then
      fail "current executable surface invokes Docker Compose: ${path#"$ROOT_DIR"/}"
    else
      status=$?
      if [ "$status" -ne 1 ]; then
        printf 'ERROR: unable to evaluate Compose prohibition for: %s\n' \
          "${path#"$ROOT_DIR"/}" >&2
        exit 2
      fi
    fi
  done <"$list"
}

for directory in "$ROOT_DIR/scripts" "$ROOT_DIR/.github/workflows"; do
  if [ ! -d "$directory" ]; then
    printf 'ERROR: required scan directory is missing: %s\n' "$directory" >&2
    exit 2
  fi
done

if ! find "$ROOT_DIR/scripts" -type f -name '*.sh' -print0 \
  >"$LIST_DIR/shell"; then
  printf 'ERROR: unable to enumerate current shell runners.\n' >&2
  exit 2
fi
if ! find "$ROOT_DIR/.github/workflows" -type f \
  \( -name '*.yml' -o -name '*.yaml' \) -print0 >"$LIST_DIR/workflows"; then
  printf 'ERROR: unable to enumerate current workflows.\n' >&2
  exit 2
fi
if ! find "$ROOT_DIR/scripts" -type f -name '*.py' -print0 \
  >"$LIST_DIR/python"; then
  printf 'ERROR: unable to enumerate current Python runners.\n' >&2
  exit 2
fi

scan_list "$LIST_DIR/shell" "$COMMAND_PATTERN"
scan_list "$LIST_DIR/workflows" "$COMMAND_PATTERN"
scan_list "$LIST_DIR/python" "$PYTHON_PATTERN"

if [ "$failures" -ne 0 ]; then
  printf 'Compose prohibition failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Compose prohibition passed.\n'
