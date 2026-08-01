#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

failures=0
spdx_license_marker="SPDX-License"
spdx_license_marker="${spdx_license_marker}-Identifier:"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    fail "required file is missing: $path"
  fi
}

require_text() {
  local path="$1"
  local text="$2"
  if [ ! -f "$path" ] || ! grep -Fq -- "$text" "$path"; then
    fail "$path must contain: $text"
  fi
}

required_files=(
  AGENTS.md
  README.md
  LICENSE
  REUSE.toml
  .gitignore
  .editorconfig
  .pre-commit-config.yaml
  CHANGELOG.md
  docs/architecture/scope.md
  docs/roadmap.md
  scripts/preflight.sh
  tests/repository-contract.sh
  .github/workflows/quality.yml
  LICENSES/AGPL-3.0-or-later.txt
  LICENSES/CC0-1.0.txt
  LICENSES/LicenseRef-SecPal-Attribution.txt
  LICENSES/MIT.txt
)

for path in "${required_files[@]}"; do
  require_file "$path"
done

require_text README.md "This repository is in its governance bootstrap phase."
require_text README.md "It does not yet contain a runnable or production-ready deployment."
require_text README.md "./scripts/preflight.sh"
require_text docs/architecture/scope.md "activity-hash-chain worker: exactly one"
require_text docs/architecture/scope.md "scheduler: exactly one"
require_text docs/architecture/scope.md "Step A bootstrap contract"
require_text docs/roadmap.md "Local container integration stack"
require_text AGENTS.md "Docker socket"
require_text AGENTS.md "activity-hash-chain worker: exactly one"
require_text AGENTS.md "scheduler: exactly one"
require_text CHANGELOG.md "## 2026-08-01 - Bootstrap Deployment Repository"

while IFS= read -r -d '' script; do
  if ! head -n 6 "$script" | grep -Fq 'SPDX-FileCopyrightText:'; then
    fail "$script has no SPDX copyright header"
  fi
  if ! head -n 6 "$script" | grep -Fq "$spdx_license_marker"; then
    fail "$script has no SPDX license header"
  fi
  if [ ! -x "$script" ]; then
    fail "$script must be executable"
  fi
done < <(find scripts tests -type f -name '*.sh' -print0 2>/dev/null)

if [ -d LICENSES ]; then
  while IFS= read -r -d '' license_file; do
    if [ ! -s "$license_file" ]; then
      fail "license file is empty: $license_file"
    fi
  done < <(find LICENSES -type f -print0)
fi

unexpected_symlink="$(find . -path ./.git -prune -o -type l -print -quit)"
if [ -n "$unexpected_symlink" ]; then
  fail "unexpected symlink found: $unexpected_symlink"
fi

# These absences define the Step A governance bootstrap. Step B must update
# this explicit contract before adding deployment implementation artifacts.
for path in \
  compose.yaml compose.yml docker-compose.yaml docker-compose.yml \
  Dockerfile Containerfile Chart.yaml values.yaml .env; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    fail "Step A forbidden path exists: $path"
  fi
done

for path in terraform ansible kubernetes helm certificates secrets; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    fail "Step A forbidden path exists: $path"
  fi
done

blocked_file="$(find . -path ./.git -prune -o -type f \( \
  -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' -o \
  -name '*.jks' -o -name '*.keystore' \
\) -print -quit)"
if [ -n "$blocked_file" ]; then
  fail "forbidden sensitive file exists: $blocked_file"
fi

while IFS= read -r -d '' candidate; do
  if grep -Iq . "$candidate"; then
    if grep -Eq -- \
      'AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|[a-zA-Z][a-zA-Z0-9+.-]*://[^/@[:space:]]+:[^/@[:space:]]+@' \
      "$candidate"; then
      fail "possible embedded credential found: $candidate"
    fi
  fi
done < <(find . -path ./.git -prune -o -type f -print0)

if [ "$failures" -ne 0 ]; then
  printf 'Repository contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Repository contract passed.\n'
