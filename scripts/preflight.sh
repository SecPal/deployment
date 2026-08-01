#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
RESOLVED_ROOT="$(realpath "$ROOT_DIR")"

cd "$ROOT_DIR"

if [ "$(pwd -P)" != "$RESOLVED_ROOT" ]; then
  printf 'ERROR: unable to resolve repository root safely.\n' >&2
  exit 1
fi

scripts/validate-origin.sh "$(git remote get-url origin)"

required_tools=(actionlint markdownlint prettier reuse shellcheck yamllint)
missing_tools=()
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools+=("$tool")
  fi
done
if [ "${#missing_tools[@]}" -ne 0 ]; then
  printf 'ERROR: required local validation tool(s) missing: %s\n' "${missing_tools[*]}" >&2
  printf 'Install the pinned organization-standard tools before rerunning; preflight never installs dependencies.\n' >&2
  exit 1
fi

{
  git ls-files -z
  git ls-files --others --exclude-standard -z
  git ls-files --others --ignored --exclude-standard -z
} | scripts/reject-sensitive-paths.sh

git diff --check
git diff --cached --check

mapfile -d '' shell_files < <(find scripts tests -type f -name '*.sh' -print0 | sort -z)
if [ "${#shell_files[@]}" -eq 0 ]; then
  printf 'ERROR: no shell validation files found.\n' >&2
  exit 1
fi

bash -n "${shell_files[@]}"
shellcheck "${shell_files[@]}"
bash tests/repository-contract.sh
bash tests/phase-b-contract.sh
bash tests/runtime-secret-contract.sh
bash tests/local-integration-lifecycle.sh
bash tests/preflight-origin-contract.sh
bash tests/sensitive-path-contract.sh

mapfile -d '' markdown_files < <(find . \( -path ./.git -o -path ./.context \) -prune -o -type f -name '*.md' -print0 | sort -z)
markdownlint --config .markdownlint.json "${markdown_files[@]}"

mapfile -d '' yaml_files < <(find . \( -path ./.git -o -path ./.context \) -prune -o -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
yamllint -c .yamllint.yml "${yaml_files[@]}"

mapfile -d '' workflow_files < <(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
actionlint "${workflow_files[@]}"

mapfile -d '' formatted_files < <(find . \( -path ./.git -o -path ./.context \) -prune -o -type f \( \
  -name '*.md' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' \
\) -print0 | sort -z)
prettier --check "${formatted_files[@]}"

reuse lint

printf 'SecPal deployment preflight passed.\n'
