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

required_tools=(actionlint markdownlint php prettier python3 reuse shellcheck yamllint)
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

if ! python3 -c 'import jsonschema, yaml' >/dev/null 2>&1; then
  printf 'ERROR: required Python modules missing: jsonschema and/or PyYAML\n' >&2
  exit 1
fi

{
  git ls-files -z
  git ls-files --others --exclude-standard -z -- . ':!node_modules' ':!playwright-report' ':!test-results'
  git ls-files --others --ignored --exclude-standard -z -- . ':!.context' ':!node_modules' ':!playwright-report' ':!test-results'
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
php -l scripts/phase-b-runtime-probe.php
python3 tests/image-consumption-evidence-contract.py
python3 tests/oci-attestation-bundle-contract.py
python3 tests/quadlet-integration-contract.py
python3 tests/quadlet-integration-lifecycle.py
python3 tests/ci-cloud-bootstrap-failure.py
python3 tests/ci-cloud-config.py
python3 tests/ci-cloud-contract.py
python3 tests/ci-cloud-rocky-control.py
python3 tests/rocky-evidence-architecture.py
python3 tests/ci-cloud-collector.py
python3 tests/ci-cloud-evidence.py
python3 tests/ci-cloud-gcp-janitor.py
python3 tests/ci-cloud-gcp-rocky-janitor.py
bash tests/ci-cloud-gcp-identity.sh
python3 tests/ci-cloud-host-setup-failure.py
python3 tests/ci-cloud-janitor.py
python3 tests/ci-cloud-quadlet-fixture.py
python3 tests/ci-cloud-ssh-port-probe.py
python3 tests/ci-cloud-systemd-reboot.py
python3 tests/ci-cloud-target-diagnostic.py
python3 tests/ci-cloud-workload-evidence.py
bash tests/ci-cloud-remote-bootstrap.sh
bash tests/ci-cloud-workload-orchestration.sh
bash tests/ci-cloud-init-retry.sh
python3 tests/production-contract-regressions.py
python3 tests/production-inventory-contract.py
python3 tests/production-state-contract.py
python3 tests/production-edge-decision-contract.py
bash tests/production-state-native-lifecycle-gate.sh
bash tests/production-state-native-lifecycle.sh
python3 tests/work-graph-governance.py
bash tests/compose-prohibition-contract.sh
bash tests/repository-contract.sh
bash tests/production-host-contract.sh
bash tests/runtime-secret-contract.sh
bash tests/preflight-origin-contract.sh
bash tests/sensitive-path-contract.sh
bash tests/workflow-action-pin-contract.sh
python3 scripts/validate-ci-cloud.py
scripts/validate-rocky-evidence-architecture.py

mapfile -d '' markdown_files < <(find . \( -path ./.git -o -path ./.context -o -name .terraform -o -path ./node_modules -o -path ./playwright-report -o -path ./test-results \) -prune -o -type f -name '*.md' -print0 | sort -z)
markdownlint --config .markdownlint.json "${markdown_files[@]}"

mapfile -d '' yaml_files < <(find . \( -path ./.git -o -path ./.context -o -name .terraform -o -path ./node_modules -o -path ./playwright-report -o -path ./test-results \) -prune -o -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
yamllint -c .yamllint.yml "${yaml_files[@]}"

mapfile -d '' workflow_files < <(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
actionlint "${workflow_files[@]}"

mapfile -d '' formatted_files < <(find . \( -path ./.git -o -path ./.context -o -name .terraform -o -path ./node_modules -o -path ./playwright-report -o -path ./test-results \) -prune -o -type f \( \
  -name '*.md' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' \
\) -print0 | sort -z)
prettier --check "${formatted_files[@]}"

reuse lint

printf 'SecPal deployment preflight passed.\n'
