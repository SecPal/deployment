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
  docs/architecture/production-host.md
  docs/architecture/production-inventory.md
  docs/api-image-consumption.md
  docs/ci-cloud-conformance.md
  docs/roadmap.md
  infra/ci-cloud/digitalocean/.terraform.lock.hcl
  infra/ci-cloud/digitalocean/main.tf
  infra/ci-cloud/digitalocean/outputs.tf
  infra/ci-cloud/digitalocean/variables.tf
  infra/ci-cloud/digitalocean/versions.tf
  infra/ci-cloud/gcp/.terraform.lock.hcl
  infra/ci-cloud/gcp/iam-role.yaml
  infra/ci-cloud/gcp/main.tf
  infra/ci-cloud/gcp/outputs.tf
  infra/ci-cloud/gcp/variables.tf
  infra/ci-cloud/gcp/versions.tf
  schemas/ci-cloud-bootstrap-failure.schema.json
  schemas/ci-cloud-evidence.schema.json
  config/production/inventory.example.yaml
  schemas/production-host-facts.schema.json
  schemas/production-inventory.schema.json
  scripts/preflight.sh
  scripts/fetch-oci-attestation.py
  scripts/ci-cloud/collect-host-evidence.py
  scripts/ci-cloud/bootstrap-conformance-host.tftpl
  scripts/ci-cloud/continue-conformance-bootstrap.sh
  scripts/ci-cloud/configure-conformance-host.sh
  scripts/ci-cloud/install-diagnostic-ssh.sh
  scripts/ci-cloud/digitalocean-janitor.py
  scripts/ci-cloud/gcp-janitor.py
  scripts/ci-cloud/host-setup-failure.py
  scripts/ci-cloud/probe-ssh-port.py
  scripts/ci-cloud/run-remote-conformance.sh
  scripts/ci-cloud/target-conformance.sh
  scripts/ci-cloud/validate-evidence.py
  scripts/ci-cloud/write-bootstrap-failure.py
  tests/ci-cloud-openssh-account.sh
  scripts/reject-sensitive-paths.sh
  scripts/validate-ci-cloud.py
  scripts/validate-production-contract.py
  scripts/validate-origin.sh
  scripts/validate-workflow-action-pins.py
  tests/repository-contract.sh
  tests/ci-cloud-bootstrap-failure.py
  tests/ci-cloud-config.py
  tests/ci-cloud-contract.py
  tests/ci-cloud-collector.py
  tests/ci-cloud-evidence.py
  tests/ci-cloud-gcp-janitor.py
  tests/ci-cloud-host-setup-failure.py
  tests/ci-cloud-janitor.py
  tests/ci-cloud-ssh-port-probe.py
  tests/ci-cloud-remote-bootstrap.sh
  tests/phase-b-contract.sh
  tests/phase-c-api-image-contract.sh
  tests/production-contract-regressions.py
  tests/production-host-contract.sh
  tests/production-inventory-contract.py
  tests/runtime-secret-contract.sh
  tests/local-integration-lifecycle.sh
  tests/preflight-origin-contract.sh
  tests/sensitive-path-contract.sh
  tests/workflow-action-pin-contract.sh
  tests/fixtures/fake-docker.sh
  tests/fixtures/fake-gh.sh
  tests/fixtures/fake-python3.sh
  tests/fixtures/fake-curl.sh
  tests/oci-attestation-bundle-contract.py
  .github/workflows/quality.yml
  .github/actionlint.yaml
  .github/workflows/cloud-conformance.yml
  .github/workflows/cloud-janitor.yml
  LICENSES/AGPL-3.0-or-later.txt
  LICENSES/CC0-1.0.txt
  LICENSES/LicenseRef-SecPal-Attribution.txt
  LICENSES/MIT.txt
)

for path in "${required_files[@]}"; do
  require_file "$path"
done

require_text README.md "It is not a production-ready deployment."
require_text README.md "./scripts/preflight.sh"
require_text README.md "Local API/frontend integration: complete."
require_text README.md "Phase B is complete:"
require_text README.md "Phase C is complete."
require_text README.md "Ephemeral Debian 13 cloud conformance"
require_text docs/architecture/scope.md "activity-hash-chain worker: exactly one"
require_text docs/architecture/scope.md "scheduler: exactly one"
require_text docs/architecture/scope.md "Step A bootstrap contract"
require_text docs/architecture/scope.md \
  "The reviewed immutable API and frontend images are already consumed here."
if grep -Fq 'Later phases will add immutable publication' docs/architecture/scope.md; then
  fail "architecture scope must not defer immutable publication that is already consumed"
fi
require_text docs/roadmap.md "Local container integration stack"
require_text docs/roadmap.md "Phase B — Local container integration stack (complete)"
require_text docs/roadmap.md "Phase C — Immutable image publishing (complete)"
require_text docs/ci-cloud-conformance.md "The workflow never checks out"
# The Markdown backticks must remain literal.
# shellcheck disable=SC2016
require_text docs/roadmap.md 'is enforced for `main`'
require_text .github/workflows/local-integration.yml "runs-on: ubuntu-latest"
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

unexpected_symlink="$(find . \( -path ./.git -o -path ./.context -o -path ./node_modules -o -path ./playwright-report -o -path ./test-results \) -prune -o -type l -print -quit)"
if [ -n "$unexpected_symlink" ]; then
  fail "unexpected symlink found: $unexpected_symlink"
fi

# These absences remain permanent or belong to later roadmap phases. Phase B
# deliberately permits only the repository-root Compose contract.
for path in \
  compose.yml docker-compose.yaml docker-compose.yml \
  Dockerfile Containerfile Chart.yaml values.yaml .env; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    fail "forbidden or later-phase path exists: $path"
  fi
done

require_file compose.yaml

if grep -Eiq 'Phase B (remains|stays|is) in progress|Phase B.*pending|Local API/frontend integration: in progress' \
  README.md docs/roadmap.md; then
  fail "README.md and docs/roadmap.md must consistently mark Phase B complete"
fi

for path in terraform ansible kubernetes helm certificates secrets; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    fail "forbidden or later-phase path exists: $path"
  fi
done

if ! find . \( -path ./.git -o -path ./.context -o -path ./node_modules -o -path ./playwright-report -o -path ./test-results \) -prune -o -type f -print0 |
  scripts/reject-sensitive-paths.sh; then
  fail "forbidden sensitive path exists"
fi

while IFS= read -r -d '' candidate; do
  if grep -Iq . "$candidate"; then
    if grep -Eq -- \
      'AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|[a-zA-Z][a-zA-Z0-9+.-]*://[^/@[:space:]]+:[^/@[:space:]]+@' \
      "$candidate"; then
      fail "possible embedded credential found: $candidate"
    fi
  fi
done < <(find . \( -path ./.git -o -path ./.context -o -path ./node_modules -o -path ./playwright-report -o -path ./test-results \) -prune -o -type f -print0)

if [ "$failures" -ne 0 ]; then
  printf 'Repository contract failed with %d issue(s).\n' "$failures" >&2
  exit 1
fi

printf 'Repository contract passed.\n'
