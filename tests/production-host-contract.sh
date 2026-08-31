#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

failures=0
checks=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  checks=$((checks + 1))
  [[ -f "$1" ]] || fail "required production host artifact is missing: $1"
}

require_text() {
  local path="$1"
  local text="$2"
  checks=$((checks + 1))
  grep -Fq -- "$text" "$path" || fail "$path must contain: $text"
}

required_paths=(
  docs/architecture/production-host.md
  schemas/production-host-facts.schema.json
  scripts/validate-production-contract.py
  scripts/qualify-production-host.sh
  tests/production-host-rocky-contract.py
  tests/production-host-native-gate.sh
  tests/fixtures/production-host/valid-amd64.yaml
  tests/fixtures/production-host/valid-arm64.yaml
  tests/fixtures/production-host/debian-host.yaml
  tests/fixtures/production-host/unqualified-rocky-minor.yaml
)
for path in "${required_paths[@]}"; do
  require_file "$path"
done

document_terms=(
  "Rocky Linux 10.2"
  "SELinux Enforcing"
  "x86-64-v3"
  "aarch64"
  "container-selinux"
  "container_t"
  "container_file_t"
  "Podman private relabel"
  ":Z"
  "rootless Podman"
  "systemd-user"
  "native Quadlet"
  "/etc/containers/systemd/users/<UID>/"
  "administrator-owned"
  "Netavark"
  "Aardvark DNS"
  "pasta"
  "cgroup v2"
  "crun"
  "seccomp"
  "digest-only"
  "Pull=never"
  "NOT RUN"
)
for text in "${document_terms[@]}"; do
  require_text docs/architecture/production-host.md "$text"
done

schema_terms=(
  '"evidence_class"'
  '"rocky-native"'
  '"const": "rocky"'
  '"container_policy_package"'
  '"process_mcs"'
  '"cross_boundary_access_denied"'
  '"avc_denial_observed"'
  '"dac_would_allow_cross_boundary"'
  '"persistent_labels"'
  '"privileged"'
  '"seccomp_enabled"'
  '"digest_only_images"'
  '"podman_socket_mounted"'
  '"docker_socket_mounted"'
  '"package_repositories"'
  '"installed_nevras"'
)
for text in "${schema_terms[@]}"; do
  require_text schemas/production-host-facts.schema.json "$text"
done

packages=(
  podman conmon crun netavark aardvark-dns passt shadow-utils-subid systemd
  container-selinux audit policycoreutils policycoreutils-python-utils
  selinux-policy-targeted
)
for package in "${packages[@]}"; do
  require_text schemas/production-host-facts.schema.json "$package"
done

validator_terms=(
  'QUALIFIED_ROCKY_MINORS = frozenset({"10.2"})'
  "glibc-loader-hwcaps"
  "rocky-aarch64-native"
  "validate_selinux_facts"
)
for text in "${validator_terms[@]}"; do
  require_text scripts/validate-production-contract.py "$text"
done

checks=$((checks + 1))
if grep -En -- 'const.*debian|debian_release_suites|trixie|debian-archive|apparmor.*required|AppArmor enabled|unattended-upgrades' schemas/production-host-facts.schema.json scripts/validate-production-contract.py; then
  fail "active machine admission retains a Debian/AppArmor production requirement"
fi

checks=$((checks + 1))
if grep -ERn -- 'label=disable|Network=host|Privileged=true|AutoUpdate=registry' config/production/quadlet scripts/render-production-quadlets.py; then
  fail "production Quadlet inputs contain a forbidden runtime fallback"
fi

checks=$((checks + 1))
if grep -En -- 'docker_engine_version|docker_compose_version|docker_data_root|/var/run/docker\.sock' schemas/production-host-facts.schema.json scripts/validate-production-contract.py; then
  fail "active host machine contract retains Docker runtime fields"
fi

python3 tests/production-host-rocky-contract.py
bash tests/production-host-native-gate.sh

if ((failures)); then
  printf 'Production host contract failed: %d of %d checks failed.\n' "$failures" "$checks" >&2
  exit 1
fi

printf 'Production host contract passed (%d static checks plus focused fixture/native gates).\n' "$checks"
