#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT
REAL_PYTHON="$(command -v python3)"
FAKE_BIN="$TEMP_DIR/bin"
PRIVATE_KEY="$TEMP_DIR/id_ed25519"
HOST_JSON="$TEMP_DIR/host.json"
LIVE_JSON="$TEMP_DIR/live.json"
CLEANUP_JSON="$TEMP_DIR/cleanup.json"
BASELINE_JSON="$TEMP_DIR/baseline.json"
mkdir -p "$FAKE_BIN"
install -m 0600 /dev/null "$PRIVATE_KEY"

"$REAL_PYTHON" - "$HOST_JSON" "$BASELINE_JSON" "$LIVE_JSON" "$CLEANUP_JSON" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, Path(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

workload = load("tests/ci-cloud-workload-evidence.py", "workload_fixture")
evidence = load("tests/ci-cloud-evidence.py", "evidence_fixture")
observations = workload.valid_observations()
host = evidence.valid_document()
host["schema_version"] = 1
host.pop("host_admission")
host.pop("workload")
host["test"].pop("phase_exit_statuses")
host["test"].pop("collection_exit_statuses")
host["test"]["target_exit_status"] = 0
Path(sys.argv[1]).write_text(
    json.dumps(host, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
for output, key in zip(
    sys.argv[2:], ("baseline", "live", "post_cleanup"), strict=True
):
    Path(output).write_text(
        json.dumps(observations[key], sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
PY

cat >"$FAKE_BIN/ssh-keyscan" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKey\n' "${*: -1}"
EOF
cat >"$FAKE_BIN/ssh-keygen" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == -lf ]]; then
  printf '256 SHA256:test-only fixture (ED25519)\n'
fi
EOF
cat >"$FAKE_BIN/sleep" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
cat >"$FAKE_BIN/timeout" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" == --* ]]; do
  shift
done
shift
exec "$@"
EOF
cat >"$FAKE_BIN/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec "${SECPAL_TEST_REAL_PYTHON:?}" "$@"
EOF
cat >"$FAKE_BIN/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -i | -o) shift 2 ;;
    *) ssh_target="$1"; shift; break ;;
  esac
done
if [[ "$ssh_target" == root@* ]]; then
  exit 255
fi
if [[ "${1:-}" == true ]]; then
  exit 0
fi
if [[ "${1:-}" == /bin/bash && "${2:-}" == -s ]]; then
  if [[ "${3:-}" != -- ]]; then
    cat >/dev/null
    exit 0
  fi
  if [[ "$#" -eq 4 ]]; then
    cat >/dev/null
    printf 'checkout\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    exit 0
  fi
  phase="${6:-}"
  wrapper="$(cat)"
  grep -Fq 'cd /home/secpal-ci/deployment-target' <<<"$wrapper"
  grep -Fq 'ulimit -f 32768' <<<"$wrapper"
  printf 'target:%s\n' "$phase" >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
  if [[ "$phase" == host &&
    "${SECPAL_TEST_INTERRUPT_HOST:-false}" == true ]]; then
    kill -TERM "$PPID"
    exit 143
  fi
  if [[ "$phase" == workload-prepare-start &&
    "${SECPAL_TEST_INTERRUPT_PREPARE:-false}" == true ]]; then
    kill -TERM "$PPID"
    exit 143
  fi
  if [[ "$phase" == workload-prepare-start &&
    "${SECPAL_TEST_FAIL_PREPARE:-false}" == true ]]; then
    printf '%020000d\n' 0 >&2
    printf 'ERROR: synthetic prepare failure\n' >&2
    printf '::error::must not become a workflow command\n' >&2
    exit 7
  fi
  exit 0
fi
case " $* " in
  *' /usr/bin/python3 -I - normalize '*)
    cat >/dev/null
    printf 'collector:normalize\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    ;;
  *' /usr/bin/python3 -I - baseline '*)
    cat >/dev/null
    printf 'collector:baseline\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    cat "${SECPAL_TEST_BASELINE_JSON:?}"
    ;;
  *' /usr/bin/python3 -I - live '*)
    cat >/dev/null
    printf 'collector:live\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    cat "${SECPAL_TEST_LIVE_JSON:?}"
    ;;
  *' /usr/bin/python3 -I - post-cleanup '*)
    cat >/dev/null
    printf 'collector:post-cleanup\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    cat "${SECPAL_TEST_CLEANUP_JSON:?}"
    ;;
  *' /usr/bin/python3 -I - digitalocean '*)
    cat >/dev/null
    printf 'collector:host\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    cat "${SECPAL_TEST_HOST_JSON:?}"
    ;;
  *' /usr/bin/podman network create '*)
    printf 'control:create-network\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    ;;
  *' /usr/bin/podman volume create '*)
    printf 'control:create-volume\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    ;;
  *' /usr/bin/podman network rm '*)
    printf 'control:remove-network\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    ;;
  *' /usr/bin/podman volume rm '*)
    printf 'control:remove-volume\n' >>"${SECPAL_TEST_SEQUENCE_LOG:?}"
    ;;
  *)
    printf 'unexpected synthetic SSH command: %s\n' "$*" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 "$FAKE_BIN"/*

expected_sequence() {
  printf '%s\n' \
    checkout \
    control:create-network \
    control:create-volume \
    collector:baseline \
    target:workload-prepare-start \
    collector:normalize \
    collector:live \
    target:workload-cleanup \
    target:host \
    collector:normalize \
    collector:post-cleanup \
    control:remove-network \
    control:remove-volume \
    collector:host
}

run_fixture() {
  local evidence_dir="$1"
  local sequence_log="$2"
  local command_output="${3:-/dev/null}"
  PATH="$FAKE_BIN:$PATH" \
    SECPAL_TEST_REAL_PYTHON="$REAL_PYTHON" \
    SECPAL_TEST_SEQUENCE_LOG="$sequence_log" \
    SECPAL_TEST_HOST_JSON="$HOST_JSON" \
    SECPAL_TEST_LIVE_JSON="$LIVE_JSON" \
    SECPAL_TEST_BASELINE_JSON="$BASELINE_JSON" \
    SECPAL_TEST_CLEANUP_JSON="$CLEANUP_JSON" \
    scripts/ci-cloud/run-remote-conformance.sh \
    digitalocean fra1 intel 1.1.1.1 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 12345 1 \
    "$PRIVATE_KEY" "$evidence_dir" debian-13-x64 234194767 \
    s-4vcpu-8gb-intel >"$command_output" 2>&1
}

assert_no_target_diagnostics() {
  local evidence_dir="$1"
  if find "$evidence_dir" -maxdepth 1 -type f \
    -name '.target-phase-diagnostic.*' -print -quit | grep -q .; then
    printf 'FAIL: private target diagnostic remained after orchestration.\n' >&2
    exit 1
  fi
}

SUCCESS_LOG="$TEMP_DIR/success.log"
run_fixture "$TEMP_DIR/success-evidence" "$SUCCESS_LOG"
diff -u <(expected_sequence) "$SUCCESS_LOG"

FAILURE_LOG="$TEMP_DIR/failure.log"
FAILURE_OUTPUT="$TEMP_DIR/failure-output.log"
set +e
SECPAL_TEST_FAIL_PREPARE=true \
  run_fixture "$TEMP_DIR/failure-evidence" "$FAILURE_LOG" "$FAILURE_OUTPUT"
failure_status=$?
set -e
if [[ "$failure_status" -ne 1 ]]; then
  printf 'FAIL: expected prepare failure evidence status 1, got %s\n' \
    "$failure_status" >&2
  exit 1
fi
diff -u <(expected_sequence) "$FAILURE_LOG"
grep -Fq 'Target phase diagnostic: {"phase":"workload-prepare-start","status":7,' \
  "$FAILURE_OUTPUT"
grep -Fq 'ERROR: synthetic prepare failure' "$FAILURE_OUTPUT"
if grep -q '^::' "$FAILURE_OUTPUT"; then
  printf 'FAIL: target output became an active workflow command.\n' >&2
  exit 1
fi
if [[ "$(wc -c <"$FAILURE_OUTPUT")" -gt 20000 ]]; then
  printf 'FAIL: bounded target failure diagnostic is excessive.\n' >&2
  exit 1
fi

INTERRUPT_LOG="$TEMP_DIR/interrupt.log"
set +e
SECPAL_TEST_INTERRUPT_PREPARE=true \
  run_fixture "$TEMP_DIR/interrupt-evidence" "$INTERRUPT_LOG"
interrupt_status=$?
set -e
if [[ "$interrupt_status" -ne 130 ]]; then
  printf 'FAIL: expected handled interruption status 130, got %s\n' \
    "$interrupt_status" >&2
  exit 1
fi
grep -Fxq 'target:workload-cleanup' "$INTERRUPT_LOG"
grep -Fxq 'collector:normalize' "$INTERRUPT_LOG"
grep -Fxq 'collector:post-cleanup' "$INTERRUPT_LOG"
assert_no_target_diagnostics "$TEMP_DIR/interrupt-evidence"

HOST_INTERRUPT_LOG="$TEMP_DIR/host-interrupt.log"
set +e
SECPAL_TEST_INTERRUPT_HOST=true \
  run_fixture "$TEMP_DIR/host-interrupt-evidence" "$HOST_INTERRUPT_LOG"
host_interrupt_status=$?
set -e
if [[ "$host_interrupt_status" -ne 130 ]]; then
  printf 'FAIL: expected handled host interruption status 130, got %s\n' \
    "$host_interrupt_status" >&2
  exit 1
fi
if [[ "$(grep -Fxc 'target:workload-cleanup' "$HOST_INTERRUPT_LOG")" -ne 1 ||
  "$(grep -Fxc 'collector:normalize' "$HOST_INTERRUPT_LOG")" -ne 2 ||
  "$(grep -Fxc 'collector:post-cleanup' "$HOST_INTERRUPT_LOG")" -ne 1 ]]; then
  printf 'FAIL: finalized workload cleanup evidence was repeated during host interruption.\n' >&2
  exit 1
fi
grep -Fxq 'collector:host' "$HOST_INTERRUPT_LOG"
assert_no_target_diagnostics "$TEMP_DIR/host-interrupt-evidence"

printf 'Cloud workload orchestration fixture passed.\n'
