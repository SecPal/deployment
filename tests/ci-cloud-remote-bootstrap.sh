#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT

FAKE_BIN="$TEMP_DIR/bin"
EVIDENCE_DIR="$TEMP_DIR/evidence"
SSH_LOG="$TEMP_DIR/ssh.log"
PRIVATE_KEY="$TEMP_DIR/id_ed25519"
mkdir -p "$FAKE_BIN"
install -m 0600 /dev/null "$PRIVATE_KEY"

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

cat >"$FAKE_BIN/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -i | -o) shift 2 ;;
    *) shift; break ;;
  esac
done
printf 'ssh\n' >>"${SECPAL_TEST_SSH_LOG:?}"
exec "$@"
EOF

cat >"$FAKE_BIN/cloud-init" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "status --wait") exit 2 ;;
  "status --long")
    head -c 20000 /dev/zero | tr '\0' x
    ;;
  *) exit 1 ;;
esac
EOF

chmod 0755 "$FAKE_BIN"/*

set +e
PATH="$FAKE_BIN:$PATH" SECPAL_TEST_SSH_LOG="$SSH_LOG" \
  scripts/ci-cloud/run-remote-conformance.sh \
  digitalocean fra1 intel 1.1.1.1 \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 12345 1 \
  "$PRIVATE_KEY" "$EVIDENCE_DIR" debian-13-x64 234194767 \
  s-4vcpu-8gb-intel >"$TEMP_DIR/output.log" 2>&1
status=$?
set -e

if [[ "$status" -ne 2 ]]; then
  printf 'FAIL: expected remote bootstrap status 2, got %s\n' "$status" >&2
  exit 1
fi
if [[ "$(wc -l <"$SSH_LOG")" -ne 1 ]]; then
  printf 'FAIL: target or collector SSH ran after failed cloud-init\n' >&2
  exit 1
fi
if [[ -e "$EVIDENCE_DIR/evidence.json" ]]; then
  printf 'FAIL: incomplete full evidence survived bootstrap failure\n' >&2
  exit 1
fi
jq -e '
  .schema_version == 1 and
  .workflow.target_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .test.failure_stage == "cloud-init" and
  .test.orchestration_exit_status == 2 and
  .test.result == "failed" and
  .test.failed_admission_invariants == ["CI_CLOUD_REMOTE_ORCHESTRATION"]
' "$EVIDENCE_DIR/bootstrap-failure.json" >/dev/null
diagnostic_bytes="$(awk '/^x+$/{print length; exit}' "$TEMP_DIR/output.log")"
if [[ "$diagnostic_bytes" -ne 8192 ]]; then
  printf 'FAIL: cloud-init diagnostic was not capped at 8192 bytes (got %s)\n' \
    "$diagnostic_bytes" >&2
  exit 1
fi
grep -Fq 'Failure stage:' "$EVIDENCE_DIR/summary.md"
grep -Fq 'cloud-init' "$EVIDENCE_DIR/summary.md"

printf 'Cloud remote bootstrap failure contract passed.\n'
