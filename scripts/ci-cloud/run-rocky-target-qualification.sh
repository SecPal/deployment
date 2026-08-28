#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly fixture='docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1'
readonly evidence_root=/var/lib/secpal-rocky/evidence
readonly source_failure="$evidence_root/target-source-failure.json"
readonly qualification_failure="$evidence_root/target-qualification-failure.json"
readonly qualification_trace="$evidence_root/target-qualification.trace"
readonly qualification_marker="$evidence_root/target-qualification.marker"
readonly reload_adjacency="$evidence_root/quadlet-reload-adjacency.json"

if [[ "$#" -ne 4 || ! "$1" =~ ^[0-9a-f]{40}$ || ! "$2" =~ ^[0-9a-f]{40}$ ||
  ! "$3" =~ ^[1-9][0-9]{0,19}$ || ! "$4" =~ ^[1-9][0-9]{0,2}$ ]]; then
  printf 'usage: run-rocky-target-qualification.sh TARGET_SHA CONTROL_SHA RUN_ID RUN_ATTEMPT\n' >&2
  exit 64
fi
readonly target_sha="$1"
readonly control_sha="$2"
readonly qualification_run_id="$3"
readonly qualification_run_attempt="$4"
[[ -f /var/lib/secpal-rocky/prepared ]]
[[ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]
[[ -z "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]
if curl --noproxy '*' --fail --silent --max-time 2 \
  -H 'Metadata-Flavor: Google' \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
  >/dev/null 2>&1; then
  printf 'ERROR: target execution can reach a metadata credential.\n' >&2
  exit 1
fi

work_root="$(mktemp -d /var/tmp/secpal-rocky-target-XXXXXX)"
chmod 0700 "$work_root"
cleanup() {
  rm -rf -- "$work_root"
}
trap cleanup EXIT HUP INT TERM

write_source_failure() {
  local operation="$1" reason="$2" exit_status="$3" temporary
  [[ "$operation" =~ ^(resolve-target-source|fetch-exact-target|checkout-exact-target|verify-target-sha)$ ]]
  [[ "$reason" =~ ^(command-failed|postcondition-failed)$ ]]
  [[ "$exit_status" =~ ^[1-9][0-9]{0,2}$ && "$exit_status" -le 255 ]]
  temporary="$(mktemp "$evidence_root/.target-source-failure.XXXXXX")"
  printf '{"schema_version":1,"phase":"qualify-target","operation":"%s","reason":"%s","exit_status":%s,"source_host":"github.com","target_sha":"%s"}\n' \
    "$operation" "$reason" "$exit_status" "$target_sha" >"$temporary"
  chown secpal-cloud:secpal-cloud "$temporary"
  chmod 0400 "$temporary"
  mv -T -- "$temporary" "$source_failure"
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-target-source-failure "$source_failure" --target-sha "$target_sha"
}

rm -f -- "$source_failure" "$qualification_failure" "$qualification_trace" \
  "$qualification_marker" "$reload_adjacency"
if ! getent ahostsv4 github.com >/dev/null 2>&1; then
  write_source_failure resolve-target-source command-failed 1
  exit 81
fi

git -C "$work_root" init --quiet
git -C "$work_root" remote add origin https://github.com/SecPal/deployment.git
set +e
git -C "$work_root" fetch --quiet --depth=1 origin "$target_sha"
fetch_status=$?
set -e
if [[ "$fetch_status" -ne 0 ]]; then
  write_source_failure fetch-exact-target command-failed "$fetch_status"
  exit 82
fi
set +e
git -C "$work_root" checkout --quiet --detach FETCH_HEAD
checkout_status=$?
set -e
if [[ "$checkout_status" -ne 0 ]]; then
  write_source_failure checkout-exact-target command-failed "$checkout_status"
  exit 83
fi
if [[ "$(git -C "$work_root" rev-parse HEAD)" != "$target_sha" ]]; then
  write_source_failure verify-target-sha postcondition-failed 1
  exit 84
fi
[[ -x "$work_root/scripts/qualify-production-host.sh" ]]

stdout="$evidence_root/qualification.stdout"
audit_baseline="$(date -u '+%m/%d/%Y %H:%M:%S')"
journal_baseline="$(date -u '+%Y-%m-%d %H:%M:%S.%6N UTC')"
boot_id="$(cat /proc/sys/kernel/random/boot_id)"
[[ "$boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
reload_event="$work_root/quadlet-reload.event"
reload_ack="$work_root/quadlet-reload.ack"
observer_pid=""
if [[ "$target_sha" == d89214795bc1bdf0e65d9bbf7c8b9647b7e1ebd6 ]] &&
  [[ "$(sha256sum "$work_root/scripts/qualify-production-host.sh" | awk '{print $1}')" == \
    ad6d2518aa3f72054e6fa373b05345e7c37c21ac65feb6075eb69f3c434fea53 ]]; then
  mkfifo -m 0600 "$reload_event" "$reload_ack"
  /opt/secpal-control/scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py \
    --event "$reload_event" --ack "$reload_ack" --output "$reload_adjacency" \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt" \
    --boot-id "$boot_id" --journal-baseline "$journal_baseline" \
    --audit-baseline "$audit_baseline" &
  observer_pid=$!
  exec 4<>"$reload_event"
  exec 5<>"$reload_ack"
fi
set +e
(
  ulimit -f 128
  timeout --signal=TERM --kill-after=30s 45m \
    env BASH_ENV=/opt/secpal-control/scripts/ci-cloud/rocky-target-qualification-trace.sh \
    bash "$work_root/scripts/qualify-production-host.sh" \
    --image "$fixture" --service-account secpal-runtime >"$stdout" 2>&1 \
    3>"$qualification_trace"
)
status=$?
if [[ -n "$observer_pid" ]]; then
  exec 4>&-
  exec 5<&-
  wait "$observer_pid" >/dev/null 2>&1
fi
set -e
stdout_size="$(stat -c %s "$stdout")"
trace_size="$(stat -c %s "$qualification_trace")"
representation_option=()
if [[ "$stdout_size" -gt 65536 || "$trace_size" -gt 4096 ]]; then
  representation_option=(--representation-invalid)
  status=1
fi

if [[ "$status" -ne 0 ]]; then
  /usr/local/sbin/secpal-classify-rocky-target-failure \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt" \
    --harness "$work_root/scripts/qualify-production-host.sh" \
    --stdout "$stdout" --trace "$qualification_trace" \
    --reload-adjacency "$reload_adjacency" --exit-status "$status" \
    "${representation_option[@]}" \
    --output "$qualification_failure"
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-target-qualification-failure "$qualification_failure" \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt"
  chown secpal-cloud:secpal-cloud "$qualification_failure"
  chmod 0400 "$qualification_failure"
  exit 91
fi

# The target cannot pre-seed the trusted admission marker. The marker is absent
# when trusted success admission starts and is written only by reject().
rm -f -- "$qualification_marker"
set +e
python3 - "$target_sha" "$status" "$stdout" "$audit_baseline" \
  "$evidence_root/qualification.json" "$qualification_marker" <<'PY'
import hashlib
import json
import pwd
import re
import subprocess
import sys
from pathlib import Path

target_sha, raw_status, stdout_path, audit_baseline, output_path, marker_path = sys.argv[1:]


def reject(operation: str, reason: str, message: str) -> None:
    Path(marker_path).write_text(f"{operation} {reason}\n", encoding="ascii")
    raise SystemExit(message)


payload = Path(stdout_path).read_bytes()
try:
    text = payload.decode("utf-8")
except UnicodeDecodeError as error:
    reject("qualification-harness", "representation-invalid", "qualification stdout is not UTF-8")
if int(raw_status) != 0:
    reject("qualification-harness", "unclassified-target-failure", "qualification harness returned nonzero")
if text.count("PASS: Rocky Linux 10.2 native") != 1:
    reject("qualification-harness", "representation-invalid", "qualification PASS marker is not singular")
facts = {}
for key, value in re.findall(r"^(process_a|process_b|storage_a|seccomp_mode)=([^\r\n]+)$", text, re.MULTILINE):
    if key in facts:
        reject("qualification-harness", "representation-invalid", "qualification facts are duplicated")
    facts[key] = value
if set(facts) != {"process_a", "process_b", "storage_a", "seccomp_mode"}:
    reject("qualification-harness", "representation-invalid", "qualification facts are incomplete")
context = re.compile(r"^([^:]+):([^:]+):(container_t|container_file_t):(s0(?::c[0-9]+(?:,c[0-9]+)?)?)$")
parsed = {}
for key in ("process_a", "process_b", "storage_a"):
    match = context.fullmatch(facts[key])
    if match is None:
        reject("qualify-selinux-storage", "representation-invalid", "qualification SELinux context is malformed")
    parsed[key] = match.groups()
if parsed["process_a"][2] != "container_t" or parsed["process_b"][2] != "container_t" or parsed["storage_a"][2] != "container_file_t":
    reject("qualify-selinux-storage", "invariant-failed", "qualification SELinux types are not admitted")
if parsed["process_a"][3] != parsed["storage_a"][3] or parsed["process_b"][3] == parsed["process_a"][3]:
    reject("qualify-mcs-relationship", "invariant-failed", "qualification MCS relationship is not admitted")
if facts["seccomp_mode"] != "2":
    reject("qualify-seccomp", "invariant-failed", "qualification seccomp mode is not enforcing")
audit = subprocess.run(["ausearch", "-m", "AVC", "-ts", audit_baseline], check=False, capture_output=True, text=True, timeout=30)
if audit.returncode not in (0, 1) or len(audit.stdout.encode()) > 65536:
    reject("qualify-avc-correlation", "command-failed", "qualification audit observation failed")
avc_pattern = re.compile(r"scontext=(\S+).*tcontext=(\S+).*permissive=0", re.DOTALL)
avcs = [(source, target) for source, target in avc_pattern.findall(audit.stdout) if source == facts["process_b"] and target == facts["storage_a"]]
if len(avcs) != 1:
    reject(
        "qualify-avc-correlation",
        "invariant-failed",
        "qualification lacks one correlated enforcing AVC",
    )
runtime_account = pwd.getpwnam("secpal-runtime")
cleanup_checks = [
    [
        "runuser", "--user", "secpal-runtime", "--", "env",
        f"HOME={runtime_account.pw_dir}",
        f"XDG_RUNTIME_DIR=/run/user/{runtime_account.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime_account.pw_uid}/bus",
        "podman", "ps", "-a", "--format", "{{.Names}}",
    ],
    ["find", "/etc/containers/systemd/users", "-name", "secpal-host-qualification-*.container", "-print"],
    ["find", "/var/tmp", "-maxdepth", "1", "-name", "secpal-host-qualification-*", "-print"],
    ["find", "/etc/selinux/targeted/contexts/files", "-name", "secpal-host-qualification-*", "-print"],
    ["systemctl", "list-units", "--all", "--no-legend", "secpal-host-qualification-*"],
]
import subprocess
cleanup_results = [
    subprocess.run(command, check=False, capture_output=True, text=True)
    for command in cleanup_checks
]
cleanup_complete = all(
    result.returncode == 0 and not result.stdout.strip()
    for result in cleanup_results
)
if not cleanup_complete:
    reject("qualify-fixture-cleanup", "cleanup-failed", "qualification cleanup is incomplete")
document = {
    "schema_version": 1,
    "target_sha": target_sha,
    "exit_status": int(raw_status),
    "stdout_sha256": hashlib.sha256(payload).hexdigest(),
    "stdout_bytes": len(payload),
    "process_contexts": [facts.get("process_a", ""), facts.get("process_b", "")],
    "storage_context": facts.get("storage_a", ""),
    "mcs_distinct": True,
    "cross_mcs_denied": True,
    "avc_observed": True,
    "seccomp_enforced": True,
    "cleanup_complete": cleanup_complete,
    "classification": "PASS",
}
Path(output_path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
admission_status=$?
set -e
if [[ "$admission_status" -ne 0 ]]; then
  /usr/local/sbin/secpal-classify-rocky-target-failure \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt" \
    --harness "$work_root/scripts/qualify-production-host.sh" \
    --stdout "$stdout" --trace "$qualification_trace" \
    --exit-status "$admission_status" --trusted-marker "$qualification_marker" \
    --output "$qualification_failure"
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-target-qualification-failure "$qualification_failure" \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt"
  chown secpal-cloud:secpal-cloud "$qualification_failure"
  chmod 0400 "$qualification_failure"
  exit 91
fi
chmod 0600 "$evidence_root/qualification.json" "$stdout"
/opt/secpal-control/scripts/ci-cloud/rocky-control.py validate-evidence qualification \
  "$evidence_root/qualification.json"
chown secpal-cloud:secpal-cloud "$evidence_root/qualification.json" "$stdout"
chmod 0400 "$evidence_root/qualification.json" "$stdout"
rm -f -- "$qualification_trace" "$qualification_marker"
