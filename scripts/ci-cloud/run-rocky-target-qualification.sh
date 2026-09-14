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
readonly avc_correlation_diagnostic="$evidence_root/avc-correlation-diagnostic.json"
readonly reload_adjacency="$evidence_root/quadlet-reload-adjacency.json"
readonly native_observation="$evidence_root/native-package-observation.json"
readonly native_diagnostic="$evidence_root/native-package-collection-diagnostic.json"
readonly trusted_selinux_isolation_contract=/opt/secpal-control/scripts/selinux_isolation_contract.py
readonly trusted_quadlet_authority_contract=/opt/secpal-control/scripts/quadlet_authority_contract.py

if [[ "$#" -ne 5 || ! "$1" =~ ^[0-9a-f]{40}$ || ! "$2" =~ ^[0-9a-f]{40}$ ||
  ! "$3" =~ ^[1-9][0-9]{0,19}$ || ! "$4" =~ ^[1-9][0-9]{0,2}$ ||
  ! "$5" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'usage: run-rocky-target-qualification.sh TARGET_SHA CONTROL_SHA RUN_ID RUN_ATTEMPT HARNESS_SHA256\n' >&2
  exit 64
fi
readonly target_sha="$1"
readonly control_sha="$2"
readonly qualification_run_id="$3"
readonly qualification_run_attempt="$4"
readonly qualification_harness_sha256="$5"
readonly expected_target_sha=b76c24fe59fbe2406d8b84094fc9e6694c57f0c6
readonly expected_harness_sha256=abf7ba4af2ef5124a92fab29c9ae913ca7ca3c0056908f4aab7b3898bb497ea0
if [[ "$target_sha" != "$expected_target_sha" ||
  "$qualification_harness_sha256" != "$expected_harness_sha256" ]]; then
  printf 'ERROR: target and qualification harness are not the trusted pair.\n' >&2
  exit 64
fi
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
  exec 4>&- 5>&- 2>/dev/null || :
  if [[ -n "${observer_pid:-}" ]]; then
    kill "$observer_pid" >/dev/null 2>&1 || :
    wait "$observer_pid" >/dev/null 2>&1 || :
  fi
  if [[ -n "${trace_capture_pid:-}" ]]; then
    kill "$trace_capture_pid" >/dev/null 2>&1 || :
    wait "$trace_capture_pid" >/dev/null 2>&1 || :
  fi
  rm -f -- /var/lib/secpal-rocky/evidence/quadlet-start-observation.json \
    /var/lib/secpal-rocky/evidence/quadlet-active-observation.json \
    /var/lib/secpal-rocky/evidence/primary-workload-observation.json \
    /var/lib/secpal-rocky/evidence/quadlet-reload-adjacency.json \
    "$qualification_trace" "$qualification_marker" \
    "$avc_correlation_diagnostic"
  rm -rf -- "$work_root"
}
interrupted() {
  trap - HUP INT TERM
  exit "$1"
}
trap cleanup EXIT
trap 'interrupted 129' HUP
trap 'interrupted 130' INT
trap 'interrupted 143' TERM

capture_bounded() {
  local maximum="$1" output="$2" head_status=0 drain_status=0
  /usr/bin/head -c "$maximum" >"$output" || head_status=$?
  /usr/bin/cat >/dev/null || drain_status=$?
  ((head_status == 0 && drain_status == 0))
}

write_source_failure() {
  local operation="$1" reason="$2" exit_status="$3" temporary
  [[ "$operation" =~ ^(resolve-target-source|fetch-exact-target|checkout-exact-target|verify-target-sha|verify-native-observation)$ ]]
  [[ "$reason" =~ ^(command-failed|postcondition-failed)$ ]]
  [[ "$exit_status" =~ ^[1-9][0-9]{0,2}$ && "$exit_status" -le 255 ]]
  temporary="$(mktemp "$evidence_root/.target-source-failure.XXXXXX")"
  printf '{"schema_version":1,"phase":"qualify-target","operation":"%s","reason":"%s","exit_status":%s,"source_host":"github.com","target_sha":"%s","trusted_control_sha":"%s","qualification_run_id":"%s","qualification_run_attempt":"%s"}\n' \
    "$operation" "$reason" "$exit_status" "$target_sha" "$control_sha" \
    "$qualification_run_id" "$qualification_run_attempt" >"$temporary"
  chown secpal-cloud:secpal-cloud "$temporary"
  chmod 0400 "$temporary"
  mv -T -- "$temporary" "$source_failure"
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-target-source-failure \
    "$source_failure" --target-sha "$target_sha" \
    --control-sha "$control_sha" --run-id "$qualification_run_id" \
    --run-attempt "$qualification_run_attempt"
}

rm -f -- "$source_failure" "$qualification_failure" "$qualification_trace" \
  "$qualification_marker" "$reload_adjacency" "$native_observation" \
  "$native_diagnostic" "$avc_correlation_diagnostic"

# This controller-owned runner observes and admits the installed RPMDB before
# fetching or executing candidate target bytes.
set +e
/usr/local/sbin/secpal-collect-rocky-preparation \
  --native-package-admission --target-sha "$target_sha" \
  --control-sha "$control_sha" --run-id "$qualification_run_id" \
  --run-attempt "$qualification_run_attempt" --output "$native_observation" \
  --diagnostic-output "$native_diagnostic"
native_observation_status=$?
set -e
if [[ "$native_observation_status" -ne 0 ]]; then
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-collection-diagnostic "$native_diagnostic" || :
  write_source_failure verify-native-observation postcondition-failed \
    "$native_observation_status"
  exit 86
fi
rm -f -- "$native_diagnostic"
set +e
/opt/secpal-control/scripts/ci-cloud/rocky-control.py \
  validate-native-observation "$native_observation" \
  --target-sha "$target_sha" --control-sha "$control_sha" \
  --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt"
native_observation_status=$?
set -e
if [[ "$native_observation_status" -ne 0 ]]; then
  write_source_failure verify-native-observation postcondition-failed \
    "$native_observation_status"
  exit 86
fi

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
if ! [[ -f "$work_root/scripts/qualify-production-host.sh" && ! -L "$work_root/scripts/qualify-production-host.sh" && -x "$work_root/scripts/qualify-production-host.sh" &&
  -f "$work_root/scripts/selinux_isolation_contract.py" && ! -L "$work_root/scripts/selinux_isolation_contract.py" &&
  -f "$trusted_selinux_isolation_contract" && ! -L "$trusted_selinux_isolation_contract" &&
  "$(stat -c '%u:%g:%a' -- "$trusted_selinux_isolation_contract")" == 0:0:700 &&
  -f "$work_root/scripts/quadlet_authority_contract.py" && ! -L "$work_root/scripts/quadlet_authority_contract.py" &&
  -f "$trusted_quadlet_authority_contract" && ! -L "$trusted_quadlet_authority_contract" &&
  "$(stat -c '%u:%g:%a' -- "$trusted_quadlet_authority_contract")" == 0:0:700 ]] ||
  [[ "$(sha256sum "$work_root/scripts/qualify-production-host.sh" | awk '{print $1}')" != "$qualification_harness_sha256" ]] ||
  ! /usr/bin/cmp --silent -- "$work_root/scripts/selinux_isolation_contract.py" "$trusted_selinux_isolation_contract" ||
  ! /usr/bin/cmp --silent -- "$work_root/scripts/quadlet_authority_contract.py" "$trusted_quadlet_authority_contract"; then
  write_source_failure verify-target-sha postcondition-failed 1
  exit 84
fi

stdout="$evidence_root/qualification.stdout"
audit_baseline="$(date -u '+%m/%d/%y %H:%M:%S')"
journal_baseline="$(date -u '+%Y-%m-%d %H:%M:%S.%6N UTC')"
boot_id="$(cat /proc/sys/kernel/random/boot_id)"
[[ "$boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
reload_event="$work_root/quadlet-reload.event"
reload_ack="$work_root/quadlet-reload.ack"
start_observation="$evidence_root/quadlet-start-observation.json"
active_observation="$evidence_root/quadlet-active-observation.json"
primary_observation="$evidence_root/primary-workload-observation.json"
trace_fifo="$work_root/target-qualification.trace.fifo"
install -o root -g root -m 0600 /dev/null "$start_observation"
install -o root -g root -m 0600 /dev/null "$active_observation"
install -o root -g root -m 0600 /dev/null "$primary_observation"
mkfifo -m 0600 "$trace_fifo"
observer_pid=""
trace_capture_pid=""
if [[ "$target_sha" == "$expected_target_sha" ]] &&
  [[ "$qualification_harness_sha256" == "$expected_harness_sha256" ]]; then
  mkfifo -m 0600 "$reload_event" "$reload_ack"
  /opt/secpal-control/scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py \
    --event "$reload_event" --ack "$reload_ack" --output "$reload_adjacency" \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt" \
    --boot-id "$boot_id" --journal-baseline "$journal_baseline" &
  observer_pid=$!
  exec 4<>"$reload_event"
  exec 5<>"$reload_ack"
fi
capture_bounded 4097 "$qualification_trace" <"$trace_fifo" &
trace_capture_pid=$!
set +e
timeout --signal=TERM --kill-after=180s 45m \
  env BASH_ENV=/opt/secpal-control/scripts/ci-cloud/rocky-target-qualification-trace.sh \
  SECPAL_AVC_CORRELATION_DIAGNOSTIC_FD=6 \
  bash "$work_root/scripts/qualify-production-host.sh" \
  --image "$fixture" --service-account secpal-runtime \
  6>"$avc_correlation_diagnostic" \
  3>"$trace_fifo" 2>&1 | capture_bounded 65537 "$stdout"
pipeline_statuses=("${PIPESTATUS[@]}")
status="${pipeline_statuses[0]}"
stdout_capture_status="${pipeline_statuses[1]}"
wait "$trace_capture_pid"
trace_capture_status=$?
trace_capture_pid=""
if [[ -n "$observer_pid" ]]; then
  exec 4>&-
  exec 5<&-
  wait "$observer_pid" >/dev/null 2>&1
  observer_pid=""
fi
set -e
stdout_size="$(stat -c %s "$stdout")"
trace_size="$(stat -c %s "$qualification_trace")"
representation_option=()
if [[ "$stdout_capture_status" -ne 0 || "$trace_capture_status" -ne 0 ||
  "$stdout_size" -gt 65536 || "$trace_size" -gt 4096 ]]; then
  representation_option=(--representation-invalid)
fi

if [[ "$status" -ne 0 || "${#representation_option[@]}" -ne 0 ]]; then
  set +e
  /usr/local/sbin/secpal-classify-rocky-target-failure \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt" \
    --harness "$work_root/scripts/qualify-production-host.sh" \
    --stdout "$stdout" --trace "$qualification_trace" \
    --reload-adjacency "$reload_adjacency" --exit-status "$status" \
    --start-observation "$start_observation" \
    --active-observation "$active_observation" \
    --primary-observation "$primary_observation" \
    --avc-correlation-diagnostic "$avc_correlation_diagnostic" \
    "${representation_option[@]}" \
    --output "$qualification_failure"
  classifier_status=$?
  rm -f -- "$stdout"
  stdout_remove_status=$?
  set -e
  [[ "$classifier_status" -eq 0 ]]
  [[ "$stdout_remove_status" -eq 0 ]]
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-target-qualification-failure "$qualification_failure" \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt"
  chown secpal-cloud:secpal-cloud "$qualification_failure"
  chmod 0400 "$qualification_failure"
  rm -f -- "$start_observation" "$active_observation" \
    "$primary_observation" "$reload_adjacency"
  exit 91
fi

# The target cannot pre-seed the trusted admission marker. The marker is absent
# when trusted success admission starts and is written only by reject().
rm -f -- "$qualification_marker"
set +e
python3 - "$target_sha" "$status" "$stdout" "$audit_baseline" \
  "$evidence_root/qualification.json" "$qualification_marker" \
  "$native_observation" <<'PY'
import base64
import binascii
import hashlib
import importlib.util
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

(
    target_sha,
    raw_status,
    stdout_path,
    audit_baseline,
    output_path,
    marker_path,
    native_observation_path,
) = sys.argv[1:]

def reject(operation: str, reason: str, message: str) -> None:
    Path(marker_path).write_text(f"{operation} {reason}\n", encoding="ascii")
    raise SystemExit(message)


contract_path = Path(
    "/opt/secpal-control/scripts/selinux_isolation_contract.py"
)
contract_specification = importlib.util.spec_from_file_location(
    "selinux_isolation_contract", contract_path
)
if contract_specification is None or contract_specification.loader is None:
    reject(
        "qualify-selinux-storage",
        "command-failed",
        "SELinux isolation contract is unavailable",
    )
selinux_isolation_contract = importlib.util.module_from_spec(
    contract_specification
)
sys.dont_write_bytecode = True
try:
    contract_specification.loader.exec_module(selinux_isolation_contract)
except Exception:
    reject(
        "qualify-selinux-storage",
        "command-failed",
        "SELinux isolation contract is unavailable",
    )

quadlet_contract_path = Path(
    "/opt/secpal-control/scripts/quadlet_authority_contract.py"
)
quadlet_contract_specification = importlib.util.spec_from_file_location(
    "quadlet_authority_contract", quadlet_contract_path
)
if (
    quadlet_contract_specification is None
    or quadlet_contract_specification.loader is None
):
    reject(
        "qualify-quadlet-authority",
        "command-failed",
        "Quadlet authority contract is unavailable",
    )
quadlet_authority_contract = importlib.util.module_from_spec(
    quadlet_contract_specification
)
try:
    quadlet_contract_specification.loader.exec_module(quadlet_authority_contract)
except Exception:
    reject(
        "qualify-quadlet-authority",
        "command-failed",
        "Quadlet authority contract is unavailable",
    )


def run_bounded(
    command: list[str],
    *,
    stdout_limit: int,
    stderr_limit: int,
    timeout: int,
    cwd: str | None = None,
) -> tuple[int | None, bytes, bytes, bool]:
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
                "LC_ALL": "C",
            },
            start_new_session=True,
        )
    except OSError:
        return None, b"", b"", True
    assert process.stdout is not None and process.stderr is not None
    streams: dict[str, tuple[bytes, bool]] = {}

    def drain(name: str, source: object, maximum: int) -> None:
        retained = bytearray()
        invalid = False
        try:
            while True:
                chunk = source.read(8192)
                if not chunk:
                    break
                remaining = maximum + 1 - len(retained)
                if remaining > 0:
                    retained.extend(chunk[:remaining])
                if len(retained) > maximum or len(chunk) > remaining:
                    invalid = True
        except OSError:
            invalid = True
        streams[name] = (bytes(retained), invalid)

    readers = (
        threading.Thread(
            target=drain,
            args=("stdout", process.stdout, stdout_limit),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=("stderr", process.stderr, stderr_limit),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    invalid = False
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        invalid = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        status = process.wait()
    for reader in readers:
        reader.join(timeout=1)
    if any(reader.is_alive() for reader in readers):
        invalid = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        for reader in readers:
            reader.join(timeout=1)
    process.stdout.close()
    process.stderr.close()
    stdout, stdout_invalid = streams.get("stdout", (b"", True))
    stderr, stderr_invalid = streams.get("stderr", (b"", True))
    return status, stdout, stderr, invalid or stdout_invalid or stderr_invalid


def acquire_audit_events(
    command: list[str],
    *,
    process_a: str,
    process_b: str,
    storage_a: str,
) -> tuple[bytes | None, dict[str, object] | None]:
    for attempt in range(12):
        status, stdout, stderr, invalid = run_bounded(
            command,
            stdout_limit=65536,
            stderr_limit=4096,
            timeout=5,
        )
        if status == 0 and not invalid and not stderr:
            try:
                audit_text = stdout.decode("utf-8")
            except UnicodeDecodeError:
                return None, None
            try:
                isolation = selinux_isolation_contract.admit_selinux_isolation(
                    process_a=process_a,
                    process_b=process_b,
                    storage_a=storage_a,
                    audit_text=audit_text,
                )
            except selinux_isolation_contract.NoMatchingAvc:
                isolation = None
            except selinux_isolation_contract.IsolationError:
                return None, None
            if isolation is not None:
                return stdout, isolation
            no_finding = True
        else:
            no_finding = (
                status == 1
                and not invalid
                and not stdout
                and stderr in {b"", b"<no matches>\n"}
            )
        if not no_finding:
            return None, None
        if attempt < 11:
            time.sleep(0.5)
    return b"", None


def runtime_home_admitted(
    runtime_home: Path,
    runtime_account: object,
    home_metadata: os.stat_result,
    parent_metadata: os.stat_result,
) -> bool:
    return (
        runtime_home == Path("/home/secpal-runtime")
        and stat.S_ISDIR(home_metadata.st_mode)
        and home_metadata.st_uid == runtime_account.pw_uid
        and home_metadata.st_gid == runtime_account.pw_gid
        and bool(home_metadata.st_mode & stat.S_IXUSR)
        and stat.S_ISDIR(parent_metadata.st_mode)
        and parent_metadata.st_uid == 0
        and parent_metadata.st_gid == 0
        and not parent_metadata.st_mode & 0o022
        and bool(parent_metadata.st_mode & stat.S_IXOTH)
    )


def admitted_runtime_home() -> tuple[object, Path] | None:
    try:
        runtime_account = pwd.getpwnam("secpal-runtime")
        runtime_home = Path(runtime_account.pw_dir)
        home_metadata = runtime_home.lstat()
        parent_metadata = runtime_home.parent.lstat()
    except (KeyError, OSError):
        return None
    if not runtime_home_admitted(
        runtime_home,
        runtime_account,
        home_metadata,
        parent_metadata,
    ):
        return None
    return runtime_account, runtime_home


payload = Path(stdout_path).read_bytes()
try:
    text = payload.decode("utf-8")
except UnicodeDecodeError as error:
    reject("qualification-harness", "representation-invalid", "qualification stdout is not UTF-8")
if int(raw_status) != 0:
    reject("qualification-harness", "unclassified-target-failure", "qualification harness returned nonzero")
if text.count("PASS: Rocky Linux 10.2 target workload contract") != 1:
    reject("qualification-harness", "representation-invalid", "qualification PASS marker is not singular")
facts = {}
for key, value in re.findall(
    r"^(process_a|process_b|storage_a|seccomp_mode|denial_pid|"
    r"selinux_isolation_sha256|quadlet_authority_base64)=([^\r\n]+)$",
    text,
    re.MULTILINE,
):
    if key in facts:
        reject("qualification-harness", "representation-invalid", "qualification facts are duplicated")
    facts[key] = value
if set(facts) != {
    "process_a",
    "process_b",
    "storage_a",
    "seccomp_mode",
    "denial_pid",
    "selinux_isolation_sha256",
    "quadlet_authority_base64",
}:
    reject("qualification-harness", "representation-invalid", "qualification facts are incomplete")
if facts["seccomp_mode"] != "2":
    reject("qualify-seccomp", "invariant-failed", "qualification seccomp mode is not enforcing")
try:
    denial_pid = int(facts["denial_pid"])
except ValueError:
    reject("qualify-avc-correlation", "representation-invalid", "qualification process identity is malformed")
if str(denial_pid) != facts["denial_pid"] or not 1 <= denial_pid <= 2_147_483_647:
    reject("qualify-avc-correlation", "representation-invalid", "qualification process identity is malformed")
if re.fullmatch(r"[0-9a-f]{64}", facts["selinux_isolation_sha256"]) is None:
    reject("qualify-avc-correlation", "representation-invalid", "qualification isolation digest is malformed")
try:
    quadlet_authority_bytes = base64.b64decode(
        facts["quadlet_authority_base64"], validate=True
    )
    if len(quadlet_authority_bytes) > 16_384:
        raise ValueError("Quadlet authority evidence exceeds its closed bound")
    quadlet_authority = json.loads(quadlet_authority_bytes)
    quadlet_authority_contract.validate_authority_evidence(quadlet_authority)
    if (
        quadlet_authority_contract.canonical_bytes(quadlet_authority)
        != quadlet_authority_bytes
    ):
        raise ValueError("Quadlet authority evidence is not canonical")
except (
    binascii.Error,
    UnicodeDecodeError,
    json.JSONDecodeError,
    ValueError,
    quadlet_authority_contract.AuthorityError,
):
    reject(
        "qualify-quadlet-authority",
        "representation-invalid",
        "qualification Quadlet authority evidence is invalid",
    )
audit_checkpoint = re.fullmatch(
    r"([0-9]{2}/[0-9]{2}/[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2})",
    audit_baseline,
)
if audit_checkpoint is None:
    reject("qualify-avc-correlation", "command-failed", "qualification audit observation failed")
audit_date, audit_time = audit_checkpoint.groups()
try:
    datetime.strptime(audit_baseline, "%m/%d/%y %H:%M:%S")
except ValueError:
    reject("qualify-avc-correlation", "command-failed", "qualification audit observation failed")
audit_stdout, selinux_isolation = acquire_audit_events(
    [
        "/usr/sbin/ausearch", "--input-logs", "-m", "AVC", "-ts",
        audit_date, audit_time, "-i",
    ],
    process_a=facts["process_a"],
    process_b=facts["process_b"],
    storage_a=facts["storage_a"],
)
if audit_stdout is None or selinux_isolation is None:
    reject("qualify-avc-correlation", "command-failed", "qualification audit observation failed")
isolation_digest = hashlib.sha256(
    selinux_isolation_contract.canonical_bytes(selinux_isolation)
).hexdigest()
if isolation_digest != facts["selinux_isolation_sha256"]:
    reject(
        "qualify-avc-correlation",
        "invariant-failed",
        "target and trusted SELinux isolation normalization disagree",
    )
if selinux_isolation["denial"]["pid"] != denial_pid:
    reject(
        "qualify-avc-correlation",
        "invariant-failed",
        "target and trusted tested-process identities disagree",
    )
runtime_identity = admitted_runtime_home()
if runtime_identity is None:
    reject("qualify-fixture-cleanup", "cleanup-failed", "qualification cleanup is incomplete")
runtime_account, runtime_home = runtime_identity
cleanup_checks = [
    ("podman", [
        "/usr/sbin/runuser", "--user", "secpal-runtime", "--", "/usr/bin/env",
        "-u", "CONTAINER_HOST", "-u", "CONTAINER_CONNECTION",
        f"HOME={runtime_account.pw_dir}",
        f"XDG_RUNTIME_DIR=/run/user/{runtime_account.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{runtime_account.pw_uid}/bus",
        "/usr/bin/podman", "ps", "-a", "--format", "{{.Names}}",
    ]),
    ("quadlet", ["/usr/bin/find", "/etc/containers/systemd/users", "-name", "secpal-host-qualification-*.container", "-print"]),
    ("vartmp", ["/usr/bin/find", "/var/tmp", "-maxdepth", "1", "-name", "secpal-host-qualification-*", "-print"]),
    ("fcontext", ["/usr/bin/find", "/etc/selinux/targeted/contexts/files", "-name", "secpal-host-qualification-*", "-print"]),
    ("units", ["/usr/bin/systemctl", "list-units", "--all", "--no-legend", "secpal-host-qualification-*"]),
]
cleanup_results = [
    run_bounded(
        command,
        stdout_limit=4096,
        stderr_limit=4096,
        timeout=10,
        cwd=str(runtime_home) if name == "podman" else None,
    )
    for name, command in cleanup_checks
]
cleanup_complete = all(
    status == 0 and not stdout.strip() and not invalid
    for status, stdout, _stderr, invalid in cleanup_results
)
if not cleanup_complete:
    reject("qualify-fixture-cleanup", "cleanup-failed", "qualification cleanup is incomplete")
document = {
    "schema_version": 3,
    "target_sha": target_sha,
    "native_observation": json.loads(
        Path(native_observation_path).read_text(encoding="utf-8")
    ),
    "quadlet_authority": quadlet_authority,
    "exit_status": int(raw_status),
    "stdout_sha256": hashlib.sha256(payload).hexdigest(),
    "stdout_bytes": len(payload),
    "selinux_isolation": selinux_isolation,
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
    --start-observation "$start_observation" \
    --active-observation "$active_observation" \
    --primary-observation "$primary_observation" \
    --avc-correlation-diagnostic "$avc_correlation_diagnostic" \
    --exit-status "$status" --trusted-marker "$qualification_marker" \
    --output "$qualification_failure"
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-target-qualification-failure "$qualification_failure" \
    --target-sha "$target_sha" --control-sha "$control_sha" \
    --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt"
  chown secpal-cloud:secpal-cloud "$qualification_failure"
  chmod 0400 "$qualification_failure"
  rm -f -- "$stdout"
  rm -f -- "$start_observation" "$active_observation" \
    "$primary_observation" "$reload_adjacency"
  exit 91
fi
chmod 0600 "$evidence_root/qualification.json" "$stdout"
/opt/secpal-control/scripts/ci-cloud/rocky-control.py validate-native-qualification \
  "$evidence_root/qualification.json" --stdout "$stdout" \
  --native-observation "$native_observation" \
  --target-sha "$target_sha" --control-sha "$control_sha" \
  --run-id "$qualification_run_id" --run-attempt "$qualification_run_attempt"
chown secpal-cloud:secpal-cloud "$evidence_root/qualification.json" "$stdout"
chown secpal-cloud:secpal-cloud "$native_observation"
chmod 0400 "$evidence_root/qualification.json" "$stdout" "$native_observation"
rm -f -- "$qualification_trace" "$qualification_marker" \
  "$start_observation" "$active_observation" "$primary_observation" \
  "$reload_adjacency"
