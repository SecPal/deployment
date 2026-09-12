#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly NOT_RUN=2
readonly QUALIFIED_ROCKY_MINOR="10.2"
readonly DEFAULT_ACCOUNT="secpal-deploy"
readonly UNIT_PREFIX="secpal-host-qualification"
readonly WORKLOAD_UID="65532"
readonly WORKLOAD_GID="65532"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly SELINUX_ISOLATION_CONTRACT="${SCRIPT_DIR}/selinux_isolation_contract.py"
readonly SELINUX_ISOLATION_INVARIANT_OWNER="selinux_isolation_contract.admit_selinux_isolation"
readonly QUADLET_AUTHORITY_CONTRACT="${SCRIPT_DIR}/quadlet_authority_contract.py"
readonly QUADLET_AUTHORITY_INVARIANT_OWNER="quadlet_authority_contract.admit_quadlet_authority"

image=""
service_account="$DEFAULT_ACCOUNT"
fixture_root=""
unit_path=""
container_a=""
container_b=""
unit_name=""
dontaudit_disabled=false
interrupted_status=0
cleanup_started=false
qualification_success_marker=""

usage() {
  printf 'Usage: %s --image REGISTRY/IMAGE@sha256:DIGEST [--service-account NAME]\n' "$0"
}

read_os_release_value() {
  local key="$1"
  awk -F= -v wanted="$key" '
    $1 == wanted {
      value = substr($0, index($0, "=") + 1)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
  ' /etc/os-release
}

run_as_service_account() (
  cd -- "$service_home"
  runuser --user "$service_account" -- env -u CONTAINER_HOST -u CONTAINER_CONNECTION \
    "HOME=${service_home}" \
    "XDG_RUNTIME_DIR=/run/user/${service_uid}" \
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${service_uid}/bus" \
    "$@"
)

rootless_podman() {
  run_as_service_account podman "$@"
}

user_systemctl() {
  run_as_service_account systemctl --user "$@"
}

path_ancestry() {
  local target="$1" boundary="$2" relative component
  [[ "$target" == /* && "$boundary" == /* ]] || return 1
  [[ "$(realpath -m -- "$target")" == "$target" ]] || return 1
  [[ "$(realpath -m -- "$boundary")" == "$boundary" ]] || return 1
  if [[ "$boundary" == / ]]; then
    relative="${target#/}"
  else
    [[ "$target" == "$boundary" || "$target" == "$boundary/"* ]] || return 1
    relative="${target#"$boundary"}"
    relative="${relative#/}"
  fi
  printf '%s\n' "$boundary"
  component="$boundary"
  while [[ -n "$relative" ]]; do
    local name="${relative%%/*}"
    [[ -n "$name" && "$name" != . && "$name" != .. ]] || return 1
    if [[ "$component" == / ]]; then
      component="/$name"
    else
      component="$component/$name"
    fi
    printf '%s\n' "$component"
    if [[ "$relative" == */* ]]; then
      relative="${relative#*/}"
    else
      relative=""
    fi
  done
}

administrator_path_admitted() {
  local target="$1" boundary="$2" administrator_uid="$3" administrator_gid="$4"
  local leaf_type="${5:-directory}" leaf_mode="${6:-}" component metadata uid gid mode
  local -a components=()
  mapfile -t components < <(path_ancestry "$target" "$boundary") || return 1
  ((${#components[@]} >= 1)) || return 1
  for component in "${components[@]}"; do
    [[ -e "$component" && ! -L "$component" ]] || return 1
    if [[ "$component" == "$target" && "$leaf_type" == file ]]; then
      [[ -f "$component" ]] || return 1
    else
      [[ -d "$component" ]] || return 1
    fi
    metadata="$(stat -c '%u:%g:%a' -- "$component")" || return 1
    IFS=: read -r uid gid mode <<<"$metadata"
    [[ "$uid" == "$administrator_uid" && "$gid" == "$administrator_gid" ]] || return 1
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (((8#$mode & 8#022) == 0)) || return 1
    if [[ "$component" == "$target" && -n "$leaf_mode" ]]; then
      [[ "$mode" == "$leaf_mode" ]] || return 1
    fi
  done
  return 0
}

service_account_cannot_write_path() {
  local target="$1" boundary="$2" component
  local -a components=()
  mapfile -t components < <(path_ancestry "$target" "$boundary") || return 1
  ((${#components[@]} >= 1)) || return 1
  for component in "${components[@]}"; do
    if run_as_service_account test -w "$component"; then
      return 1
    fi
  done
  return 0
}

effective_process_ids() {
  local status_path="$1" identities
  identities="$(awk '
    $1 == "Uid:" { uid_count++; uid = $3 }
    $1 == "Gid:" { gid_count++; gid = $3 }
    END {
      if (uid_count != 1 || gid_count != 1) exit 1
      print uid ":" gid
    }
  ' "$status_path")" || return 1
  [[ "$identities" =~ ^[0-9]+:[0-9]+$ ]] || return 1
  printf '%s\n' "$identities"
}

runtime_identity_admitted() {
  local rootless="$1" observed_uid="$2" observed_gid="$3" expected_uid="$4" expected_gid="$5"
  [[ "$rootless" == true ]] || return 1
  [[ "$expected_uid" =~ ^[1-9][0-9]*$ && "$expected_gid" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$observed_uid" == "$expected_uid" && "$observed_gid" == "$expected_gid" ]] || return 1
  return 0
}

effective_quadlet_service_admitted() {
  local properties_path="$1" expected_fragment="$2" expected_source="$3"
  local evidence_path="$4"
  [[ -f "$QUADLET_AUTHORITY_CONTRACT" && ! -L "$QUADLET_AUTHORITY_CONTRACT" ]] || return 1
  python3 "$QUADLET_AUTHORITY_CONTRACT" "$properties_path" \
    --expected-fragment "$expected_fragment" \
    --expected-source "$expected_source" --output "$evidence_path" \
    >/dev/null 2>&1 &&
    grep -Fq \
      "\"invariant_owner\":\"${QUADLET_AUTHORITY_INVARIANT_OWNER}\"" \
      "$evidence_path"
}

least_authority_process_admitted() {
  local status_path="$1" expected_uid="$2" expected_gid="$3" identities field value
  identities="$(effective_process_ids "$status_path")" || return 1
  [[ "$identities" == "$expected_uid:$expected_gid" ]] || return 1
  value="$(awk '$1 == "NoNewPrivs:" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$status_path")" || return 1
  [[ "$value" == 1 ]] || return 1
  for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    value="$(awk -v field="$field:" '$1 == field { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$status_path")" || return 1
    [[ "$value" == 0000000000000000 ]] || return 1
  done
  value="$(awk '$1 == "Seccomp:" { count++; value = $2 } END { if (count != 1) exit 1; print value }' "$status_path")" || return 1
  [[ "$value" == 2 ]] || return 1
  return 0
}

cleanup() {
  local exit_status=$?
  trap - EXIT HUP INT TERM
  if ((interrupted_status != 0)); then
    exit_status="$interrupted_status"
  fi
  if [[ "$cleanup_started" == true ]]; then
    exit "$exit_status"
  fi
  cleanup_started=true
  set +e
  if [[ -n "$qualification_success_marker" ]]; then
    /usr/bin/timeout --signal=KILL 5s rm -f -- "$qualification_success_marker" \
      >/dev/null 2>&1
  fi
  if [[ "$dontaudit_disabled" == true ]]; then
    /usr/bin/timeout --signal=KILL 30s semodule -B >/dev/null 2>&1
    dontaudit_disabled=false
  fi
  if [[ -n "$unit_name" ]]; then
    run_as_service_account /usr/bin/timeout --signal=KILL 20s \
      systemctl --user stop "${unit_name}.service" >/dev/null 2>&1
  fi
  if [[ -n "$container_a" ]]; then
    run_as_service_account /usr/bin/timeout --signal=KILL 20s \
      podman rm --force "$container_a" >/dev/null 2>&1
  fi
  if [[ -n "$container_b" ]]; then
    run_as_service_account /usr/bin/timeout --signal=KILL 20s \
      podman rm --force "$container_b" >/dev/null 2>&1
  fi
  if [[ -n "$unit_path" && -f "$unit_path" ]]; then
    /usr/bin/timeout --signal=KILL 5s rm -- "$unit_path" >/dev/null 2>&1
    run_as_service_account /usr/bin/timeout --signal=KILL 20s \
      systemctl --user daemon-reload >/dev/null 2>&1
  fi
  if [[ -n "$unit_name" ]]; then
    run_as_service_account /usr/bin/timeout --signal=KILL 20s \
      systemctl --user reset-failed "${unit_name}.service" >/dev/null 2>&1
  fi
  if [[ -n "$fixture_root" && -d "$fixture_root" ]]; then
    /usr/bin/timeout --signal=KILL 10s rm -rf -- "$fixture_root" \
      >/dev/null 2>&1
  fi
  exit "$exit_status"
}

interrupted() {
  interrupted_status="$1"
  trap - HUP INT TERM
  exit "$interrupted_status"
}

install_cleanup_traps() {
  trap cleanup EXIT
  trap 'interrupted 129' HUP
  trap 'interrupted 130' INT
  trap 'interrupted 143' TERM
}

admit_audit_observation() {
  local audit_path="$1" output_path="$2"
  python3 - "$SELINUX_ISOLATION_CONTRACT" "$audit_path" "$output_path" \
    "$process_a" "$process_b" "$storage_a" \
    "$SELINUX_ISOLATION_INVARIANT_OWNER" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

(
    contract_path,
    audit_path,
    output_path,
    process_a,
    process_b,
    storage_a,
    invariant_owner,
) = sys.argv[1:]
specification = importlib.util.spec_from_file_location(
    "selinux_isolation_contract", contract_path
)
if specification is None or specification.loader is None:
    raise SystemExit(1)
contract = importlib.util.module_from_spec(specification)
sys.dont_write_bytecode = True
try:
    specification.loader.exec_module(contract)
    if contract.INVARIANT_OWNER != invariant_owner:
        raise ValueError("SELinux isolation invariant owner mismatch")
    document = contract.admit_selinux_isolation(
        process_a=process_a,
        process_b=process_b,
        storage_a=storage_a,
        audit_text=Path(audit_path).read_text(encoding="utf-8"),
    )
except contract.NoMatchingAvc:
    raise SystemExit(2) from None
except (OSError, UnicodeError, ValueError, contract.IsolationError):
    raise SystemExit(1) from None
Path(output_path).write_bytes(contract.canonical_bytes(document))
PY
}

observe_denied_access() {
  local audit_date audit_time access_status audit_status capture_status
  local admission_status audit_size attempt
  rm -f -- "$audit_observation" "$isolation_document"
  read -r audit_date audit_time < <(LC_ALL=C date '+%x %T')
  set +e
  rootless_podman exec "$container_b" cat /foreign/marker >/dev/null 2>&1
  access_status=$?
  set -e
  if [[ "$access_status" -eq 0 ]]; then
    return 2
  fi
  if [[ ! -e "${state_a}/marker" || ! -r "${state_a}/marker" ]]; then
    return 2
  fi

  for attempt in {1..12}; do
    set +e
    LC_ALL=C /usr/bin/timeout --signal=KILL 5s \
      ausearch --input-logs -m AVC -ts "$audit_date" "$audit_time" -i \
      2>/dev/null | /usr/bin/head -c 65537 >"$audit_observation"
    pipeline_statuses=("${PIPESTATUS[@]}")
    audit_status="${pipeline_statuses[0]}"
    capture_status="${pipeline_statuses[1]}"
    set -e
    audit_size="$(stat -c %s -- "$audit_observation")"
    if [[ "$audit_status" -eq 0 && "$capture_status" -eq 0 &&
      "$audit_size" -le 65536 ]]; then
      set +e
      admit_audit_observation \
        "$audit_observation" "$isolation_document"
      admission_status=$?
      set -e
      case "$admission_status" in
        0) return 0 ;;
        2) ;;
        *) return 2 ;;
      esac
    elif [[ "$audit_status" -ne 1 || "$capture_status" -ne 0 ||
      "$audit_size" -gt 65536 ]]; then
      return 2
    fi
    if ((attempt < 12)); then
      sleep 0.5
    fi
  done
  return 3
}

main() {

while (($#)); do
  case "$1" in
    --image)
      [[ $# -ge 2 ]] || { usage >&2; exit 64; }
      image="$2"
      shift 2
      ;;
    --service-account)
      [[ $# -ge 2 ]] || { usage >&2; exit 64; }
      service_account="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
done

os_id="$(read_os_release_value ID)"
os_version="$(read_os_release_value VERSION_ID)"
if [[ "$os_id" != rocky || "$os_version" != "$QUALIFIED_ROCKY_MINOR" ]]; then
  printf 'NOT RUN: Rocky Linux %s native qualification requires ID=rocky and VERSION_ID=%s; observed ID=%s VERSION_ID=%s.\n' \
    "$QUALIFIED_ROCKY_MINOR" "$QUALIFIED_ROCKY_MINOR" "${os_id:-missing}" "${os_version:-missing}"
  exit "$NOT_RUN"
fi

if ((EUID != 0)); then
  printf 'ERROR: native qualification must run as an administrator on the disposable qualification host.\n' >&2
  exit 1
fi
if [[ ! "$image" =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
  printf 'ERROR: --image must be a fully qualified, pre-staged digest reference.\n' >&2
  exit 1
fi
service_passwd_entry="$(getent passwd "$service_account" || true)"
if [[ -z "$service_passwd_entry" ]]; then
  printf 'ERROR: required service account does not exist: %s\n' "$service_account" >&2
  exit 1
fi

service_uid="$(id -u "$service_account")"
service_gid="$(id -g "$service_account")"
service_home="$(awk -F: '{print $6}' <<<"$service_passwd_entry")"
if [[ -z "$service_home" || "$service_home" != /* || ! -d "$service_home" ]]; then
  printf 'ERROR: service-account home must be an existing absolute directory: %s\n' "$service_account" >&2
  exit 1
fi
readonly service_uid service_gid service_home
if ! [[ "$service_uid" =~ ^[1-9][0-9]*$ && "$service_gid" =~ ^[1-9][0-9]*$ ]]; then
  printf 'ERROR: service account must resolve to a non-root runtime identity.\n' >&2
  exit 1
fi
if ! run_as_service_account test -d "$service_home"; then
  printf 'ERROR: service-account home is not usable by %s: %s\n' "$service_account" "$service_home" >&2
  exit 1
fi
readonly quadlet_root="/etc/containers/systemd/users/${service_uid}"
readonly quadlet_search_policy="/etc/systemd/system/user@${service_uid}.service.d/50-secpal-quadlet.conf"

if [[ "$(getenforce)" != Enforcing ]]; then
  printf 'ERROR: SELinux is not Enforcing.\n' >&2
  exit 1
fi

architecture="$(uname -m)"
case "$architecture" in
  x86_64)
    if ! /lib64/ld-linux-x86-64.so.2 --help | grep -Fq 'x86-64-v3 (supported, searched)'; then
      printf 'ERROR: x86_64 CPU does not satisfy Rocky Linux 10 x86-64-v3.\n' >&2
      exit 1
    fi
    ;;
  aarch64) ;;
  *)
    printf 'ERROR: unsupported native architecture: %s\n' "$architecture" >&2
    exit 1
    ;;
esac

if [[ "$(findmnt -no FSTYPE /sys/fs/cgroup)" != cgroup2 ]]; then
  printf 'ERROR: unified cgroup v2 is not effective.\n' >&2
  exit 1
fi
if [[ "$(rootless_podman info --format '{{.Host.OCIRuntime.Name}}')" != crun ]]; then
  printf 'ERROR: rootless Podman does not select crun.\n' >&2
  exit 1
fi
if [[ "$(rootless_podman info --format '{{.Host.NetworkBackend}}')" != netavark ]]; then
  printf 'ERROR: rootless Podman does not select Netavark.\n' >&2
  exit 1
fi
runtime_status="$(run_as_service_account cat /proc/self/status)"
runtime_ids="$(effective_process_ids <(printf '%s\n' "$runtime_status"))"
IFS=: read -r runtime_uid runtime_gid <<<"$runtime_ids"
podman_rootless="$(rootless_podman info --format '{{.Host.Security.Rootless}}')"
if ! runtime_identity_admitted \
  "$podman_rootless" "$runtime_uid" "$runtime_gid" "$service_uid" "$service_gid"; then
  printf 'ERROR: effective Podman runtime is not the admitted rootless service identity.\n' >&2
  exit 1
fi
if ! rootless_podman image exists "$image"; then
  printf 'ERROR: digest-only fixture image is not pre-staged for the service account.\n' >&2
  exit 1
fi

fixture_root="$(mktemp -d /var/tmp/secpal-host-qualification-XXXXXX)"
chmod 0755 "$fixture_root"
fixture_id="${fixture_root##*-}"
container_a="${UNIT_PREFIX}-${fixture_id}-a"
container_b="${UNIT_PREFIX}-${fixture_id}-b"
unit_name="${UNIT_PREFIX}-${fixture_id}"
unit_path="${quadlet_root}/${unit_name}.container"
qualification_success_marker="${fixture_root}/qualification.success"
install_cleanup_traps

readonly quadlet_parent="${quadlet_root%/*}"
if ! administrator_path_admitted "$quadlet_parent" / 0 0 directory 755 ||
  ! service_account_cannot_write_path "$quadlet_parent" /; then
  printf 'ERROR: administrator Quadlet path ancestry is not trusted.\n' >&2
  exit 1
fi
if [[ -e "$quadlet_root" || -L "$quadlet_root" ]]; then
  if ! administrator_path_admitted "$quadlet_root" / 0 0 directory 755 ||
    ! service_account_cannot_write_path "$quadlet_root" /; then
    printf 'ERROR: administrator Quadlet path ancestry is not trusted.\n' >&2
    exit 1
  fi
fi
install -d -o 0 -g 0 -m 0755 "$quadlet_root"
if ! administrator_path_admitted "$quadlet_root" / 0 0 directory 755 ||
  ! service_account_cannot_write_path "$quadlet_root" /; then
  printf 'ERROR: administrator Quadlet path ancestry is not trusted.\n' >&2
  exit 1
fi

install -o 0 -g 0 -m 0644 /dev/null "$unit_path"
printf '%s\n' \
  '[Unit]' \
  'Description=SecPal bounded Rocky host qualification fixture' \
  '[Container]' \
  "Image=${image}" \
  "ContainerName=${unit_name}" \
  'Pull=never' \
  "User=${WORKLOAD_UID}:${WORKLOAD_GID}" \
  'DropCapability=all' \
  'Network=none' \
  'Exec=sleep infinity' \
  'PodmanArgs=--security-opt=no-new-privileges' \
  '[Service]' \
  'TimeoutStopSec=15' \
  >"$unit_path"
chmod 0644 "$unit_path"

if ! administrator_path_admitted "$unit_path" / 0 0 file 644 ||
  ! service_account_cannot_write_path "$unit_path" /; then
  printf 'ERROR: administrator Quadlet path ancestry is not trusted.\n' >&2
  exit 1
fi
if ! administrator_path_admitted "$quadlet_search_policy" / 0 0 file 644 ||
  ! service_account_cannot_write_path "$quadlet_search_policy" /; then
  printf 'ERROR: administrator Quadlet search-path policy is not trusted.\n' >&2
  exit 1
fi
effective_quadlet_dirs="$(
  user_systemctl show-environment |
    awk -F= '$1 == "QUADLET_UNIT_DIRS" { count++; value = substr($0, index($0, "=") + 1) } END { if (count != 1) exit 1; print value }'
)"
if [[ "$effective_quadlet_dirs" != "$quadlet_root" ]]; then
  printf 'ERROR: effective Quadlet search path is not the admitted administrator directory.\n' >&2
  exit 1
fi
if grep -En 'AutoUpdate=|Network=host|label=disable|Privileged=true' "$unit_path"; then
  printf 'ERROR: unsafe Quadlet setting detected.\n' >&2
  exit 1
fi
user_systemctl daemon-reload
unit_properties="${fixture_root}/quadlet-service.properties"
quadlet_authority_evidence="${fixture_root}/quadlet-authority.json"
if ! user_systemctl show "${unit_name}.service" \
  --property=FragmentPath --property=SourcePath \
  --property=DropInPaths --property=ExecStart >"$unit_properties"; then
  printf 'ERROR: effective Quadlet service authority is unavailable.\n' >&2
  exit 1
fi
chmod 0600 "$unit_properties"
if ! effective_quadlet_service_admitted \
  "$unit_properties" \
  "/run/user/${service_uid}/systemd/generator/${unit_name}.service" \
  "$unit_path" "$quadlet_authority_evidence"; then
  printf 'ERROR: effective Quadlet service contradicts the admitted administrator configuration.\n' >&2
  exit 1
fi
user_systemctl start "${unit_name}.service"
user_systemctl is-active --quiet "${unit_name}.service"

unit_main_pid="$(user_systemctl show --property MainPID --value "${unit_name}.service")"
if ! [[ "$unit_main_pid" =~ ^[1-9][0-9]*$ && -r "/proc/${unit_main_pid}/status" ]]; then
  printf 'ERROR: effective Quadlet runtime identity is unavailable.\n' >&2
  exit 1
fi
unit_runtime_ids="$(effective_process_ids "/proc/${unit_main_pid}/status")"
IFS=: read -r unit_runtime_uid unit_runtime_gid <<<"$unit_runtime_ids"
if ! runtime_identity_admitted \
  true "$unit_runtime_uid" "$unit_runtime_gid" "$service_uid" "$service_gid"; then
  printf 'ERROR: effective Quadlet runtime identity contradicts the service account.\n' >&2
  exit 1
fi
workload_status="${fixture_root}/quadlet-workload.status"
# The single-quoted $1 is the awk field selector.
# shellcheck disable=SC2016
rootless_podman exec "$unit_name" awk \
  '$1 ~ /^(Uid:|Gid:|NoNewPrivs:|CapInh:|CapPrm:|CapEff:|CapBnd:|CapAmb:|Seccomp:)$/ { print }' \
  /proc/1/status >"$workload_status"
if [[ "$(stat -c %s -- "$workload_status")" -gt 1024 ]] ||
  ! least_authority_process_admitted \
    "$workload_status" "$WORKLOAD_UID" "$WORKLOAD_GID"; then
  printf 'ERROR: representative workload lacks the effective least-authority process state.\n' >&2
  exit 1
fi
seccomp_mode=2

state_a="${fixture_root}/state-a"
install -d -o "$service_uid" -g "$service_gid" -m 0777 "$state_a"

rootless_podman run --detach --name "$container_a" \
  --security-opt no-new-privileges --cap-drop all \
  --user "${WORKLOAD_UID}:${WORKLOAD_GID}" --network pasta \
  -v "${state_a}:/state:Z" "$image" sleep infinity >/dev/null
rootless_podman exec "$container_a" sh -ceu 'printf native-selinux > /state/marker; chmod 0666 /state/marker; cat /state/marker' >/dev/null
rootless_podman run --detach --name "$container_b" \
  --security-opt no-new-privileges --cap-drop all \
  --user "${WORKLOAD_UID}:${WORKLOAD_GID}" --network pasta \
  -v "${state_a}:/foreign:ro" "$image" sleep infinity >/dev/null

process_a="$(rootless_podman top "$container_a" label | tr -d '\000' | tail -n 1 | tr -d '[:space:]')"
process_b="$(rootless_podman top "$container_b" label | tr -d '\000' | tail -n 1 | tr -d '[:space:]')"
storage_a="$(stat --printf='%C' "$state_a")"
if [[ "$process_a" != *:container_t:* || "$process_b" != *:container_t:* || "$storage_a" != *:container_file_t:* ]]; then
  printf 'ERROR: representative process or storage label is not container-confined.\n' >&2
  exit 1
fi
audit_observation="${fixture_root}/audit-avc.txt"
isolation_document="${fixture_root}/selinux-isolation.json"
set +e
observe_denied_access
denial_status=$?
set -e
if [[ "$denial_status" -eq 2 ]]; then
  printf 'ERROR: cross-boundary denial observation is invalid.\n' >&2
  exit 1
fi
if [[ "$denial_status" -ne 0 ]]; then
  dontaudit_disabled=true
  if ! /usr/bin/timeout --signal=KILL 30s semodule -DB; then
    printf 'ERROR: unable to temporarily expose SELinux dontaudit denials.\n' >&2
    exit 1
  fi
  if [[ "$(getenforce)" != Enforcing ]]; then
    printf 'ERROR: SELinux stopped Enforcing while exposing dontaudit denials.\n' >&2
    exit 1
  fi
  set +e
  observe_denied_access
  denial_status=$?
  set -e
  if [[ "$denial_status" -ne 0 ]]; then
    printf 'ERROR: cross-boundary failure lacks one correlated enforcing SELinux AVC denial.\n' >&2
    exit 1
  fi
  if ! /usr/bin/timeout --signal=KILL 30s semodule -B; then
    printf 'ERROR: unable to restore SELinux dontaudit policy.\n' >&2
    exit 1
  fi
  dontaudit_disabled=false
  if [[ "$(getenforce)" != Enforcing ]]; then
    printf 'ERROR: SELinux is not Enforcing after restoring dontaudit policy.\n' >&2
    exit 1
  fi
fi

denial_pid="$(python3 - "$isolation_document" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
pid = document.get("denial", {}).get("pid")
if not isinstance(pid, int) or isinstance(pid, bool) or not 1 <= pid <= 2_147_483_647:
    raise SystemExit(1)
print(pid)
PY
)"
selinux_isolation_sha256="$(sha256sum "$isolation_document" | awk '{print $1}')"
if ! [[ "$selinux_isolation_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'ERROR: normalized SELinux isolation evidence is unavailable.\n' >&2
  exit 1
fi

printf 'seccomp_mode=%s\nprocess_a=%s\nprocess_b=%s\nstorage_a=%s\n' \
  "$seccomp_mode" "$process_a" "$process_b" "$storage_a"
printf 'denial_pid=%s\nselinux_isolation_sha256=%s\n' \
  "$denial_pid" "$selinux_isolation_sha256"
printf 'quadlet_authority_base64=%s\n' \
  "$(base64 --wrap=0 "$quadlet_authority_evidence")"

if rootless_podman inspect "$container_a" "$container_b" | grep -Eq 'label=disable|"Privileged": true|"NetworkMode": "host"'; then
  printf 'ERROR: effective runtime facts contain a forbidden security fallback.\n' >&2
  exit 1
fi

install -o 0 -g 0 -m 0600 /dev/null "$qualification_success_marker"
printf 'PASS: Rocky Linux %s target workload contract (%s); native admission requires trusted control.\n' \
  "$os_version" "$architecture"
rm -f -- "$qualification_success_marker"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
