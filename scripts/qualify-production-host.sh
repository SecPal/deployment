#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly NOT_RUN=2
readonly QUALIFIED_ROCKY_MINOR="10.2"
readonly DEFAULT_ACCOUNT="secpal-deploy"
readonly UNIT_PREFIX="secpal-host-qualification"

image=""
service_account="$DEFAULT_ACCOUNT"
fixture_root=""
unit_path=""
container_a=""
container_b=""
unit_name=""
fcontext_expression=""
fcontext_added=false
dontaudit_disabled=false

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

matching_marker_avc() {
  local audit_date="$1"
  local audit_time="$2"
  LC_ALL=C ausearch -m AVC -ts "$audit_date" "$audit_time" -i | grep -Fq 'marker'
}

cleanup() {
  local exit_status=$?
  set +e
  if [[ "$dontaudit_disabled" == true ]]; then
    semodule -B >/dev/null 2>&1
    dontaudit_disabled=false
  fi
  if [[ -n "$unit_name" ]]; then
    user_systemctl stop "${unit_name}.service" >/dev/null 2>&1
  fi
  if [[ -n "$container_a" ]]; then
    rootless_podman rm --force "$container_a" >/dev/null 2>&1
  fi
  if [[ -n "$container_b" ]]; then
    rootless_podman rm --force "$container_b" >/dev/null 2>&1
  fi
  if [[ -n "$unit_path" && -f "$unit_path" ]]; then
    rm -- "$unit_path"
    user_systemctl daemon-reload >/dev/null 2>&1
  fi
  if [[ -n "$unit_name" ]]; then
    user_systemctl reset-failed "${unit_name}.service" >/dev/null 2>&1
  fi
  if [[ "$fcontext_added" == true ]]; then
    semanage fcontext --delete "$fcontext_expression" >/dev/null 2>&1
  fi
  if [[ -n "$fixture_root" && -d "$fixture_root" ]]; then
    rm -rf -- "$fixture_root"
  fi
  exit "$exit_status"
}

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
if ! run_as_service_account test -d "$service_home"; then
  printf 'ERROR: service-account home is not usable by %s: %s\n' "$service_account" "$service_home" >&2
  exit 1
fi
readonly quadlet_root="/etc/containers/systemd/users/${service_uid}"

if [[ "$(getenforce)" != Enforcing ]]; then
  printf 'ERROR: SELinux is not Enforcing.\n' >&2
  exit 1
fi

required_packages=(
  podman conmon crun netavark aardvark-dns passt shadow-utils-subid systemd
  container-selinux audit policycoreutils policycoreutils-python-utils selinux-policy-targeted
)
rpm -q --qf '%{NEVRA}\n' "${required_packages[@]}"

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
fcontext_expression="${fixture_root}(/.*)?"
trap cleanup EXIT HUP INT TERM

install -d -o 0 -g 0 -m 0755 "$quadlet_root"
if run_as_service_account test -w "$quadlet_root"; then
  printf 'ERROR: service account can write the administrator Quadlet directory.\n' >&2
  exit 1
fi
if [[ -L "$quadlet_root" || -L "$unit_path" ]]; then
  printf 'ERROR: unsafe Quadlet symlink detected.\n' >&2
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
  'User=65532:65532' \
  'DropCapability=all' \
  'Network=none' \
  'Exec=sleep infinity' \
  'PodmanArgs=--security-opt=no-new-privileges' \
  '[Service]' \
  'TimeoutStopSec=15' \
  >"$unit_path"
chmod 0644 "$unit_path"

if run_as_service_account test -w "$unit_path"; then
  printf 'ERROR: service account can write the administrator Quadlet definition.\n' >&2
  exit 1
fi
if grep -En 'AutoUpdate=|Network=host|label=disable|Privileged=true' "$unit_path"; then
  printf 'ERROR: unsafe Quadlet setting detected.\n' >&2
  exit 1
fi
user_systemctl daemon-reload
user_systemctl start "${unit_name}.service"
user_systemctl is-active --quiet "${unit_name}.service"

state_a="${fixture_root}/state-a"
state_b="${fixture_root}/state-b"
install -d -o "$service_uid" -g "$service_gid" -m 0777 "$state_a" "$state_b"
semanage fcontext --add --type container_file_t "$fcontext_expression"
fcontext_added=true
restorecon -RF "$fixture_root"
matchpathcon -V "$state_a"

rootless_podman run --detach --name "$container_a" \
  --security-opt no-new-privileges --cap-drop all \
  --user 65532:65532 --network pasta \
  -v "${state_a}:/state:Z" "$image" sleep infinity >/dev/null
rootless_podman exec "$container_a" sh -ceu 'printf native-selinux > /state/marker; chmod 0666 /state/marker; cat /state/marker' >/dev/null
seccomp_line="$(rootless_podman exec "$container_a" grep '^Seccomp:' /proc/1/status)"
seccomp_mode="$(printf '%s' "${seccomp_line#*:}" | tr -d '[:space:]')"
if [[ "$seccomp_mode" != 2 ]]; then
  printf 'ERROR: representative rootless workload is not effectively seccomp-confined.\n' >&2
  exit 1
fi

rootless_podman run --detach --name "$container_b" \
  --security-opt no-new-privileges --cap-drop all \
  --user 65532:65532 --network pasta \
  -v "${state_a}:/foreign:ro" "$image" sleep infinity >/dev/null

process_a="$(rootless_podman top "$container_a" label | tr -d '\000' | tail -n 1 | tr -d '[:space:]')"
process_b="$(rootless_podman top "$container_b" label | tr -d '\000' | tail -n 1 | tr -d '[:space:]')"
storage_a="$(stat --printf='%C' "$state_a")"
if [[ "$process_a" != *:container_t:* || "$process_b" != *:container_t:* || "$storage_a" != *:container_file_t:* ]]; then
  printf 'ERROR: representative process or storage label is not container-confined.\n' >&2
  exit 1
fi
process_a_mcs="${process_a#*:container_t:}"
process_b_mcs="${process_b#*:container_t:}"
storage_a_mcs="${storage_a#*:container_file_t:}"
if [[ "$process_a_mcs" != "$storage_a_mcs" || "$process_a_mcs" == "$process_b_mcs" ]]; then
  printf 'ERROR: representative SELinux MCS boundaries are not distinct and effective.\n' >&2
  exit 1
fi

printf 'seccomp_mode=%s\nprocess_a=%s\nprocess_b=%s\nstorage_a=%s\n' \
  "$seccomp_mode" "$process_a" "$process_b" "$storage_a"

read -r audit_date audit_time < <(LC_ALL=C date '+%x %T')
if rootless_podman exec "$container_b" cat /foreign/marker >/dev/null 2>&1; then
  printf 'ERROR: cross-boundary read unexpectedly succeeded.\n' >&2
  exit 1
fi
if [[ ! -e "${state_a}/marker" || ! -r "${state_a}/marker" ]]; then
  printf 'ERROR: negative test cannot distinguish missing path or DAC denial.\n' >&2
  exit 1
fi
if ! matching_marker_avc "$audit_date" "$audit_time"; then
  dontaudit_disabled=true
  if ! semodule -DB; then
    printf 'ERROR: unable to temporarily expose SELinux dontaudit denials.\n' >&2
    exit 1
  fi
  if [[ "$(getenforce)" != Enforcing ]]; then
    printf 'ERROR: SELinux stopped Enforcing while exposing dontaudit denials.\n' >&2
    exit 1
  fi
  read -r audit_date audit_time < <(LC_ALL=C date '+%x %T')
  if rootless_podman exec "$container_b" cat /foreign/marker >/dev/null 2>&1; then
    printf 'ERROR: cross-boundary read unexpectedly succeeded with dontaudit disabled.\n' >&2
    exit 1
  fi
  if [[ ! -e "${state_a}/marker" || ! -r "${state_a}/marker" ]]; then
    printf 'ERROR: repeated negative test cannot distinguish missing path or DAC denial.\n' >&2
    exit 1
  fi
  if ! matching_marker_avc "$audit_date" "$audit_time"; then
    printf 'ERROR: cross-boundary failure lacks a matching SELinux AVC denial.\n' >&2
    exit 1
  fi
  if ! semodule -B; then
    printf 'ERROR: unable to restore SELinux dontaudit policy.\n' >&2
    exit 1
  fi
  dontaudit_disabled=false
  if [[ "$(getenforce)" != Enforcing ]]; then
    printf 'ERROR: SELinux is not Enforcing after restoring dontaudit policy.\n' >&2
    exit 1
  fi
fi

if rootless_podman inspect "$container_a" "$container_b" | grep -Eq 'label=disable|"Privileged": true|"NetworkMode": "host"'; then
  printf 'ERROR: effective runtime facts contain a forbidden security fallback.\n' >&2
  exit 1
fi

printf 'PASS: Rocky Linux %s native rootless Podman/Quadlet/SELinux qualification (%s).\n' "$os_version" "$architecture"
