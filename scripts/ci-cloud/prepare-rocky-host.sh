#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

readonly expected_os_id=rocky
readonly expected_version='VERSION_ID=10.2'
readonly expected_architecture=aarch64
readonly runtime_account=secpal-runtime
readonly fixture='docker.io/library/alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1'
readonly arm_child='sha256:4562b419adf48c5f3c763995d6014c123b3ce1d2e0ef2613b189779caa787192'
readonly state_root=/var/lib/secpal-rocky

if [[ "$#" -ne 7 ]]; then
  printf 'usage: prepare-rocky-host.sh TARGET_SHA CONTROL_SHA RUN_ID RUN_ATTEMPT EXPIRES_AT IMAGE_SELF_LINK EVIDENCE_OUTPUT\n' >&2
  exit 64
fi
readonly target_sha="$1"
readonly control_sha="$2"
readonly run_id="$3"
readonly run_attempt="$4"
readonly expires_at="$5"
readonly image_self_link="$6"
readonly evidence_output="$7"
readonly failure_output="$state_root/evidence/preparation-failure.json"
[[ "$target_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$control_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$run_id" =~ ^[1-9][0-9]{0,19}$ ]]
[[ "$run_attempt" =~ ^[1-9][0-9]{0,2}$ ]]
[[ "$evidence_output" == "$state_root/evidence/preparation.json" ]]
current_phase="guest-identity"
reboot_requested=false

read_release_value() {
  local key="$1"
  awk -F= -v wanted="$key" '$1 == wanted {value=substr($0,index($0,"=")+1); gsub(/^"|"$/, "", value); print value; exit}' /etc/os-release
}

safe_guest_fact() {
  local value="$1"
  if [[ "$value" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
    printf '%s' "$value"
  else
    printf '%s' unavailable
  fi
}

write_failure_evidence() {
  local status="$1" temporary guest_id guest_version guest_architecture
  set +e
  trap - EXIT
  [[ "$status" =~ ^[1-9][0-9]{0,2}$ ]] || status=1
  case "$current_phase" in
    guest-identity|repositories|packages|selinux|runtime-account|subids|systemd-user|quadlet-authority|fixture|pre-reboot|post-reboot-identity|post-reboot-selinux|cloud-identity|evidence-collection|evidence-validation) ;;
    *) current_phase=evidence-collection ;;
  esac
  guest_id="$(safe_guest_fact "$(read_release_value ID 2>/dev/null || true)")"
  guest_version="$(safe_guest_fact "$(read_release_value VERSION_ID 2>/dev/null || true)")"
  guest_architecture="$(safe_guest_fact "$(uname -m 2>/dev/null || true)")"
  install -d -o root -g secpal-cloud -m 0710 "$state_root" || return 0
  install -d -o root -g secpal-cloud -m 0750 "$state_root/evidence" || return 0
  if [[ "$evidence_output" == "$state_root/evidence/preparation.json" ]]; then
    rm -f -- "$evidence_output"
  fi
  temporary="$(mktemp "$state_root/evidence/.preparation-failure.XXXXXX")" || return 0
  chown root:root "$temporary" || { rm -f -- "$temporary"; return 0; }
  chmod 0600 "$temporary" || { rm -f -- "$temporary"; return 0; }
  printf '{"schema_version":1,"target_sha":"%s","trusted_control_sha":"%s","run_id":"%s","run_attempt":"%s","phase":"%s","exit_status":%s,"guest":{"id":"%s","version_id":"%s","uname_machine":"%s"}}\n' \
    "$target_sha" "$control_sha" "$run_id" "$run_attempt" "$current_phase" "$status" \
    "$guest_id" "$guest_version" "$guest_architecture" >"$temporary" || { rm -f -- "$temporary"; return 0; }
  [[ "$(wc -c <"$temporary")" -le 2048 ]] || { rm -f -- "$temporary"; return 0; }
  chown root:secpal-cloud "$temporary" && chmod 0440 "$temporary" && mv -T -- "$temporary" "$failure_output"
}

preparation_exit() {
  local status="$1"
  trap - EXIT
  if [[ "$status" -ne 0 && "$reboot_requested" != true ]]; then
    write_failure_evidence "$status"
  fi
  exit "$status"
}

trap 'preparation_exit "$?"' EXIT

prepare_evidence_transport() {
  install -d -o root -g secpal-cloud -m 0710 "$state_root"
  install -d -o root -g secpal-cloud -m 0750 "$state_root/evidence"
  [[ ! -L "$failure_output" ]]
  rm -f -- "$failure_output"
}

assert_guest_identity() {
  [[ "$(read_release_value ID)" == "$expected_os_id" ]]
  [[ "$(read_release_value VERSION_ID)" == "${expected_version#VERSION_ID=}" ]]
  [[ "$(uname -m)" == "$expected_architecture" ]]
}

run_as_runtime() {
  local uid home
  uid="$(id -u "$runtime_account")"
  home="$(getent passwd "$runtime_account" | awk -F: '{print $6}')"
  [[ "$home" == /* && -d "$home" ]]
  runuser --user "$runtime_account" -- env \
    HOME="$home" \
    XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    "$@"
}

block_metadata_credentials() {
  nft add table inet secpal_metadata 2>/dev/null || true
  nft 'add chain inet secpal_metadata output { type filter hook output priority -150; policy accept; }' 2>/dev/null || true
  if ! nft list chain inet secpal_metadata output | grep -Fq 'ip daddr 169.254.169.254 reject'; then
    nft add rule inet secpal_metadata output ip daddr 169.254.169.254 reject
  fi
}

configure_subids() {
  local start path temporary
  start="$(/usr/local/sbin/secpal-allocate-rocky-subids /etc/subuid /etc/subgid)"
  for path in /etc/subuid /etc/subgid; do
    temporary="$(mktemp --tmpdir=/etc ".${path##*/}.XXXXXX")"
    chmod 0600 "$temporary"
    awk -F: -v account="$runtime_account" '$1 != account' "$path" >"$temporary"
    printf '%s:%s:65536\n' "$runtime_account" "$start" >>"$temporary"
    chown root:root "$temporary"
    chmod 0644 "$temporary"
    mv -T -- "$temporary" "$path"
  done
}

install_policy() {
  current_phase="guest-identity"
  assert_guest_identity
  current_phase="repositories"
  mapfile -t enabled_repos < <(
    dnf4 --quiet repolist --enabled |
      awk 'NF && tolower($1) != "repo" {print $1}' |
      sort -u
  )
  if [[ "${enabled_repos[*]}" != 'appstream baseos extras' ]]; then
    printf 'ERROR: enabled repositories must be exactly baseos,appstream,extras.\n' >&2
    exit 1
  fi
  current_phase="packages"
  dnf4 --assumeyes --releasever=10 --disablerepo='*' \
    --enablerepo=baseos,appstream,extras install \
    podman conmon crun netavark aardvark-dns passt shadow-utils-subid systemd \
    container-selinux audit policycoreutils policycoreutils-python-utils \
    selinux-policy-targeted curl dnf git jq nftables openssh-server sudo \
    python3-jsonschema
  current_phase="guest-identity"
  assert_guest_identity
  current_phase="selinux"
  [[ "$(getenforce)" == Enforcing ]]
  sestatus | grep -Eq '^Loaded policy name:[[:space:]]+targeted$'

  systemctl disable --now dnf-automatic.timer dnf-automatic-install.timer \
    dnf-automatic-download.timer dnf-automatic-notifyonly.timer 2>/dev/null || true
  systemctl mask podman.socket podman.service

  current_phase="runtime-account"
  if ! getent passwd "$runtime_account" >/dev/null; then
    useradd --system --user-group --create-home \
      --shell /usr/sbin/nologin "$runtime_account"
  fi
  usermod --shell /usr/sbin/nologin "$runtime_account"
  [[ "$(id -Gn "$runtime_account")" == "$runtime_account" ]]
  current_phase="subids"
  configure_subids
  current_phase="systemd-user"
  loginctl enable-linger "$runtime_account"
  local runtime_uid
  runtime_uid="$(id -u "$runtime_account")"
  current_phase="quadlet-authority"
  install -d -o root -g root -m 0755 "/etc/containers/systemd/users/$runtime_uid"
  if run_as_runtime test -w "/etc/containers/systemd/users/$runtime_uid"; then
    printf 'ERROR: runtime account can write administrator Quadlet authority.\n' >&2
    exit 1
  fi
  systemctl start "user@$runtime_uid.service"
  run_as_runtime systemctl --user mask podman.socket podman.service
  current_phase="fixture"
  run_as_runtime podman pull "$fixture"
  run_as_runtime podman image exists "$fixture"
  resolved_child="$(run_as_runtime podman image inspect --format '{{.Digest}}' "$fixture")"
  [[ "$resolved_child" == "$arm_child" ]]

  cat >/etc/sudoers.d/secpal-cloud-rocky <<'SECPAL_CLOUD_SUDO'
secpal-cloud ALL=(root) NOPASSWD: /usr/local/sbin/secpal-run-rocky-target-qualification [0-9a-f]*
SECPAL_CLOUD_SUDO
  chown root:root /etc/sudoers.d/secpal-cloud-rocky
  chmod 0440 /etc/sudoers.d/secpal-cloud-rocky
  visudo --check --file=/etc/sudoers.d/secpal-cloud-rocky

  current_phase="pre-reboot"
  install -d -o root -g secpal-cloud -m 0710 "$state_root"
  cat /proc/sys/kernel/random/boot_id >"$state_root/first-boot-id"
  chmod 0600 "$state_root/first-boot-id"
  install -o root -g root -m 0600 /dev/null "$state_root/reboot-pending"
  if ! systemctl reboot; then
    return 1
  fi
  reboot_requested=true
  exit 0
}

collect_after_reboot() {
  current_phase="post-reboot-identity"
  assert_guest_identity
  current_phase="post-reboot-selinux"
  [[ "$(getenforce)" == Enforcing ]]
  [[ -f "$state_root/reboot-pending" ]]
  [[ "$(cat "$state_root/first-boot-id")" != "$(cat /proc/sys/kernel/random/boot_id)" ]]
  rm -f -- "$state_root/reboot-pending"

  # The target must not be able to reach any metadata credential endpoint.
  current_phase="cloud-identity"
  block_metadata_credentials
  if curl --noproxy '*' --fail --silent --max-time 2 \
    -H 'Metadata-Flavor: Google' \
    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
    >/dev/null 2>&1; then
    printf 'ERROR: metadata credentials remain reachable.\n' >&2
    exit 1
  fi
  [[ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]
  [[ -z "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]

  current_phase="evidence-collection"
  /usr/local/sbin/secpal-collect-rocky-preparation \
    --target-sha "$target_sha" \
    --control-sha "$control_sha" \
    --run-id "$run_id" \
    --run-attempt "$run_attempt" \
    --expires-at "$expires_at" \
    --image "$image_self_link" \
    --first-boot-id "$(cat "$state_root/first-boot-id")" \
    --output "$evidence_output"
  current_phase="evidence-validation"
  /opt/secpal-control/scripts/ci-cloud/rocky-control.py \
    validate-evidence preparation "$evidence_output"
  chown root:secpal-cloud "$evidence_output"
  chmod 0440 "$evidence_output"
  install -o root -g root -m 0600 /dev/null "$state_root/prepared"
}

prepare_evidence_transport
if [[ -e "$state_root/prepared" ]]; then
  current_phase="guest-identity"
  assert_guest_identity
  current_phase="cloud-identity"
  block_metadata_credentials
elif [[ -e "$state_root/reboot-pending" ]]; then
  collect_after_reboot
else
  install_policy
fi
