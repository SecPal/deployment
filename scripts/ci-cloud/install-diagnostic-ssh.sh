#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

diagnostic_root=/var/lib/secpal-ci-diagnostic
diagnostic_selector="$diagnostic_root/selected"
diagnostic_key="$diagnostic_root/authorized-key"
diagnostic_command=/usr/local/sbin/secpal-ci-bootstrap-diagnostic
diagnostic_recovery_command=/usr/local/sbin/secpal-ci-recover-diagnostic-ssh
diagnostic_config=/etc/ssh/secpal-ci-diagnostic-sshd.conf
diagnostic_unit=secpal-ci-diagnostic-sshd
diagnostic_service="${diagnostic_unit}.service"
diagnostic_timer="${diagnostic_unit}.timer"
diagnostic_recovery_service=secpal-ci-diagnostic-ssh-recover.service
diagnostic_service_unit="/etc/systemd/system/$diagnostic_service"
diagnostic_timer_unit="/etc/systemd/system/$diagnostic_timer"
diagnostic_recovery_service_unit="/etc/systemd/system/$diagnostic_recovery_service"
diagnostic_user=secpal-ci-diagnostic
diagnostic_home="$diagnostic_root/home"
primary_ssh_config=/etc/ssh/sshd_config.d/00-secpal-ci.conf
active_operator_root=/var/lib/secpal-ci
active_operator_key="$active_operator_root/authorized-keys/secpal-ci"
completion_marker="$active_operator_root/host-setup-complete"
operator_ssh_gate_dir=/etc/systemd/system/ssh.service.d
operator_ssh_gate="$operator_ssh_gate_dir/secpal-ci-ready.conf"
key_tmp=""
command_tmp=""
recovery_command_tmp=""
config_tmp=""
service_tmp=""
timer_tmp=""
recovery_service_tmp=""
operator_gate_tmp=""
validated_context=false

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  [[ -z "$key_tmp" ]] || rm -f -- "$key_tmp"
  [[ -z "$command_tmp" ]] || rm -f -- "$command_tmp"
  [[ -z "$recovery_command_tmp" ]] || rm -f -- "$recovery_command_tmp"
  [[ -z "$config_tmp" ]] || rm -f -- "$config_tmp"
  [[ -z "$service_tmp" ]] || rm -f -- "$service_tmp"
  [[ -z "$timer_tmp" ]] || rm -f -- "$timer_tmp"
  [[ -z "$recovery_service_tmp" ]] || rm -f -- "$recovery_service_tmp"
  [[ -z "$operator_gate_tmp" ]] || rm -f -- "$operator_gate_tmp"
  if [[ "$status" -ne 0 && "$validated_context" == true ]]; then
    if ! start_diagnostic_fallback; then
      printf 'ERROR: unable to establish restricted diagnostic SSH after installer failure.\n' >&2
    fi
  fi
  exit "$status"
}

trap cleanup EXIT

is_ipv4() {
  local value="$1" octet
  local -a octets

  IFS=. read -r -a octets <<<"$value"
  [[ "${#octets[@]}" -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

validate_effective_sshd_config() {
  local accepted_algorithms context effective_config expected keyword
  local route_context local_ipv4

  route_context="$(ip -o -4 route get "$runner_ipv4")" || return 1
  [[ "$route_context" =~ (^|[[:space:]])src[[:space:]]+([^[:space:]]+) ]] ||
    return 1
  local_ipv4="${BASH_REMATCH[2]}"
  is_ipv4 "$local_ipv4" || return 1
  local -a contexts=(
    "user=secpal-ci,host=$runner_ipv4,addr=$runner_ipv4,laddr=$local_ipv4,lport=22"
    "user=root,host=$runner_ipv4,addr=$runner_ipv4,laddr=$local_ipv4,lport=22"
  )
  local -a expected_settings=(
    "allowusers secpal-ci"
    "authenticationmethods publickey"
    "authorizedkeyscommand none"
    "authorizedkeysfile /var/lib/secpal-ci/authorized-keys/%u"
    "authorizedprincipalscommand none"
    "authorizedprincipalsfile none"
    "chrootdirectory none"
    "disableforwarding yes"
    "forcecommand none"
    "kbdinteractiveauthentication no"
    "maxsessions 1"
    "pamservicename sshd"
    "passwordauthentication no"
    "permitrootlogin no"
    "permittty no"
    "permituserenvironment no"
    "permituserrc no"
    "pubkeyauthentication yes"
    "refuseconnection no"
    "revokedkeys none"
    "strictmodes yes"
    "trustedusercakeys none"
    "usedns no"
    "usepam yes"
  )

  sshd -t || return 1
  for context in "${contexts[@]}"; do
    effective_config="$(sshd -T -C "$context")" || return 1
    for expected in "${expected_settings[@]}"; do
      keyword="${expected%% *}"
      [[ "$(grep -Ec "^${keyword} " <<<"$effective_config")" -eq 1 ]] ||
        return 1
      grep -Fqx -- "$expected" <<<"$effective_config" || return 1
    done
    ! grep -Eq '^(denyusers|denygroups|allowgroups|setenv) ' \
      <<<"$effective_config" || return 1
    [[ "$(grep -Ec '^pubkeyacceptedalgorithms ' \
      <<<"$effective_config")" -eq 1 ]] || return 1
    accepted_algorithms="$(
      grep -E '^pubkeyacceptedalgorithms ' <<<"$effective_config"
    )"
    accepted_algorithms="${accepted_algorithms#pubkeyacceptedalgorithms }"
    [[ ",$accepted_algorithms," == *,ssh-ed25519,* ]] || return 1
  done
}

validate_operator_identity() {
  local group_entry group_gid group_members group_name password_marker
  local shadow_entry shadow_name user_entry user_gid user_home user_name
  local user_shell user_uid

  user_entry="$(getent passwd secpal-ci)" || return 1
  group_entry="$(getent group secpal-ci)" || return 1
  shadow_entry="$(getent shadow secpal-ci)" || return 1
  IFS=: read -r user_name _ user_uid user_gid _ user_home user_shell \
    <<<"$user_entry"
  IFS=: read -r group_name _ group_gid group_members <<<"$group_entry"
  IFS=: read -r shadow_name password_marker _ <<<"$shadow_entry"
  [[ "$user_name" == secpal-ci && "$group_name" == secpal-ci &&
    "$shadow_name" == secpal-ci && "$user_uid" == 20000 &&
    "$user_gid" == 20000 && "$group_gid" == 20000 &&
    "$user_home" == /home/secpal-ci && "$user_shell" == /bin/bash &&
    -z "$group_members" && "$password_marker" == '*NP*' ]] || return 1
  [[ "$(id -G secpal-ci)" == 20000 ]]
}

completed_setup_is_valid() {
  local config_metadata root_metadata directory_metadata gate_metadata key_metadata
  local marker_metadata ssh_service_state ssh_socket_state

  [[ -f "$primary_ssh_config" && ! -L "$primary_ssh_config" &&
    -d "$active_operator_root" && ! -L "$active_operator_root" &&
    -d "$active_operator_root/authorized-keys" &&
    ! -L "$active_operator_root/authorized-keys" &&
    -f "$active_operator_key" && ! -L "$active_operator_key" &&
    -f "$completion_marker" && ! -L "$completion_marker" &&
    ! -e "$diagnostic_selector" && ! -L "$diagnostic_selector" &&
    -f "$operator_ssh_gate" && ! -L "$operator_ssh_gate" ]] || return 1
  config_metadata="$(stat -c '%u:%g:%a' -- "$primary_ssh_config")" || return 1
  root_metadata="$(stat -c '%u:%g:%a' -- "$active_operator_root")" || return 1
  directory_metadata="$(
    stat -c '%u:%g:%a' -- "$active_operator_root/authorized-keys"
  )" || return 1
  key_metadata="$(stat -c '%u:%g:%a' -- "$active_operator_key")" || return 1
  marker_metadata="$(stat -c '%u:%g:%a' -- "$completion_marker")" || return 1
  gate_metadata="$(stat -c '%u:%g:%a' -- "$operator_ssh_gate")" || return 1
  [[ "$config_metadata" == 0:0:644 && "$root_metadata" == 0:0:755 &&
    "$directory_metadata" == 0:0:755 &&
    "$key_metadata" == 0:0:644 && "$marker_metadata" == 0:0:400 &&
    "$gate_metadata" == 0:0:644 ]] || return 1
  [[ "$(wc -l <"$completion_marker")" -eq 1 ]] || return 1
  grep -Fqx 'SECPAL_CI_HOST_SETUP_COMPLETE' "$completion_marker" || return 1
  [[ "$(wc -l <"$operator_ssh_gate")" -eq 2 ]] || return 1
  grep -Fqx '[Unit]' "$operator_ssh_gate" || return 1
  grep -Fqx "ConditionPathExists=!$diagnostic_selector" \
    "$operator_ssh_gate" || return 1
  printf '%s\n' "$ssh_public_key" |
    cmp -s -- - "$active_operator_key" || return 1
  ssh-keygen -l -E sha256 -f "$active_operator_key" >/dev/null || return 1
  validate_operator_identity || return 1
  validate_effective_sshd_config || return 1
  ssh_service_state="$(systemctl is-enabled ssh.service 2>/dev/null || true)"
  ssh_socket_state="$(systemctl is-enabled ssh.socket 2>/dev/null || true)"
  [[ "$ssh_service_state" == enabled && "$ssh_socket_state" == disabled ]] ||
    return 1
}

operator_ssh_boot_gate_is_valid() {
  local gate_metadata

  [[ -f "$operator_ssh_gate" && ! -L "$operator_ssh_gate" ]] || return 1
  gate_metadata="$(stat -c '%u:%g:%a' -- "$operator_ssh_gate")" || return 1
  [[ "$gate_metadata" == 0:0:644 &&
    "$(wc -l <"$operator_ssh_gate")" -eq 2 ]] || return 1
  grep -Fqx '[Unit]' "$operator_ssh_gate" || return 1
  grep -Fqx "ConditionPathExists=!$diagnostic_selector" \
    "$operator_ssh_gate"
}

prepare_operator_ssh_boot_gate() {
  local gate_dir_metadata

  if [[ -e "$operator_ssh_gate_dir" || -L "$operator_ssh_gate_dir" ]]; then
    [[ -d "$operator_ssh_gate_dir" && ! -L "$operator_ssh_gate_dir" ]] ||
      return 1
    gate_dir_metadata="$(stat -c '%u:%g:%a' -- "$operator_ssh_gate_dir")" ||
      return 1
    [[ "$gate_dir_metadata" == 0:0:755 ]] || return 1
  else
    install -d -o root -g root -m 0755 "$operator_ssh_gate_dir" || return 1
  fi
  if [[ -e "$operator_ssh_gate" || -L "$operator_ssh_gate" ]]; then
    operator_ssh_boot_gate_is_valid
    return
  fi
  operator_gate_tmp="$(
    mktemp "$operator_ssh_gate_dir/.secpal-ci-ready.XXXXXX"
  )" || return 1
  if ! chmod 0644 "$operator_gate_tmp" ||
    ! printf '[Unit]\nConditionPathExists=!%s\n' \
      "$diagnostic_selector" >"$operator_gate_tmp" ||
    ! mv -T -- "$operator_gate_tmp" "$operator_ssh_gate"; then
    return 1
  fi
  operator_gate_tmp=""
  operator_ssh_boot_gate_is_valid
}

select_diagnostic_ssh() {
  local selector_metadata selector_tmp=""

  [[ -d "$diagnostic_root" && ! -L "$diagnostic_root" ]] || return 1
  [[ "$(stat -c '%u:%g:%a' -- "$diagnostic_root")" == 0:0:755 ]] || return 1
  if [[ -e "$diagnostic_selector" || -L "$diagnostic_selector" ]]; then
    [[ -f "$diagnostic_selector" && ! -L "$diagnostic_selector" ]] || return 1
  else
    selector_tmp="$(mktemp "$diagnostic_root/.selected.XXXXXX")" || return 1
    if ! chmod 0600 "$selector_tmp" ||
      ! printf 'SECPAL_CI_DIAGNOSTIC_SSH_SELECTED\n' >"$selector_tmp" ||
      ! mv -T -- "$selector_tmp" "$diagnostic_selector"; then
      rm -f -- "$selector_tmp"
      return 1
    fi
  fi
  selector_metadata="$(stat -c '%u:%g:%a' -- "$diagnostic_selector")" ||
    return 1
  [[ "$selector_metadata" == 0:0:600 &&
    "$(wc -l <"$diagnostic_selector")" -eq 1 ]] || return 1
  grep -Fqx 'SECPAL_CI_DIAGNOSTIC_SSH_SELECTED' "$diagnostic_selector"
}

ensure_diagnostic_identity() {
  local group_entry group_gid password_marker shadow_entry shadow_name
  local user_entry user_gid user_home user_shell

  install -d -o root -g root -m 0755 "$diagnostic_home" || return 1
  group_entry="$(getent group "$diagnostic_user" || true)"
  user_entry="$(getent passwd "$diagnostic_user" || true)"
  if [[ -z "$group_entry" ]]; then
    [[ -z "$user_entry" ]] || return 1
    groupadd --system "$diagnostic_user" || return 1
    group_entry="$(getent group "$diagnostic_user")" || return 1
  fi
  IFS=: read -r _ _ group_gid _ <<<"$group_entry"
  [[ "$group_gid" =~ ^[1-9][0-9]*$ ]] || return 1
  if [[ -z "$user_entry" ]]; then
    useradd --system --gid "$diagnostic_user" --no-create-home \
      --home-dir "$diagnostic_home" --shell /bin/sh "$diagnostic_user" || return 1
    user_entry="$(getent passwd "$diagnostic_user")" || return 1
  fi
  IFS=: read -r _ _ _ user_gid _ user_home user_shell <<<"$user_entry"
  [[ "$user_gid" == "$group_gid" && "$user_home" == "$diagnostic_home" &&
    "$user_shell" == /bin/sh ]] || return 1
  [[ "$(id -G "$diagnostic_user")" == "$group_gid" ]] || return 1
  # OpenSSH's portable account check can reject a leading "!" lock before
  # public-key authentication, while PAM stacks may differ. *NP* remains an
  # impossible password without making the restricted identity inaccessible.
  usermod --password '*NP*' "$diagnostic_user" || return 1
  shadow_entry="$(getent shadow "$diagnostic_user")" || return 1
  IFS=: read -r shadow_name password_marker _ <<<"$shadow_entry"
  [[ "$shadow_name" == "$diagnostic_user" ]] || return 1
  [[ "$password_marker" == '*NP*' ]] || return 1
}

prepare_diagnostic_fallback() {
  local diagnostic_command_metadata diagnostic_config_metadata
  local diagnostic_key_metadata diagnostic_recovery_command_metadata
  local diagnostic_recovery_service_unit_metadata diagnostic_root_metadata
  local diagnostic_service_unit_metadata diagnostic_timer_unit_metadata

  install -d -o root -g root -m 0755 /run/sshd /etc/ssh \
    /etc/systemd/system /usr/local/sbin || return 1
  if [[ -e "$diagnostic_root" || -L "$diagnostic_root" ]]; then
    [[ -d "$diagnostic_root" && ! -L "$diagnostic_root" ]] || return 1
    [[ "$(stat -c '%u:%g:%a' -- "$diagnostic_root")" == 0:0:755 ]] || return 1
  else
    install -d -o root -g root -m 0755 "$diagnostic_root" || return 1
  fi
  ensure_diagnostic_identity || return 1

  key_tmp="$(mktemp "$diagnostic_root/.authorized-key.XXXXXX")" || return 1
  command_tmp="$(mktemp /usr/local/sbin/.secpal-ci-bootstrap-diagnostic.XXXXXX)" || return 1
  recovery_command_tmp="$(mktemp /usr/local/sbin/.secpal-ci-recover-diagnostic.XXXXXX)" || return 1
  config_tmp="$(mktemp /etc/ssh/.secpal-ci-diagnostic-sshd.XXXXXX)" || return 1
  service_tmp="$(mktemp /etc/systemd/system/.secpal-ci-diagnostic-service.XXXXXX)" || return 1
  timer_tmp="$(mktemp /etc/systemd/system/.secpal-ci-diagnostic-timer.XXXXXX)" || return 1
  recovery_service_tmp="$(mktemp /etc/systemd/system/.secpal-ci-diagnostic-recovery.XXXXXX)" || return 1
  chmod 0600 "$key_tmp" "$config_tmp" "$service_tmp" "$timer_tmp" \
    "$recovery_service_tmp" || return 1
  chmod 0700 "$command_tmp" "$recovery_command_tmp" || return 1

  printf '%s\n' "$ssh_public_key" >"$key_tmp" || return 1
  ssh-keygen -l -E sha256 -f "$key_tmp" >/dev/null || return 1
  printf 'restrict,command="%s" %s\n' \
    "$diagnostic_command" "$ssh_public_key" >"$key_tmp" || return 1

  cat >"$command_tmp" <<'DIAGNOSTIC'
#!/usr/bin/env bash
set -euo pipefail

printf 'SECPAL_CI_DIAGNOSTIC_SSH\n'
set +e
setup_failure="$(
  /usr/local/sbin/secpal-ci-host-setup-failure read 2>/dev/null
)"
setup_failure_status=$?
if [[ "$setup_failure_status" -eq 0 && -n "$setup_failure" ]]; then
  printf 'SECPAL_CI_HOST_SETUP_FAILURE %s\n' "$setup_failure"
fi
exit 125
DIAGNOSTIC

  cat >"$recovery_command_tmp" <<'RECOVERY'
#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

diagnostic_root=/var/lib/secpal-ci-diagnostic
diagnostic_selector="$diagnostic_root/selected"
completion_marker=/var/lib/secpal-ci/host-setup-complete
selector_tmp=""

cleanup() {
  local status=$?
  trap - EXIT
  [[ -z "$selector_tmp" ]] || rm -f -- "$selector_tmp"
  exit "$status"
}
trap cleanup EXIT

[[ ! -e "$completion_marker" && ! -L "$completion_marker" ]]
[[ -d "$diagnostic_root" && ! -L "$diagnostic_root" ]]
[[ "$(stat -c '%u:%g:%a' -- "$diagnostic_root")" == 0:0:755 ]]
if [[ -e "$diagnostic_selector" || -L "$diagnostic_selector" ]]; then
  [[ -f "$diagnostic_selector" && ! -L "$diagnostic_selector" ]]
else
  selector_tmp="$(mktemp "$diagnostic_root/.selected.XXXXXX")"
  chmod 0600 "$selector_tmp"
  printf 'SECPAL_CI_DIAGNOSTIC_SSH_SELECTED\n' >"$selector_tmp"
  mv -T -- "$selector_tmp" "$diagnostic_selector"
  selector_tmp=""
fi
[[ "$(stat -c '%u:%g:%a' -- "$diagnostic_selector")" == 0:0:600 ]]
[[ "$(wc -l <"$diagnostic_selector")" -eq 1 ]]
grep -Fqx 'SECPAL_CI_DIAGNOSTIC_SSH_SELECTED' "$diagnostic_selector"
systemctl mask --now ssh.service ssh.socket >/dev/null 2>&1
systemctl restart secpal-ci-diagnostic-sshd.service
systemctl is-active --quiet secpal-ci-diagnostic-sshd.service
RECOVERY

  cat >"$config_tmp" <<EOF
Port 22
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/secpal-ci-diagnostic-sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxSessions 1
PAMServiceName sshd
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
PubkeyAcceptedAlgorithms ssh-ed25519
AuthorizedKeysCommand none
AuthorizedKeysFile $diagnostic_key
AuthorizedPrincipalsCommand none
AuthorizedPrincipalsFile none
TrustedUserCAKeys none
RevokedKeys none
RefuseConnection no
StrictModes yes
UseDNS no
UsePAM yes
AllowUsers secpal-ci-diagnostic@$runner_ipv4
ForceCommand /usr/local/sbin/secpal-ci-bootstrap-diagnostic
DisableForwarding yes
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
EOF

  cat >"$service_tmp" <<EOF
[Unit]
Description=SecPal restricted bootstrap diagnostic SSH
ConditionPathExists=/var/lib/secpal-ci-diagnostic/selected
Wants=network-online.target
After=network-online.target
Before=secpal-ci-bootstrap-continue.service
StartLimitIntervalSec=2m
StartLimitBurst=5

[Service]
Type=notify
ExecStart=/usr/sbin/sshd -D -e -f $diagnostic_config
Restart=on-failure
RestartSec=5s
RuntimeDirectory=sshd secpal-ci-evidence
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes

[Install]
WantedBy=multi-user.target
EOF
  cat >"$recovery_service_tmp" <<EOF
[Unit]
Description=Restore SecPal restricted bootstrap diagnostic SSH
ConditionPathExists=!/var/lib/secpal-ci/host-setup-complete
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$diagnostic_recovery_command
EOF
  cat >"$timer_tmp" <<EOF
[Unit]
Description=Delay SecPal restricted bootstrap diagnostic SSH

[Timer]
OnActiveSec=10m
AccuracySec=1s
Unit=secpal-ci-diagnostic-ssh-recover.service
EOF

  ssh-keygen -A || return 1
  sshd -t -f "$config_tmp" || return 1
  mv -T -- "$key_tmp" "$diagnostic_key" || return 1
  key_tmp=""
  mv -T -- "$command_tmp" "$diagnostic_command" || return 1
  command_tmp=""
  mv -T -- "$recovery_command_tmp" "$diagnostic_recovery_command" || return 1
  recovery_command_tmp=""
  mv -T -- "$config_tmp" "$diagnostic_config" || return 1
  config_tmp=""
  mv -T -- "$service_tmp" "$diagnostic_service_unit" || return 1
  service_tmp=""
  mv -T -- "$recovery_service_tmp" \
    "$diagnostic_recovery_service_unit" || return 1
  recovery_service_tmp=""
  mv -T -- "$timer_tmp" "$diagnostic_timer_unit" || return 1
  timer_tmp=""
  chmod 0644 "$diagnostic_key" || return 1
  chmod 0600 "$diagnostic_config" || return 1
  chmod 0755 "$diagnostic_command" "$diagnostic_recovery_command" || return 1
  chmod 0644 "$diagnostic_service_unit" "$diagnostic_timer_unit" \
    "$diagnostic_recovery_service_unit" || return 1
  [[ -f "$diagnostic_key" && ! -L "$diagnostic_key" &&
    -f "$diagnostic_config" && ! -L "$diagnostic_config" &&
    -f "$diagnostic_command" && ! -L "$diagnostic_command" &&
    -f "$diagnostic_recovery_command" && ! -L "$diagnostic_recovery_command" &&
    -f "$diagnostic_service_unit" && ! -L "$diagnostic_service_unit" &&
    -f "$diagnostic_recovery_service_unit" &&
    ! -L "$diagnostic_recovery_service_unit" &&
    -f "$diagnostic_timer_unit" && ! -L "$diagnostic_timer_unit" ]] || return 1
  diagnostic_key_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_key"
  )" || return 1
  diagnostic_config_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_config"
  )" || return 1
  diagnostic_command_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_command"
  )" || return 1
  diagnostic_recovery_command_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_recovery_command"
  )" || return 1
  diagnostic_service_unit_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_service_unit"
  )" || return 1
  diagnostic_timer_unit_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_timer_unit"
  )" || return 1
  diagnostic_recovery_service_unit_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_recovery_service_unit"
  )" || return 1
  diagnostic_root_metadata="$(
    stat -c '%u:%g:%a' -- "$diagnostic_root"
  )" || return 1
  [[ "$diagnostic_root_metadata" != 0:0:755 ||
    "$diagnostic_key_metadata" != 0:0:644 ||
    "$diagnostic_config_metadata" != 0:0:600 ||
    "$diagnostic_command_metadata" != 0:0:755 ||
    "$diagnostic_recovery_command_metadata" != 0:0:755 ||
    "$diagnostic_service_unit_metadata" != 0:0:644 ||
    "$diagnostic_timer_unit_metadata" != 0:0:644 ||
    "$diagnostic_recovery_service_unit_metadata" != 0:0:644 ]] && {
    printf 'ERROR: published diagnostic SSH artifacts have unsafe metadata.\n' >&2
    return 1
  }
  systemd-analyze verify "$diagnostic_service_unit" \
    "$diagnostic_timer_unit" "$diagnostic_recovery_service_unit" \
    >/dev/null || return 1
  prepare_operator_ssh_boot_gate || return 1
  systemctl daemon-reload || return 1
}

start_diagnostic_fallback() {
  prepare_diagnostic_fallback || return 1
  systemctl enable "$diagnostic_service" >/dev/null 2>&1 || return 1
  select_diagnostic_ssh || return 1
  systemctl mask --now ssh.service ssh.socket >/dev/null 2>&1 || return 1
  systemctl restart "$diagnostic_service" >/dev/null 2>&1 || return 1
  if systemctl is-active --quiet ssh.service ||
    systemctl is-active --quiet ssh.socket ||
    ! systemctl is-active --quiet "$diagnostic_service"; then
    return 1
  fi
  systemctl stop "$diagnostic_timer" || return 1
  ! systemctl is-active --quiet "$diagnostic_timer"
}

if [[ "$#" -ne 4 ]] || ! is_ipv4 "$2" ||
  [[ ! "$3" =~ ^[1-9][0-9]{0,19}$ ||
    ! "$4" =~ ^[1-9][0-9]{0,2}$ ]]; then
  printf 'ERROR: diagnostic SSH context is outside the closed format.\n' >&2
  exit 1
fi

ssh_public_key="$1"
runner_ipv4="$2"
read -r key_type key_data key_comment key_extra <<<"$ssh_public_key"
if [[ "$key_type" != ssh-ed25519 ||
  ! "$key_data" =~ ^[A-Za-z0-9+/]+={0,2}$ ||
  "$key_comment" != "secpal-ci-$3-$4" || -n "${key_extra:-}" ]]; then
  printf 'ERROR: diagnostic SSH key is outside the closed format.\n' >&2
  exit 1
fi
validated_context=true

if completed_setup_is_valid; then
  exit 0
fi
rm -f -- "$completion_marker" "$active_operator_key"

if ! start_diagnostic_fallback; then
  printf 'ERROR: unable to establish restricted diagnostic SSH during bootstrap.\n' >&2
  exit 1
fi
