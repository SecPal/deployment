#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

readonly reviewed_key_package='gpg-pubkey-6fedfc85-682ae1a9'
readonly reviewed_key_packet_sha256='1f09530c1d1fdcbe03279b565e9b7ff1ec4d6fccd663ac2710d0b2f0119dbb7e'
readonly reviewed_key_fingerprint='fc226859c0860bf0ddb95b085b106c736fedfc85'
readonly verified_signature='Header V4 RSA/SHA256 Signature, key ID 6fedfc85: OK'
readonly verified_sha256='Header SHA256 digest: OK'
readonly verified_sha1='Header SHA1 digest: OK'

temporary_directory="$(mktemp -d)"
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

# shellcheck source=/dev/null
source /etc/os-release
[[ "$ID" == rocky && "$VERSION_ID" == 10.2 ]]
[[ "$(rpm --version)" == 'RPM version 4.19.1.1' ]]

dnf4 --quiet --disablerepo='*' \
  --enablerepo=baseos,appstream,extras \
  install -y dnf-plugins-core
[[ "$(dnf4 --version | head -n 1)" == 4.20.0 ]]

rpm -q --qf $'%{VERSION}\n%{PUBKEYS}\n' "$reviewed_key_package" \
  >"$temporary_directory/key"
[[ "$(head -n 1 "$temporary_directory/key")" == 6fedfc85 ]]
tail -n +2 "$temporary_directory/key" | tr -d '\n' | base64 --decode \
  >"$temporary_directory/key.packet"
[[ "$(sha256sum "$temporary_directory/key.packet" | cut -d ' ' -f 1)" == \
  "$reviewed_key_packet_sha256" ]]

verify_installed_header() {
  local package="$1"
  local expected_repository="$2"
  local nevra repositories
  local -a identity
  mapfile -t identity < <(
    rpm -q --qf $'%{NAME}\n%{EPOCHNUM}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n%{NEVRA}\n' \
      "$package"
  )
  [[ "${#identity[@]}" == 6 ]]
  [[ "${identity[0]}" == "$package" ]]
  nevra="${identity[5]}"
  repositories="$(dnf4 --quiet --disablerepo='*' \
    --enablerepo=baseos,appstream,extras \
    repoquery-nevra --qf '%{repoid}' "$nevra")"
  [[ "$repositories" == "$expected_repository" ]]

  rpm -qvv --qf $'%{NAME}\n%{EPOCHNUM}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n%{NEVRA}\n%{PAYLOADDIGEST}\n%{PAYLOADDIGESTALGO}\n%{SHA256HEADER}\n%{RSAHEADER:pgpsig}\n' \
    "$nevra" >"$temporary_directory/$package.header" \
    2>"$temporary_directory/$package.verification"
  mapfile -t header <"$temporary_directory/$package.header"
  [[ "${#header[@]}" == 10 ]]
  [[ "${header[0]}" == "$package" ]]
  [[ "${header[1]}" == "${identity[1]}" ]]
  [[ "${header[2]}" == "${identity[2]}" ]]
  [[ "${header[3]}" == "${identity[3]}" ]]
  [[ "${header[4]}" == "${identity[4]}" ]]
  [[ "${header[5]}" == "$nevra" ]]
  [[ "${header[6]}" =~ ^[0-9a-f]{64}$ ]]
  [[ "${header[7]}" == 8 ]]
  [[ "${header[8]}" =~ ^[0-9a-f]{64}$ ]]
  [[ "${header[9]}" =~ ^RSA/SHA256,.+Key\ ID\ [0-9a-f]{16}$ ]]
  grep -Fxq "$verified_signature" "$temporary_directory/$package.verification"
  grep -Fxq "$verified_sha256" "$temporary_directory/$package.verification"
  grep -Fxq "$verified_sha1" "$temporary_directory/$package.verification"

  python3 - "$package" "$nevra" "$repositories" \
    "$temporary_directory/$package.header" \
    "$temporary_directory/$package.verification" \
    "$temporary_directory/key" <<'PY'
import importlib.util
import pathlib
import sys

root = pathlib.Path("/workspace")
path = root / "scripts/ci-cloud/rocky_preparation_contract.py"
spec = importlib.util.spec_from_file_location("rocky_preparation_contract", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
package, nevra, repository, header, verification, key = sys.argv[1:]
identity = pathlib.Path(header).read_text().splitlines()[:6]
signer = module.admit_rocky_signing_key(
    module.normalize_rocky_signing_key(pathlib.Path(key).read_text())
)
fact = module.normalize_package(
    package,
    {
        "name": identity[0],
        "epoch": identity[1],
        "version": identity[2],
        "release": identity[3],
        "architecture": identity[4],
        "nevra": nevra,
        "repositories": [repository],
        "signed_header": pathlib.Path(header).read_text().strip(),
        "verification": pathlib.Path(verification).read_text().strip(),
    },
    identity[4] if identity[4] != "noarch" else "x86_64",
)
host_architecture = identity[4] if identity[4] != "noarch" else "x86_64"
admitted = module.admit_package(fact, signer, host_architecture)
assert admitted["nevra"] == nevra
assert admitted["name"] == package
assert admitted["architecture"] == identity[4]
assert admitted["resolved_repository"] == repository
assert admitted["signature_verified"] is True
if package == "podman":
    runtime = {"packages_admitted": [admitted]}
    module.admit_runtime_podman_version(runtime)
    assert runtime["podman_version_admitted"] == identity[2]
PY
}

# dnf is present in the immutable base image; Podman is installed by the
# reviewed transaction below. Both cross the identical RPMDB admission path.
verify_installed_header dnf baseos
dnf4 --quiet --disablerepo='*' \
  --enablerepo=baseos,appstream,extras install -y podman
mkdir -m 0700 "$temporary_directory/gnupg"
fingerprint="$(GNUPGHOME="$temporary_directory/gnupg" \
  gpg --batch --with-colons --show-keys "$temporary_directory/key.packet" |
  awk -F: '$1 == "fpr" { print tolower($10); exit }')"
[[ "$fingerprint" == "$reviewed_key_fingerprint" ]]
verify_installed_header podman appstream

nevra="$(rpm -q --qf '%{NEVRA}' bash)"

rpmdb="$(rpm --eval '%{_dbpath}')"
readonly rpmdb
cp -a -- "$rpmdb" "$temporary_directory/no-key"
rpm --dbpath "$temporary_directory/no-key" -e "$reviewed_key_package"
rpm --dbpath "$temporary_directory/no-key" -Vvv --nofiles --nodeps "$nevra" \
  >"$temporary_directory/no-key.stdout" 2>"$temporary_directory/no-key.stderr"
grep -Fq 'NOKEY' "$temporary_directory/no-key.stderr"
if grep -Fxq "$verified_signature" "$temporary_directory/no-key.stderr"; then
  echo 'missing-key RPMDB unexpectedly retained an admitted signature' >&2
  exit 1
fi

cp -a -- "$rpmdb" "$temporary_directory/tampered"
python3 - "$temporary_directory/tampered/rpmdb.sqlite" <<'PY'
import sqlite3
import sys

database = sqlite3.connect(sys.argv[1])
hnum = database.execute(
    "SELECT hnum FROM Name WHERE key = 'bash' ORDER BY hnum LIMIT 1"
).fetchone()[0]
blob = bytes(database.execute(
    "SELECT blob FROM Packages WHERE hnum = ?", (hnum,)
).fetchone()[0])
old = b"5.2.26"
new = b"5.2.27"
if old not in blob:
    raise SystemExit("unexpected RPMDB header representation")
database.execute(
    "UPDATE Packages SET blob = ? WHERE hnum = ?", (blob.replace(old, new, 1), hnum)
)
database.commit()
PY
if rpm --dbpath "$temporary_directory/tampered" -Vvv --nofiles --nodeps bash \
  >"$temporary_directory/tampered.stdout" 2>"$temporary_directory/tampered.stderr"; then
  echo 'tampered RPMDB header unexpectedly verified' >&2
  exit 1
fi
grep -Eq 'Signature.*BAD|digest: BAD' "$temporary_directory/tampered.stderr"

echo 'Rocky RPMDB provenance contract passed.'
