#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Pure reviewed Rocky HAProxy supply admission, owned by deployment#219.

Official AppStream RPM bytes/signatures were checked independently on both
architectures. Matching a signed arm64 binary does not prove arm64 execution.
#80 owns the Rocky minor/repository/signature/update authority; this consumer
strengthens its package boundary with exact reviewed HAProxy payload identity.
"""

import hashlib
from types import MappingProxyType

VERSION = '3.0.5'
RELEASE = '6.el10_2.2'
SOURCE_RPM = f'haproxy-{VERSION}-{RELEASE}.src.rpm'
REQUIRED_FEATURES = frozenset({'+SYSTEMD', '+THREAD', '+OPENSSL', '+PCRE2'})
PACKAGES = MappingProxyType({
    'x86_64': MappingProxyType({
        'rpm_sha256': '8a6bb5f3afc88e3da5ce4c0631484ac44b3f33696953d2037c71ef49f41d02b4',
        'binary_sha256': '61b90cd8d83713880c11ee82c9e3d9ae73662ebdef1244695f63338df7dc05ed',
    }),
    'aarch64': MappingProxyType({
        'rpm_sha256': 'cd576d4eb6fcc4c35f2da916782e5f77be8d170a772195a770c78c76cd50dd05',
        'binary_sha256': '442e3802fa46248e75c3c402ba86a197f3313db4eed5f199173d2e3600179859',
    }),
})


def admit_installed_package(architecture: str, rpm_identity: str, binary_digest: str, features: frozenset[str]):
    if architecture not in PACKAGES:
        raise ValueError('admit-haproxy-architecture')
    if rpm_identity != f'haproxy|0|{VERSION}|{RELEASE}|{architecture}':
        raise ValueError('admit-haproxy-reviewed-rpm')
    if binary_digest != PACKAGES[architecture]['binary_sha256']:
        raise ValueError('admit-haproxy-reviewed-binary')
    if not isinstance(features, frozenset) or not REQUIRED_FEATURES <= features:
        raise ValueError('admit-haproxy-required-features')


def normalize_features(output: str) -> frozenset[str]:
    if not isinstance(output, str) or len(output) > 65536:
        raise ValueError('normalize-haproxy-build-size')
    lines = [line for line in output.splitlines() if line.startswith('Feature list : ')]
    if len(lines) != 1:
        raise ValueError('normalize-haproxy-build-features')
    tokens = lines[0].removeprefix('Feature list : ').split()
    if (len(tokens) > 128 or len(set(tokens)) != len(tokens)
            or any(len(token) > 64 or token[:1] not in {'+', '-'} for token in tokens)):
        raise ValueError('normalize-haproxy-build-features')
    return frozenset(tokens)


def binary_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
