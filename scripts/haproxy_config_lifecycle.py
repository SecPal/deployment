#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Atomic reviewed candidate publication; no active partial-write pathname.

The privileged wrapper owns path/identity admission and serialization. Binary
validation precedes any replacement. HAProxy's master-worker reload retains old
workers on failure; rollback restores accepted disk bytes for the next start.
"""

import os
import hashlib
import json
from pathlib import Path
import stat
import tempfile

from haproxy_base_contract import MAX_CONFIG_BYTES


def sync_directory(directory: Path):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage(directory: Path, data: bytes, prepare, *, mode=0o444):
    descriptor, name = tempfile.mkstemp(prefix='.secpal-candidate-', dir=directory)
    candidate = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(candidate, mode)
        prepare(candidate)
        return candidate
    except BaseException:
        candidate.unlink(missing_ok=True)
        raise


def admit_publication_record(record):
    if (type(record) is not dict or set(record) != {'previous_sha256', 'candidate_sha256'}
            or any(value is not None and (type(value) is not str or len(value) != 64
                   or any(c not in '0123456789abcdef' for c in value)) for value in record.values())
            or record['candidate_sha256'] is None):
        raise ValueError('admit-publication-journal')
    return record


def recover_publication(serving: Path, journal: Path, prepare, recover):
    """#103 crash recovery under the same administrator-held publication lock.

    A pending generation is never replayed or treated as accepted. Restore the
    authenticated predecessor before one compensating shared-runtime reload.
    The wrapper admits fixed root-owned private paths before invoking this seam.
    """
    if not journal.exists():
        return False
    if journal.stat().st_size > 1024:
        raise ValueError('admit-publication-journal')
    record = admit_publication_record(json.loads(journal.read_bytes()))
    backup = journal.with_name(journal.name + '.pem')
    previous = record['previous_sha256']
    if previous is None:
        # An interrupted first installation has no accepted certificate.
        serving.unlink(missing_ok=True)
    else:
        if not backup.is_file() or backup.stat().st_size > MAX_CONFIG_BYTES:
            raise ValueError('admit-publication-predecessor')
        data = backup.read_bytes()
        if hashlib.sha256(data).hexdigest() != previous:
            raise ValueError('admit-publication-predecessor')
        candidate = stage(serving.parent, data, prepare, mode=0o600)
        os.replace(candidate, serving)
    sync_directory(serving.parent)
    recover()
    journal.unlink()
    sync_directory(journal.parent)
    backup.unlink(missing_ok=True)
    sync_directory(journal.parent)
    return True


def publish(serving: Path, data: bytes, validate, reload, prepare=lambda _: None, recover=lambda: None,
            *, mode=0o444, journal: Path | None = None, prepare_initial=False):
    """Reject invalid bytes before replacement; preserve LKG on reload failure.

    No configurable shell command or runtime API. Callbacks are reviewed code,
    never operator inputs. The installed wrapper holds a root-owned flock across
    this entire operation and requires regular immutable root-owned paths.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_CONFIG_BYTES:
        raise ValueError('admit-candidate-size')
    if mode not in (0o444, 0o600) or (journal is not None and mode != 0o600):
        raise ValueError('admit-publication-mode')
    if journal is not None and journal.exists():
        raise ValueError('recover-pending-publication-first')
    if prepare_initial and (journal is None or serving.exists()):
        raise ValueError('admit-first-certificate-preparation')
    previous = None
    if serving.exists() or serving.is_symlink():
        info = serving.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_CONFIG_BYTES:
            raise ValueError('admit-serving-file')
        previous = serving.read_bytes()
    candidate = stage(serving.parent, data, prepare, mode=mode)
    rollback = None
    try:
        validate(candidate)
        if previous == data:
            # Disk equality cannot authenticate an uncertain live generation.
            reload()
            return
        if previous is not None:
            rollback = stage(serving.parent, previous, prepare, mode=mode)
        if journal is not None:
            backup = journal.with_name(journal.name + '.pem')
            if previous is not None:
                saved = stage(journal.parent, previous, prepare, mode=mode)
                os.replace(saved, backup)
            record = json.dumps({'previous_sha256': hashlib.sha256(previous).hexdigest() if previous is not None else None,
                                 'candidate_sha256': hashlib.sha256(data).hexdigest()}, sort_keys=True).encode()
            saved = stage(journal.parent, record, lambda _: None, mode=mode)
            os.replace(saved, journal)
            sync_directory(journal.parent)
        os.replace(candidate, serving)
        try:
            sync_directory(serving.parent)
            if prepare_initial:
                # Only first-install construction may defer live activation.
                # Return pending, retain the durable journal, and never claim
                # issuance/activation success before an independent TLS probe.
                return False
            reload()
            if journal is not None:
                journal.unlink()
                sync_directory(journal.parent)
            return True
        except BaseException:
            if rollback is not None:
                os.replace(rollback, serving)
            else:
                serving.unlink(missing_ok=True)
            try:
                sync_directory(serving.parent)
            finally:
                # Even an uncertain directory sync must attempt bounded live
                # recovery from the restored bytes; never report success.
                try:
                    if journal is not None and not journal.exists():
                        # Journal removal is accepted only with directory fsync.
                        # A failed compensation must retain recovery authority,
                        # even when unlink succeeded before that sync failed.
                        saved = stage(journal.parent, record, lambda _: None, mode=mode)
                        os.replace(saved, journal)
                        sync_directory(journal.parent)
                finally:
                    recover()
            if journal is not None:
                journal.unlink(missing_ok=True)
                sync_directory(journal.parent)
            raise
    finally:
        candidate.unlink(missing_ok=True)
        if rollback is not None:
            rollback.unlink(missing_ok=True)
        if journal is not None and not journal.exists():
            journal.with_name(journal.name + '.pem').unlink(missing_ok=True)
