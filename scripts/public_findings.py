# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Public findings and notification delivery, without incident/action authority.

Source configuration and expected evidence/subject bindings come from the
consumer's authenticated producer channel, never from submitted JSON.
This is data admission, not a sandbox or an OS credential/privilege boundary.
"""
from dataclasses import dataclass
import hashlib
import json
import re

MAX_BYTES = 4096


def _code(value, pattern=r'[a-z][a-z0-9-]{0,63}'):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _digest(value):
    return _code(value, r'[0-9a-f]{64}')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


@dataclass(frozen=True)
class Source:
    """Reviewed producer vocabulary/freshness; not an incoming authority claim."""
    producer: str
    category: str
    capability: str
    codes: frozenset[tuple[str, str]]
    freshness_seconds: int

    def __post_init__(self):
        if (not _code(self.producer) or self.category not in
                ('health', 'security', 'update', 'conformance', 'integrity')
                or not _code(self.capability, r'[A-Za-z][A-Za-z0-9-]{0,63}')
                or type(self.freshness_seconds) is not int
                or not 1 <= self.freshness_seconds <= 31536000
                or type(self.codes) is not frozenset or not 1 <= len(self.codes) <= 128
                or any(type(pair) is not tuple or len(pair) != 2
                       or not _code(pair[0], r'[A-Z][A-Z0-9_-]{0,63}') or not _code(pair[1])
                       for pair in self.codes)):
            raise ValueError('finding-source-contract')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('finding-duplicate-field')
        result[key] = value
    return result


def accept(raw, *, source, subject_sha256, evidence_sha256, now):
    """Admit one bounded finding; return an immutable canonical JSON snapshot.

    Authenticating producer, subject and referenced evidence is the caller's
    responsibility. Matching submitted strings alone does not authenticate them.
    UNKNOWN may retain missing/stale observation time; known conditions may not.
    No health aggregation or producer-specific condition calculation lives here.
    """
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES
            or type(source) is not Source or not _digest(subject_sha256)
            or not _digest(evidence_sha256) or type(now) is not int or not 0 <= now < 2**63):
        raise ValueError('finding-input')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError('finding-json') from error
    if type(value) is not dict or set(value) != {
            'schema_version', 'producer', 'category', 'capability', 'subject_sha256',
            'evidence_sha256', 'condition', 'reason', 'observed_at'}:
        raise ValueError('finding-fields')
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['producer'] != source.producer or value['category'] != source.category
            or value['capability'] != source.capability or value['subject_sha256'] != subject_sha256
            or value['evidence_sha256'] != evidence_sha256
            or type(value['condition']) is not str or type(value['reason']) is not str
            or (value['condition'], value['reason']) not in source.codes):
        raise ValueError('finding-provenance-or-vocabulary')
    observed = value['observed_at']
    if observed is not None and (type(observed) is not int or not 0 <= observed <= now):
        raise ValueError('finding-observation-time')
    if value['condition'] != 'UNKNOWN' and (
            observed is None or now - observed > source.freshness_seconds):
        raise ValueError('finding-stale-observation')
    return _canonical(value)


def tls_finding(observation, *, subject_sha256, evidence_sha256, now):
    """Project #103's actual fact, without duplicating its health decisions.

    The evidence identity binds the canonical observation bytes. The caller
    independently authenticates collection and the opaque technical subject.
    """
    from viewer_tls_contract import health, OBSERVATION_FRESHNESS_SECONDS
    if hashlib.sha256(_canonical(observation)).hexdigest() != evidence_sha256:
        raise ValueError('finding-tls-evidence')
    fact = health(observation, now)
    source = Source(fact['producer'], 'health', fact['capability'],
                    frozenset({(fact['state'], fact['reason'])}), OBSERVATION_FRESHNESS_SECONDS)
    return accept(_canonical(dict(schema_version=1, producer=fact['producer'], category=source.category,
                  capability=fact['capability'], subject_sha256=subject_sha256,
                  evidence_sha256=evidence_sha256, condition=fact['state'], reason=fact['reason'],
                  observed_at=fact['observed_at'])),
                  source=source, subject_sha256=subject_sha256, evidence_sha256=evidence_sha256, now=now)


def notify(raw, *, source, subject_sha256, evidence_sha256, now, notification_id, send, silent=False):
    """One synchronous attempt, no broker, policy, incident state or auto-retry.

    The operator supplies a trusted delivery adapter out of band. Data cannot
    name a destination, executable, authority, or action. True acknowledges
    adapter delivery only, never human receipt, remediation or service health.
    """
    accepted = accept(raw, source=source, subject_sha256=subject_sha256,
                      evidence_sha256=evidence_sha256, now=now)
    if not _digest(notification_id) or type(silent) is not bool or not callable(send):
        raise ValueError('finding-notification-input')
    result = dict(schema_version=1, notification_id=notification_id,
                  finding_sha256=hashlib.sha256(accepted).hexdigest(), delivery='SILENCED')
    if not silent:
        # A detached immutable envelope prevents adapters from rewriting facts.
        envelope = _canonical(dict(schema_version=1, notification_id=notification_id,
                                   finding=json.loads(accepted)))
        try:
            result['delivery'] = 'DELIVERED' if send(envelope) is True else 'FAILED'
        except Exception:
            # No raw destination, exception text, credentials or transport logs.
            result['delivery'] = 'FAILED'
    return result


def stream_adapter(stream):
    """Representative Self-Hosted binary-stream adapter selected by the operator.

    Successful write + flush is local transport acknowledgment, not durability
    or receiver acknowledgment. Broken/partial writes propagate to notify().
    """
    def send(envelope):
        record = envelope + b'\n'
        if stream.write(record) != len(record):
            return False
        stream.flush()
        return True
    return send
