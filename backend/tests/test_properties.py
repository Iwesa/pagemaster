"""Property-based tests for Correctness Properties 1-5 (design.md).

No Postgres, Redis, or network access is required.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any
from uuid import UUID

from hypothesis import given, settings
from hypothesis import strategies as st

from backend.app.services.dedup import Acquired, Duplicate, InMemoryDedupStore, compute_fingerprint
from backend.app.services.guardrails import (
    GENESIS_HASH,
    PAGER_MAX_CHARS,
    AuditLogger,
    AuditRecord,
    ResolutionGates,
    TripwireValidator,
    can_resolve,
    compute_audit_hash,
    format_pager_payload,
    jsonb_text,
    parse_sms_reply,
    verify_chain,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

tokens = st.from_regex(r"[A-Z0-9]{2}", fullmatch=True)

_SENSITIVE_FRAGMENTS = [
    "ops@example.com",
    "a.b+c@sub.domain.org",
    "10.20.4.17",
    "192.168.0.1",
    "255.255.255.255",
    "::1",
    "2001:db8::8a2e:370:7334",
    "fe80::1ff:fe23:4567:890a",
    "Bearer eyJhbGciOiJIUzI1NiJ9.mock.sig",
    "bearer abc123",
    "BEARER",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
    "sk_" + "live_" + "FAKEFIXTUREKEY0000000000",
]

diagnosis_text = st.lists(
    st.one_of(st.text(max_size=120), st.sampled_from(_SENSITIVE_FRAGMENTS)),
    min_size=0,
    max_size=8,
).map(lambda parts: " ".join(parts))

service_names = st.one_of(
    st.sampled_from(["auth-db", "payment-gateway", "ledger-worker"]),
    st.text(max_size=80),
    st.sampled_from(_SENSITIVE_FRAGMENTS),
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_BEARER = re.compile(r"bearer\s+\S+", re.IGNORECASE)


def _contains_ip(text: str) -> bool:
    if _IPV4.search(text):
        return True
    for word in text.split():
        candidate = word.strip(".,;:()[]\"'")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# Property 1: pager payload invariant (Req 3.1, 3.2, 3.3)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(token=tokens, service=service_names, summary=diagnosis_text)
def test_property_1_pager_payload_invariant(token: str, service: str, summary: str) -> None:
    """**Validates: Requirements 3.1, 3.2, 3.3**"""
    text = format_pager_payload(token, service, summary).text
    assert text.isascii()
    assert len(text) <= PAGER_MAX_CHARS
    assert text.startswith(f"INC-{token}")
    assert f"{token}-1" in text and f"{token}-2" in text
    assert _EMAIL.search(text) is None
    assert not _contains_ip(text)
    assert _BEARER.search(text) is None
    assert "eyJ" not in text


# ---------------------------------------------------------------------------
# Property 2: deduplication idempotence (Req 1.2)
# ---------------------------------------------------------------------------

_SERVICES = ["auth-db", "payment-gateway", "ledger-worker"]
_CODES = ["DB_POOL_EXHAUSTED", "UPSTREAM_TIMEOUT", "LAG"]
alert_sequences = st.lists(
    st.tuples(st.sampled_from(_SERVICES), st.sampled_from(_CODES)), min_size=1, max_size=40
)


@settings(max_examples=200, deadline=None)
@given(alerts=alert_sequences, ids=st.lists(st.uuids(), min_size=40, max_size=40, unique=True))
def test_property_2_dedup_idempotence(alerts: list[tuple[str, str]], ids: list[UUID]) -> None:
    """**Validates: Requirements 1.2**"""

    async def run() -> None:
        store = InMemoryDedupStore()
        owners: dict[tuple[str, str], UUID] = {}
        acquired_count: dict[tuple[str, str], int] = {}
        for (service, code), incident_id in zip(alerts, ids, strict=False):
            result = await store.acquire(service, code, incident_id)
            key = (service, code)
            if key not in owners:
                assert isinstance(result, Acquired)
                owners[key] = incident_id
                acquired_count[key] = 1
            else:
                assert isinstance(result, Duplicate)
                assert result.incident_id == owners[key]
        assert all(n == 1 for n in acquired_count.values())
        assert set(owners) == set(alerts)

    asyncio.run(run())


@settings(max_examples=200, deadline=None)
@given(
    a=st.tuples(st.text(max_size=8), st.text(max_size=8)),
    b=st.tuples(st.text(max_size=8), st.text(max_size=8)),
)
def test_property_2_fingerprint_separates_fields(a: tuple[str, str], b: tuple[str, str]) -> None:
    """**Validates: Requirements 1.2**"""
    assert (compute_fingerprint(*a) == compute_fingerprint(*b)) == (a == b)


# ---------------------------------------------------------------------------
# Property 3: SMS reply parsing (Req 4.4, 4.5)
# ---------------------------------------------------------------------------

_KNOWN = ["7A", "B3", "K9"]
_WS = st.text(alphabet=" \t\r\n", max_size=3)


@st.composite
def _valid_replies(draw: st.DrawFn) -> tuple[str, str, str]:
    token = draw(st.sampled_from(_KNOWN))
    choice = draw(st.sampled_from(["1", "2"]))
    cased = "".join(draw(st.sampled_from([c.lower(), c.upper()])) for c in token)
    return f"{draw(_WS)}{cased}-{choice}{draw(_WS)}", token, choice


@settings(max_examples=200, deadline=None)
@given(case=_valid_replies())
def test_property_3_valid_replies_accepted(case: tuple[str, str, str]) -> None:
    """**Validates: Requirements 4.4, 4.5**"""
    body, token, choice = case
    reply = parse_sms_reply(body, _KNOWN)
    assert reply is not None
    assert reply.token == token and reply.choice == choice
    assert reply.action_code == f"{token}-{choice}"


def _oracle(body: str, known: list[str]) -> bool:
    s = body.strip()
    return (
        len(s) == 4
        and s[:2].isascii()
        and s[:2].isalnum()
        and s[2] == "-"
        and s[3] in ("1", "2")
        and s[:2].upper() in known
    )


_near_misses = st.one_of(
    st.text(max_size=12),
    st.from_regex(r"[A-Za-z0-9]{0,3}[-\u2013 ]?[0-9]{0,2}", fullmatch=True),
    st.sampled_from(["7A-3", "7A-0", "7A-11", "7A 1", "7A1", "7A-", "-1", "ZZ-1", "7A-1 yes", "yes 7A-1", "7A\u20131"]),
)


@settings(max_examples=200, deadline=None)
@given(body=_near_misses)
def test_property_3_only_exact_format_for_known_token(body: str) -> None:
    """**Validates: Requirements 4.4, 4.5**"""
    reply = parse_sms_reply(body, _KNOWN)
    assert (reply is not None) == _oracle(body, _KNOWN)


# ---------------------------------------------------------------------------
# Property 4: Tripwire soundness (Req 5.2)
# ---------------------------------------------------------------------------

_hosts = st.sampled_from(["auth-db", "payment-gateway", "ledger-worker", "", "AUTH-DB"])
_actions = st.sampled_from(["RB-A", "RB-B", "RB-C", "UNKNOWN", "", "rb-a"])


@settings(max_examples=200, deadline=None)
@given(
    target=_hosts,
    service=_hosts,
    action=_actions,
    approved=st.sets(_actions, max_size=4),
)
def test_property_4_tripwire_soundness(
    target: str, service: str, action: str, approved: set[str]
) -> None:
    """**Validates: Requirements 5.2**"""
    result = TripwireValidator(approved).validate(
        target_host=target, service_name=service, action_id=action
    )
    assert result.passed == (target == service and action in approved)
    if not result.passed:
        assert result.reason in {"target_host_mismatch", "action_not_approved"}


# ---------------------------------------------------------------------------
# Property 5: audit chain integrity and RESOLVED gating (Req 5.3, 5.4, 5.5)
# ---------------------------------------------------------------------------

_json_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(min_value=-(10**12), max_value=10**12), st.text(max_size=12)
)
_json_values = st.recursive(
    _json_scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=3), st.dictionaries(st.text(max_size=6), inner, max_size=3)
    ),
    max_leaves=6,
)
_payloads = st.dictionaries(st.text(max_size=6), _json_values, max_size=4)
_events = st.lists(
    st.tuples(st.sampled_from(["INCIDENT_CREATED", "PAGER_SENT", "TRIPWIRE_PASSED", "X"]), _payloads),
    min_size=1,
    max_size=8,
)
_incident_ids = st.uuids()


def _build(incident_id: UUID, events: list[tuple[str, dict[str, Any]]]) -> list[AuditRecord]:
    logger = AuditLogger(incident_id)
    for event, payload in events:
        logger.append(event, payload)
    return list(logger.records)


@settings(max_examples=200, deadline=None)
@given(incident_id=_incident_ids, events=_events)
def test_property_5_chain_valid_and_hash_formula(
    incident_id: UUID, events: list[tuple[str, dict[str, Any]]]
) -> None:
    """**Validates: Requirements 5.3**"""
    records = _build(incident_id, events)
    assert verify_chain(records).valid
    assert records[0].prev_hash == GENESIS_HASH
    for prev, rec in zip(records, records[1:], strict=False):
        assert rec.prev_hash == prev.hash
    for rec in records:
        assert rec.hash == compute_audit_hash(
            rec.prev_hash, rec.incident_id, rec.seq, rec.event_type, rec.payload
        )


@settings(max_examples=200, deadline=None)
@given(
    incident_id=_incident_ids,
    events=_events,
    data=st.data(),
    field=st.sampled_from(["payload", "event_type", "hash", "prev_hash", "seq", "incident_id"]),
)
def test_property_5_any_mutation_detected(
    incident_id: UUID,
    events: list[tuple[str, dict[str, Any]]],
    data: st.DataObject,
    field: str,
) -> None:
    """**Validates: Requirements 5.3**"""
    records = _build(incident_id, events)
    index = data.draw(st.integers(min_value=0, max_value=len(records) - 1))
    target = records[index]
    updates: dict[str, Any] = {
        "payload": {**target.payload, "tampered": True},
        "event_type": target.event_type + "!",
        "hash": ("1" if target.hash[0] != "1" else "2") + target.hash[1:],
        "prev_hash": ("1" if target.prev_hash[0] != "1" else "2") + target.prev_hash[1:],
        "seq": target.seq + 1,
        "incident_id": UUID(int=target.incident_id.int ^ 1),
    }
    mutated = list(records)
    mutated[index] = target.model_copy(update={field: updates[field]})
    result = verify_chain(mutated)
    assert not result.valid
    assert result.broken_at is not None and result.broken_at <= index


@settings(max_examples=200, deadline=None)
@given(incident_id=_incident_ids, events=st.lists(st.tuples(st.just("E"), _payloads), min_size=2, max_size=8), data=st.data())
def test_property_5_deletion_detected(
    incident_id: UUID, events: list[tuple[str, dict[str, Any]]], data: st.DataObject
) -> None:
    """**Validates: Requirements 5.3**"""
    records = _build(incident_id, events)
    # Dropping the tail leaves a valid prefix (a chain alone cannot prove completeness),
    # so only non-tail deletions are required to be detected.
    index = data.draw(st.integers(min_value=0, max_value=len(records) - 2))
    assert not verify_chain(records[:index] + records[index + 1 :]).valid


_AUDIT_INCIDENT = UUID("00000000-0000-4000-8000-0000000000a4")
# Computed with hashlib over the exact string produced by the SQL in
# database/init_mock_logs.sql: prev_hash || '|' || incident_id::text || '|' || seq
# || '|' || event_type || '|' || payload::text  (jsonb::text uses ': ' and ', ').
_VECTOR_HASH_0 = "b01ddcc639880486d43ad53f034c557e039dacbb617dcc24577e6dcf25604b7a"
_VECTOR_HASH_1 = "3ab7cd754cf7f36a18b598e4294f865c2371c47f39170ee738e9d78922cf7d08"


def test_property_5_python_hash_matches_sql_vector() -> None:
    """**Validates: Requirements 5.3** (hard-coded vector for the seeded incident Z1 chain)."""
    h0 = compute_audit_hash(
        GENESIS_HASH, _AUDIT_INCIDENT, 0, "INCIDENT_CREATED", {"service_name": "auth-db"}
    )
    assert h0 == _VECTOR_HASH_0
    h1 = compute_audit_hash(
        h0, _AUDIT_INCIDENT, 1, "TRIPWIRE_PASSED", {"action_id": "RB-AUTHDB-RESET-POOL"}
    )
    assert h1 == _VECTOR_HASH_1


def test_property_5_jsonb_text_matches_postgres_rendering() -> None:
    """**Validates: Requirements 5.3** (key order is length-then-bytes, as in jsonb)."""
    assert jsonb_text({"bb": 1, "a": [True, None], "ccc": "x"}) == '{"a": [true, null], "bb": 1, "ccc": "x"}'


_tri = st.one_of(st.none(), st.booleans())


@settings(max_examples=200, deadline=None)
@given(t=_tri, s=_tri, c=_tri, a=_tri)
def test_property_5_resolved_requires_all_four_gates(
    t: bool | None, s: bool | None, c: bool | None, a: bool | None
) -> None:
    """**Validates: Requirements 5.4, 5.5**"""
    gates = ResolutionGates(
        tripwire_check_passed=t,
        simulated_step_executed=s,
        confirmation_sms_sent=c,
        audit_record_committed=a,
    )
    assert can_resolve(gates) == (t is True and s is True and c is True and a is True)


# ---------------------------------------------------------------------------
# Task 6.2: IPv6 candidate validation and float-safe jsonb rendering
# ---------------------------------------------------------------------------

import pytest  # noqa: E402

from backend.app.services.guardrails import sanitize_pager_text  # noqa: E402

_non_ip_colon_ids = st.one_of(
    st.builds(
        lambda h, m, s: f"{h:02d}:{m:02d}:{s:02d}",
        st.integers(0, 23),
        st.integers(0, 59),
        st.integers(0, 59),
    ),
    st.sampled_from(["ab:cd:ef", "12:30:45", "aa:bb:cc:dd:ee:ff", "00:1A:2B:3C:4D:5E"]),
    st.lists(st.from_regex(r"[0-9a-f]{2}", fullmatch=True), min_size=3, max_size=6).map(":".join),
)


@settings(max_examples=200, deadline=None)
@given(ident=_non_ip_colon_ids)
def test_property_1_timestamps_and_mac_like_ids_survive(ident: str) -> None:
    """**Validates: Requirements 3.2, 3.3**"""
    assert sanitize_pager_text(f"at {ident} err") == f"at {ident} err"


@settings(max_examples=200, deadline=None)
@given(addr=st.ip_addresses(v=6))
def test_property_1_real_ipv6_is_redacted(addr: ipaddress.IPv6Address) -> None:
    """**Validates: Requirements 3.2**"""
    for form in (str(addr), addr.exploded):
        out = sanitize_pager_text(f"host {form} down")
        assert form not in out
        assert not _contains_ip(out)
    assert sanitize_pager_text(f"[{addr}]:8080") == "[***]:8080"


def test_property_1_ipv6_special_forms_redacted() -> None:
    """**Validates: Requirements 3.2**"""
    for form in ("::1", "fe80::1", "::ffff:10.1.2.3", "fe80::1%eth0"):
        assert sanitize_pager_text(f"x {form} y") == "x *** y"
    assert sanitize_pager_text("10.0.0.1 x") == "*** x"


_audit_floats = st.floats(allow_nan=False, allow_infinity=False)


@settings(max_examples=200, deadline=None)
@given(values=st.lists(_audit_floats, min_size=1, max_size=5), nested=_audit_floats)
def test_property_5_floats_in_audit_payload_keep_chain_valid(
    values: list[float], nested: float
) -> None:
    """**Validates: Requirements 5.3**"""
    log = AuditLogger(UUID(int=7))
    log.append("TELEMETRY", {"samples": values, "meta": {"latency": nested}})
    log.append("NEXT", {"x": 1.5})
    assert verify_chain(log.records).valid
    assert log.verify().valid
    for v in values:
        text = jsonb_text(v)
        assert "e" not in text.lower()
        assert float(text) == v


def test_property_5_jsonb_float_rendering_and_rejection() -> None:
    """**Validates: Requirements 5.3**"""
    assert jsonb_text(1.5) == "1.5"
    assert jsonb_text(2.0) == "2.0"
    assert jsonb_text(1e-07) == "0.0000001"
    assert jsonb_text(1e16) == "10000000000000000"
    assert jsonb_text(-0.0) == "0.0"
    assert jsonb_text({"a": [0.25, True]}) == '{"a": [0.25, true]}'
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            jsonb_text(bad)


# ---------------------------------------------------------------------------
# Property 6: failed runs end FAILED and free the fingerprint (Req 5.6)
# ---------------------------------------------------------------------------

_P6_OUTCOMES = st.sampled_from(["RESOLVED", "EXECUTING", "BLOCKED_BY_TRIPWIRE", "RAISE"])


@settings(max_examples=200, deadline=None)
@given(outcome=_P6_OUTCOMES, flags=st.tuples(_tri, _tri, _tri, _tri))
def test_property_6_failed_runs_end_failed_and_release_lock(
    outcome: str, flags: tuple[bool | None, bool | None, bool | None, bool | None]
) -> None:
    """**Validates: Requirements 5.4, 5.5, 5.6**"""
    from backend.tests.test_failed_path import fingerprint_free, run_stub

    names = ("tripwire_check_passed", "simulated_step_executed", "confirmation_sms_sent", "audit_record_committed")
    gates = dict(zip(names, flags, strict=True))
    all_true = all(f is True for f in flags)

    async def scenario() -> tuple[str, bool]:
        if outcome == "RAISE":
            services, incident = await run_stub(error=RuntimeError("boom"))
        else:
            services, incident = await run_stub({"status": outcome, "gates": gates})
        row = await services.incidents.get(incident.incident_id)
        assert row is not None
        return row.state, await fingerprint_free(services)

    state, freed = asyncio.run(scenario())
    if outcome == "RESOLVED" and all_true:
        assert state == "RESOLVED"
    elif outcome == "BLOCKED_BY_TRIPWIRE":
        assert state == "BLOCKED_BY_TRIPWIRE"
    else:
        assert state == "FAILED"  # RESOLVED is never written without all four gates
    assert freed  # every terminal state frees the fingerprint
