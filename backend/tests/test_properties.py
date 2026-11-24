"""Property-based tests for Correctness Properties 1-5 (design.md).

No Postgres, Redis, or network access is required.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import unicodedata
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
    """Independent model of the Req 4.9 normalisation, written char by char."""
    chars: list[str] = []
    for ch in body:
        code = ord(ch)
        if ch.isspace():
            chars.append(" " if unicodedata.normalize("NFKC", ch) == " " else ch)
        elif code < 0x80:
            chars.append(ch)
        elif 0xFF01 <= code <= 0xFF5E:  # full-width forms
            chars.append(chr(code - 0xFEE0))
        elif 0x2010 <= code <= 0x2015 or code == 0x2212:
            chars.append("-")
        else:
            return False
    s = "".join(chars).strip()
    while s and (s[-1] in ".!" or s[-1].isspace()):
        s = s[:-1]
    return (
        len(s) == 4
        and s[:2].isascii()
        and s[:2].isalnum()
        and s[2] in "- "
        and s[3] in ("1", "2")
        and s[:2].upper() in known
    )


_near_misses = st.one_of(
    st.text(max_size=12),
    st.from_regex(r"[A-Za-z0-9]{0,3}[-\u2013\u2212 ]?[0-9]{0,2}", fullmatch=True),
    st.from_regex(r"[ \t]{0,2}(7A|b3|\uff17\uff21)[-\u2010-\u2015\u2212\uff0d ][12\uff11\uff12\u00b9][.!\s]{0,3}", fullmatch=True),
    st.sampled_from(
        [
            "7A-3", "7A-0", "7A-11", "7A 1", "7A1", "7A-", "-1", "ZZ-1", "7A-1 yes", "yes 7A-1",
            "7A\u20131", "7A-1.", "7A-\u00b9", "\u212aA-1", "K9-1\u2026", "7A  1", "7A\t1", "7A-1?",
        ]
    ),
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
# database/30_demo_seed.sql: prev_hash || '|' || incident_id::text || '|' || seq
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
    assert sanitize_pager_text(f"at {ident} err", neutralize_codes=False) == f"at {ident} err"


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


# ---------------------------------------------------------------------------
# Property 7: single-SMS septet budget (Req 3.1, 3.2, 3.3)
# ---------------------------------------------------------------------------

from backend.app.services.guardrails import (  # noqa: E402
    _GSM7_BASIC,
    _GSM7_EXTENSION,
    gsm7_septets,
)

_P7_SPECIAL = "`\u2018\u2019\u201c\u201d{}[]|^~\\\u20ac\U0001f600\u00e9\u00fc\u4e2d\n\t\x00 @$_%"
_p7_text = st.one_of(
    st.text(max_size=400),
    st.text(alphabet=_P7_SPECIAL, max_size=300),
    st.lists(
        st.one_of(st.sampled_from(_SENSITIVE_FRAGMENTS), st.text(alphabet=_P7_SPECIAL, max_size=12), st.text(max_size=12)),
        max_size=30,
    ).map(" ".join),
)
_p7_title = st.one_of(st.none(), _p7_text)
_GSM_ALL = sorted(_GSM7_BASIC | _GSM7_EXTENSION)
_ASCII_EXT = set("^{}\\[~]|")


@settings(max_examples=200, deadline=None)
@given(token=tokens, service=_p7_text, summary=_p7_text, t1=_p7_title, t2=_p7_title)
def test_property_7_single_sms_septet_budget(
    token: str, service: str, summary: str, t1: str | None, t2: str | None
) -> None:
    """**Validates: Requirements 3.1, 3.2, 3.3**"""
    text = format_pager_payload(token, service, summary, t1, t2).text
    assert text.isascii()
    assert all(c in _GSM7_BASIC or c in _GSM7_EXTENSION for c in text)  # no UCS-2 trigger
    assert gsm7_septets(text) <= 160  # raises if not GSM-7 encodable
    assert text.startswith(f"INC-{token} ")
    if f"{token}-1:" in text:
        # Main path: both action markers, each followed by a non-empty title.
        assert f"{token}-2:" in text
        for n in (1, 2):
            tail = text.split(f"{token}-{n}:", 1)[1]
            assert tail[:1] not in ("", " ")
    else:
        # Documented last-resort fallback: both reply codes survive.
        assert text == f"INC-{token} Reply: {token}-1, {token}-2"


@settings(max_examples=200, deadline=None)
@given(
    token=tokens,
    service=_p7_text,
    summary=_p7_text,
    t1=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=4),
    t2=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=4),
)
def test_property_7_short_titles_appear_verbatim(token: str, service: str, summary: str, t1: str, t2: str) -> None:
    """**Validates: Requirements 3.1, 3.2**"""
    text = format_pager_payload(token, service, summary, t1, t2).text
    # A "," joins the options when t1 ends in two alphanumerics and the token starts with 1 or 2.
    sep = "," if token[0] in "12" and t1[-2:].isalnum() and len(t1[-2:]) == 2 else " "
    assert text.endswith(f". {token}-1:{t1}{sep}{token}-2:{t2}")


@settings(max_examples=200, deadline=None)
@given(s=st.text(alphabet=st.sampled_from(_GSM_ALL), max_size=300))
def test_property_7_septets_equal_len_plus_extension_chars(s: str) -> None:
    """**Validates: Requirements 3.1**"""
    assert gsm7_septets(s) == len(s) + sum(1 for c in s if c in _GSM7_EXTENSION)


@settings(max_examples=200, deadline=None)
@given(token=tokens, service=_p7_text, summary=_p7_text, t1=_p7_title, t2=_p7_title)
def test_property_7_extension_chars_in_pages_count_double(
    token: str, service: str, summary: str, t1: str | None, t2: str | None
) -> None:
    """**Validates: Requirements 3.1**"""
    text = format_pager_payload(token, service, summary, t1, t2).text
    ext = sum(1 for c in text if c in _GSM7_EXTENSION)
    assert ext == sum(1 for c in text if c in _ASCII_EXT)  # euro/form feed never survive
    assert gsm7_septets(text) == len(text) + ext
    assert len(text) + ext <= 160


# ---------------------------------------------------------------------------
# Property 8: inbound reply authorization (Req 4.2, 4.3)
# A reply changes incident state only when the secret matches AND the canonical E.164
# sender equals ONCALL_PHONE_NUMBER AND the shortcode matches (when configured) AND the
# message id has not been seen.
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient  # noqa: E402
from pydantic import SecretStr  # noqa: E402

from backend.app.api.routes import authorize_inbound_sms  # noqa: E402
from backend.app.main import Settings, build_in_memory_services, create_app  # noqa: E402
from backend.app.services.africastalking_client import (  # noqa: E402
    AfricasTalkingSettings,
    canonicalize_e164,
)

_P8_ONCALL = "+254711000111"
_P8_SHORTCODE = "20880"
_P8_SECRET = "p8-secret"

_p8_senders = st.sampled_from(
    [_P8_ONCALL, "254711000111", " +254711000111 ", "+254 711 000 111", "+254711000112", "+14155550123", "", "abc", "+0"]
)
_p8_to = st.sampled_from([_P8_SHORTCODE, " 20880 ", "99999", "", "abc"])
_p8_secrets = st.sampled_from([_P8_SECRET, "wrong", "", _P8_SECRET + "x"])
_p8_shortcodes = st.sampled_from([_P8_SHORTCODE, ""])  # configured / not configured


def _p8_expected(secret: str, sender: str, to: str, shortcode: str, seen: bool) -> bool:
    sender_ok = canonicalize_e164(sender) == canonicalize_e164(_P8_ONCALL)
    code = "".join(ch for ch in shortcode if ch.isdigit())
    shortcode_ok = not shortcode.strip() or "".join(ch for ch in to if ch.isdigit()) == code
    return secret == _P8_SECRET and sender_ok and shortcode_ok and not seen


@settings(max_examples=200, deadline=None)
@given(secret=_p8_secrets, sender=_p8_senders, to=_p8_to, shortcode=_p8_shortcodes)
def test_property_8_pure_authorization_matches_model(secret: str, sender: str, to: str, shortcode: str) -> None:
    """**Validates: Requirements 4.2, 4.3**"""
    reason = authorize_inbound_sms(
        expected_secret=_P8_SECRET,
        supplied_secrets=(secret, ""),
        sender=sender,
        to=to,
        oncall_phone_number=_P8_ONCALL,
        shortcode=shortcode,
    )
    assert (reason is None) == _p8_expected(secret, sender, to, shortcode, seen=False)


@settings(max_examples=200, deadline=None)
@given(secret=st.text(max_size=20), sender=st.text(max_size=20), to=st.text(max_size=10))
def test_property_8_unconfigured_secret_always_rejects(secret: str, sender: str, to: str) -> None:
    """**Validates: Requirements 4.2**"""
    assert (
        authorize_inbound_sms(
            expected_secret="",
            supplied_secrets=(secret,),
            sender=sender,
            to=to,
            oncall_phone_number=_P8_ONCALL,
            shortcode="",
        )
        is not None
    )


@settings(max_examples=200, deadline=None)
@given(secret=_p8_secrets, sender=_p8_senders, to=_p8_to, shortcode=_p8_shortcodes, seen=st.booleans())
def test_property_8_route_changes_state_only_when_authorized(
    secret: str, sender: str, to: str, shortcode: str, seen: bool
) -> None:
    """**Validates: Requirements 4.2, 4.3**"""
    at = AfricasTalkingSettings(
        webhook_secret=SecretStr(_P8_SECRET), to_number=_P8_ONCALL, shortcode=shortcode
    )
    svc = build_in_memory_services(Settings(use_in_memory=True, africastalking=at))
    with TestClient(create_app(svc, Settings(frontend_dir=None))) as client:
        alert = {"service_name": "auth-db", "error_code": "DB_POOL_EXHAUSTED", "summary": "x"}
        incident_id = UUID(client.post("/webhooks/alerts", json=alert).json()["incident_id"])
        record = asyncio.run(svc.incidents.get(incident_id))
        assert record is not None and record.state == "AWAITING_APPROVAL"
        if seen:
            assert asyncio.run(svc.seen_ids.claim("ATXid_p8"))
        form = {"from": sender, "to": to, "text": f"{record.token}-1", "date": "d", "id": "ATXid_p8", "linkId": "l"}
        headers = {"X-Webhook-Secret": secret} if secret else {}
        resp = client.post("/webhooks/africastalking/sms", data=form, headers=headers)
        after = asyncio.run(svc.incidents.get(incident_id))
        assert after is not None
        if _p8_expected(secret, sender, to, shortcode, seen):
            assert resp.status_code == 200 and after.state == "RESOLVED"
        else:
            assert after.state == "AWAITING_APPROVAL"
            assert resp.status_code in (200, 403) and (resp.status_code == 403 or seen)


# ---------------------------------------------------------------------------
# Property 9: TOCTOU Tripwire (Req 5.2)
# Approved-set mutations between triage and execution: the graph resolves iff the chosen
# action is currently approved for the service with a matching host.
# ---------------------------------------------------------------------------

_P9_MUTATIONS = st.sampled_from(["keep", "remove", "wrong_host", "wrong_host_then_right"])


@settings(max_examples=200, deadline=None)
@given(
    choice=st.sampled_from(["1", "2"]),
    mutations=st.tuples(_P9_MUTATIONS, _P9_MUTATIONS),
    lookup_fails=st.booleans(),
)
def test_property_9_toctou_tripwire(
    choice: str, mutations: tuple[str, str], lookup_fails: bool
) -> None:
    """**Validates: Requirements 5.2**"""
    from backend.app.agents.ports import Runbook
    from backend.app.services.guardrails import verify_chain
    from backend.tests.test_workflow import RUNBOOKS, SERVICE, Rig

    async def scenario() -> None:
        rig = Rig()
        await rig.start()  # triage caches both runbooks as approved
        assert rig.runbooks.executed == []
        mutated: list[Runbook] = []
        for book, mutation in zip(RUNBOOKS, mutations, strict=True):
            wrong = book.model_copy(update={"target_host": "payment-gateway"})
            if mutation == "keep":
                mutated.append(book)
            elif mutation == "wrong_host":
                mutated.append(wrong)
            elif mutation == "wrong_host_then_right":
                mutated.extend([wrong, book])
        rig.runbooks.approved = tuple(mutated)
        rig.runbooks.fail_lookup = lookup_fails
        chosen = RUNBOOKS[int(choice) - 1]
        still_approved = any(
            r.action_id == chosen.action_id and r.target_host == SERVICE for r in mutated
        )
        done = await rig.resume(choice)
        events = [r.event_type for r in await rig.chain()]
        assert verify_chain(await rig.chain()).valid
        if still_approved and not lookup_fails:
            assert done["status"] == "RESOLVED"
            assert done["gates"] == {
                "tripwire_check_passed": True,
                "simulated_step_executed": True,
                "confirmation_sms_sent": True,
                "audit_record_committed": True,
            }
            assert rig.runbooks.executed == [(SERVICE, chosen.action_id)]
        else:
            assert done["status"] == "BLOCKED_BY_TRIPWIRE"
            assert rig.runbooks.executed == []
            assert done["gates"]["tripwire_check_passed"] is False
            assert "TRIPWIRE_BLOCKED" in events and "REMEDIATION_EXECUTED" not in events
            assert not any(m.endswith("RESOLVED") for m in rig.sms.sent)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Property 10: expiry and reconciliation (Req 6.1 to 6.5)
# ---------------------------------------------------------------------------

_P10_TTL = 900


@settings(max_examples=200, deadline=None)
@given(age=st.integers(min_value=0, max_value=3 * _P10_TTL), choice=st.sampled_from(["1", "2"]))
def test_property_10_reply_expiry_vs_ttl(age: int, choice: str) -> None:
    """**Validates: Requirements 6.1, 6.2, 6.3, 6.5**"""
    from backend.tests.test_expiry import (
        TTL,
        add_incident,
        events_of,
        fingerprint_free,
        make_services,
        reply,
        state_of,
    )

    assert TTL == _P10_TTL

    async def scenario() -> None:
        services, clock, graph = make_services()
        incident = await add_incident(services, "AWAITING_APPROVAL")
        clock.advance(age)
        await reply(services, f"{incident.token}-{choice}")
        state = await state_of(services, incident.incident_id)
        if age >= TTL:  # store clock: updated_at <= now - ttl
            assert state == "EXPIRED"
            assert graph.calls == []  # no infrastructure mutation
            assert (await events_of(services, incident.incident_id))[-1] == "INCIDENT_EXPIRED"
        else:
            assert state == "RESOLVED"
            assert len(graph.calls) == 1
        assert await fingerprint_free(services)  # both terminal states release the lock

    asyncio.run(scenario())


_P10_STATES = st.sampled_from(
    ["TRIAGING", "AWAITING_APPROVAL", "EXECUTING", "RESOLVED", "BLOCKED_BY_TRIPWIRE", "FAILED", "EXPIRED"]
)


@settings(max_examples=200, deadline=None)
@given(rows=st.lists(st.tuples(_P10_STATES, st.integers(min_value=0, max_value=40)), min_size=0, max_size=10))
def test_property_10_reconcile_orphans_moves_exactly_stale_inflight(rows: list[tuple[str, int]]) -> None:
    """**Validates: Requirements 6.4, 6.5**"""
    from typing import cast
    from uuid import uuid4

    from backend.app.services.dedup import Acquired, Duplicate
    from backend.app.services.incident_store import IncidentStatus
    from backend.tests.test_expiry import add_incident, events_of, make_services, state_of

    async def scenario() -> None:
        services, clock, graph = make_services()
        stale_after = services.inflight_stale_seconds
        seeded = []
        for i, (state, gap) in enumerate(rows):
            clock.advance(gap)  # gaps make earlier incidents older
            incident = await add_incident(services, cast(IncidentStatus, state), token=f"T{i}", service=f"svc-{i}")
            seeded.append((incident, state, f"svc-{i}", clock.now))
        clock.advance(stale_after // 2)

        def is_stale(state: str, seeded_at: datetime) -> bool:
            return state in ("TRIAGING", "EXECUTING") and (clock.now - seeded_at).total_seconds() >= stale_after

        expected = sum(1 for _, s, _, at in seeded if is_stale(s, at))
        assert await services.lifecycle.reconcile_orphans() == expected
        for incident, before, svc, at in seeded:
            after = await state_of(services, incident.incident_id)
            failed = "INCIDENT_FAILED" in await events_of(services, incident.incident_id)
            probe = await services.dedup.acquire(svc, "E1", uuid4())
            if is_stale(before, at):
                assert after == "FAILED" and failed
                assert isinstance(probe, Acquired)  # lock released
            else:
                assert after == before and not failed
                assert isinstance(probe, Duplicate)  # untouched, lock still held
        assert graph.calls == []

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Property 11: stale-lease reconciliation (Req 6.4)
# ---------------------------------------------------------------------------

from datetime import UTC, datetime, timedelta  # noqa: E402

from backend.app.services.incident_store import ALL_STATUSES, InMemoryIncidentRepository  # noqa: E402

_P11_STATES = sorted(ALL_STATUSES)


@settings(max_examples=200, deadline=None)
@given(
    rows=st.lists(
        st.tuples(st.sampled_from(_P11_STATES), st.integers(min_value=0, max_value=300)),
        max_size=12,
    ),
    cutoff=st.integers(min_value=10, max_value=300),
)
def test_property_11_reconcile_fails_exactly_stale_inflight(
    rows: list[tuple[str, int]], cutoff: int
) -> None:
    """**Validates: Requirements 6.4**"""

    async def scenario() -> None:
        t0 = datetime(2025, 1, 1, tzinfo=UTC)
        now = t0 + timedelta(seconds=1000)
        clock = {"t": t0}
        repo = InMemoryIncidentRepository(lambda: clock["t"])
        expected: dict[UUID, str] = {}
        stale: set[UUID] = set()
        for i, (state, age) in enumerate(rows):
            iid = UUID(int=i + 1)
            clock["t"] = now - timedelta(seconds=age)
            await repo.create(
                incident_id=iid, token=f"{i // 36}{'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[i % 36]}",
                service_name=f"svc{i}", error_code="E", raw_alert={},
            )
            if state != "TRIAGING":
                await repo.set_state(iid, state)  # type: ignore[arg-type]
            if state in ("TRIAGING", "EXECUTING") and age >= cutoff:
                stale.add(iid)
                expected[iid] = "FAILED"
            else:
                expected[iid] = state
        clock["t"] = now
        reclaimed = await repo.reconcile_stale_inflight(cutoff)
        assert {r.incident_id for r in reclaimed} == stale
        assert len(reclaimed) == len(stale)
        for iid, state in expected.items():
            row = await repo.get(iid)
            assert row is not None and row.state == state

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Property 12: header-only callback secret (Req 4.2, 4.3)
# The first available source (X-Webhook-Secret, Authorization: Bearer, ?secret= only when
# allowed) is the only one compared; a wrong higher-priority source is never rescued.
# ---------------------------------------------------------------------------

from backend.app.services.africastalking_client import extract_webhook_secret  # noqa: E402

_P12_SECRET = "p12-secret"
_p12_values = st.sampled_from([_P12_SECRET, "wrong", "", None])
_p12_bearer = st.sampled_from(
    [
        f"Bearer {_P12_SECRET}",
        f"bEaReR {_P12_SECRET}",
        f"Bearer  {_P12_SECRET}",  # two spaces: malformed
        f"Basic {_P12_SECRET}",
        "Bearer wrong",
        "Bearer ",
        "Bearer",
        "",
        None,
    ]
)


def _p12_model(header: str | None, bearer: str | None, query: str | None, allow: bool) -> str | None:
    if header:
        return header
    if bearer is not None and bearer.lower().startswith("bearer ") and bearer[7:] and not bearer[7].isspace():
        return bearer[7:]
    if allow and query:
        return query
    return None


@settings(max_examples=200, deadline=None)
@given(header=_p12_values, bearer=_p12_bearer, query=_p12_values, allow=st.booleans())
def test_property_12_extract_returns_first_available_source(
    header: str | None, bearer: str | None, query: str | None, allow: bool
) -> None:
    """**Validates: Requirements 4.2, 4.3**"""
    assert extract_webhook_secret(header, bearer, query, allow_query=allow) == _p12_model(
        header, bearer, query, allow
    )


@settings(max_examples=200, deadline=None)
@given(header=_p12_values, bearer=_p12_bearer, query=_p12_values, allow=st.booleans())
def test_property_12_route_accepts_only_when_selected_source_matches(
    header: str | None, bearer: str | None, query: str | None, allow: bool
) -> None:
    """**Validates: Requirements 4.2, 4.3**"""
    at = AfricasTalkingSettings(webhook_secret=SecretStr(_P12_SECRET), to_number=_P8_ONCALL, shortcode="")
    svc = build_in_memory_services(Settings(use_in_memory=True, africastalking=at, allow_query_secret=allow))
    with TestClient(create_app(svc, Settings(frontend_dir=None))) as client:
        alert = {"service_name": "auth-db", "error_code": "DB_POOL_EXHAUSTED", "summary": "x"}
        incident_id = UUID(client.post("/webhooks/alerts", json=alert).json()["incident_id"])
        record = asyncio.run(svc.incidents.get(incident_id))
        assert record is not None
        headers: dict[str, str] = {}
        if header is not None:
            headers["X-Webhook-Secret"] = header
        if bearer is not None:
            headers["Authorization"] = bearer
        params = {"secret": query} if query is not None else {}
        form = {"from": _P8_ONCALL, "to": "", "text": f"{record.token}-1", "date": "d", "id": "ATXid_p12", "linkId": "l"}
        resp = client.post("/webhooks/africastalking/sms", data=form, headers=headers, params=params)
        after = asyncio.run(svc.incidents.get(incident_id))
        assert after is not None
        if _p12_model(header, bearer, query, allow) == _P12_SECRET:
            assert resp.status_code == 200 and after.state == "RESOLVED"
        else:
            assert resp.status_code == 403 and after.state == "AWAITING_APPROVAL"


# ---------------------------------------------------------------------------
# Property 13: no incident stays non-terminal beyond the maximum timeout (Req 6.8, 6.11)
# ---------------------------------------------------------------------------
_P13_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


@settings(max_examples=200, deadline=None)
@given(
    rows=st.lists(
        st.tuples(
            st.sampled_from(["TRIAGING", "EXECUTING", "AWAITING_APPROVAL"]),
            st.integers(min_value=0, max_value=5000),
        ),
        min_size=0,
        max_size=15,
    ),
    triage_t=st.integers(min_value=10, max_value=1000),
    exec_t=st.integers(min_value=10, max_value=1000),
    ttl=st.integers(min_value=10, max_value=1000),
)
def test_property_13_no_incident_stays_non_terminal_past_timeout(
    rows: list[tuple[str, int]], triage_t: int, exec_t: int, ttl: int
) -> None:
    """**Validates: Requirements 6.8, 6.11**"""
    from uuid import uuid4

    from backend.app.services.dedup import InMemoryDedupStore
    from backend.app.services.incident_store import InMemoryAuditStore, TERMINAL_STATUSES
    from backend.app.services.lifecycle import Lifecycle
    from backend.tests.test_expiry import Clock

    class _Sms:
        async def send(self, text: str) -> None:
            return None

    async def scenario() -> None:
        clock = Clock()
        repo = InMemoryIncidentRepository(clock)
        base = clock.now
        ids: list[tuple[UUID, str, int]] = []
        for i, (state, age) in enumerate(rows):
            clock.now = base - timedelta(seconds=age)
            iid = uuid4()
            await repo.create(
                incident_id=iid, token=f"{_P13_ALPHABET[i]}1", service_name="svc", error_code=f"E{i}", raw_alert={}
            )
            await repo.set_state(iid, state)  # type: ignore[arg-type]
            ids.append((iid, state, age))
        clock.now = base
        lifecycle = Lifecycle(
            incidents=repo,
            audit=InMemoryAuditStore(repo),
            dedup=InMemoryDedupStore(),
            sms=_Sms(),
            approval_ttl_seconds=ttl,
            clock=clock,
            triage_timeout_seconds=triage_t,
            executing_timeout_seconds=exec_t,
        )
        await lifecycle.tick()
        bound = {"TRIAGING": triage_t, "EXECUTING": exec_t, "AWAITING_APPROVAL": ttl}
        for iid, state, age in ids:
            row = await repo.get(iid)
            assert row is not None
            if age >= bound[state]:
                assert row.state in TERMINAL_STATUSES
            else:
                assert row.state == state

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Property 14: page delivery attempts (Req 8.1, 8.2, 8.3)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(
    failures=st.integers(min_value=0, max_value=10),
    max_attempts=st.integers(min_value=1, max_value=6),
    retryable=st.booleans(),
)
def test_property_14_page_attempt_count(failures: int, max_attempts: int, retryable: bool) -> None:
    """**Validates: Requirements 8.1, 8.2**"""
    from backend.app.services.africastalking_client import SmsSendError
    from backend.app.services.retrying_sms import RetryingSmsPort

    class _Inner:
        def __init__(self) -> None:
            self.calls = 0

        async def send(self, text: str) -> None:
            self.calls += 1
            if self.calls <= failures:
                raise SmsSendError("x", retryable=retryable)

    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    async def scenario() -> tuple[int, bool]:
        inner = _Inner()
        port = RetryingSmsPort(inner, max_attempts=max_attempts, sleep=fake_sleep, rand=lambda: 0.5)
        try:
            await port.send("page")
        except SmsSendError:
            return inner.calls, False
        return inner.calls, True

    attempts, delivered = asyncio.run(scenario())
    if failures == 0:
        expected = 1
    elif retryable:
        expected = min(failures + 1, max_attempts)
    else:
        expected = 1
    assert attempts == expected
    assert len(sleeps) == (attempts - 1 if retryable else 0)
    assert delivered == (failures == 0 or (retryable and failures < max_attempts))


# ---------------------------------------------------------------------------
# Property 15: the page offers exactly as many reply codes as options (Req 3.4, 3.5, 3.6)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(
    count=st.integers(min_value=0, max_value=2),
    token=st.from_regex(r"[A-Z0-9]{2}", fullmatch=True),
    service=st.text(max_size=60),
    summary=st.text(max_size=300),
    titles=st.lists(st.text(max_size=40), min_size=2, max_size=2),
)
def test_property_15_page_has_exactly_as_many_codes_as_options(
    count: int, token: str, service: str, summary: str, titles: list[str]
) -> None:
    """**Validates: Requirements 3.4, 3.5, 3.6**"""
    from backend.app.services.guardrails import (
        NO_ACTION_TEXT,
        format_pager_payload,
        gsm7_septets,
        parse_sms_reply,
    )

    text = format_pager_payload(token, service, summary, option_titles=titles[:count]).text
    assert text.isascii() and gsm7_septets(text) <= 160 and text.startswith(f"INC-{token}")
    codes = re.findall(rf"(?<![A-Za-z0-9]){token}-(\d)(?![0-9])", text, re.IGNORECASE)
    assert codes == [str(n) for n in range(1, count + 1)]
    for n in range(1, count + 1):
        reply = parse_sms_reply(f"{token}-{n}", known_tokens=[token])
        assert reply is not None and reply.action_code == f"{token}-{n}"
    if count == 0:
        assert text.endswith(NO_ACTION_TEXT)


# ---------------------------------------------------------------------------
# Property 16: forgiving but exact reply parsing (Req 4.9)
# ---------------------------------------------------------------------------

_P16_ALPHABET = st.sampled_from(
    list("aAzZ09-.! \t") + ["\u2010", "\u2013", "\u2015", "\u2212", "\uff11", "\uff21", "\u00b9", "\u212a", "\u00a0", "x_"]
)


@settings(max_examples=200, deadline=None)
@given(body=st.lists(_P16_ALPHABET, max_size=10).map("".join))
def test_property_16_accepted_text_normalises_to_canonical_code(body: str) -> None:
    """**Validates: Requirements 4.9**"""
    from backend.app.services.guardrails import normalize_sms_reply

    reply = parse_sms_reply(body)
    if reply is None:
        return
    assert re.fullmatch(r"[A-Z0-9]{2}-[12]", reply.action_code, re.ASCII)
    normalized = normalize_sms_reply(body)
    assert normalized is not None
    assert re.fullmatch(r"[A-Za-z0-9]{2}[- ][12]", normalized, re.ASCII)
    assert normalized[:2].upper() == reply.token and normalized[3] == reply.choice


@settings(max_examples=200, deadline=None)
@given(
    token=st.from_regex(r"[A-Za-z0-9]{2}", fullmatch=True),
    choice=st.sampled_from(["1", "2"]),
    sep=st.sampled_from(["-", " ", "\u2013", "\u2212"]),
    extra=st.from_regex(r"[A-Za-z0-9_]{1,4}", fullmatch=True),
    where=st.sampled_from(["prefix", "suffix", "prefix_space", "suffix_space"]),
)
def test_property_16_extra_word_characters_are_rejected(
    token: str, choice: str, sep: str, extra: str, where: str
) -> None:
    """**Validates: Requirements 4.9**"""
    core = f"{token}{sep}{choice}"
    assert parse_sms_reply(core) is not None  # the core alone is accepted
    body = {
        "prefix": f"{extra}{core}",
        "suffix": f"{core}{extra}",
        "prefix_space": f"{extra} {core}",
        "suffix_space": f"{core} {extra}",
    }[where]
    assert parse_sms_reply(body) is None


# ---------------------------------------------------------------------------
# Property 17: issued tokens are unique among active and cooling-down tokens (Req 9.1, 9.2)
# ---------------------------------------------------------------------------

_P17_OPS = st.lists(
    st.one_of(
        st.tuples(st.just("create"), st.just(0)),
        st.tuples(st.just("terminate"), st.integers(min_value=0, max_value=20)),
        st.tuples(st.just("advance"), st.integers(min_value=0, max_value=40)),
    ),
    max_size=40,
)


@settings(max_examples=200, deadline=None)
@given(ops=_P17_OPS, cooldown=st.integers(min_value=0, max_value=60))
def test_property_17_issued_tokens_are_unique_among_active_and_cooling(
    ops: list[tuple[str, int]], cooldown: int
) -> None:
    """**Validates: Requirements 9.1, 9.2**"""
    from uuid import UUID, uuid4

    from backend.app.services.incident_store import TokenExhaustedError, generate_token, token_space
    from backend.tests.test_expiry import Clock

    alphabet = "ABC"  # 9 tokens, so exhaustion is reachable
    everything = set(token_space(alphabet))

    async def scenario() -> None:
        clock = Clock()
        repo = InMemoryIncidentRepository(clock)
        active: dict[UUID, str] = {}
        cooling: list[tuple[str, datetime]] = []  # token, terminal time (independent model)
        for n, (op, arg) in enumerate(ops):
            if op == "advance":
                clock.advance(arg)
            elif op == "terminate" and active:
                incident_id = sorted(active, key=str)[arg % len(active)]
                await repo.set_state(incident_id, "RESOLVED")
                cooling.append((active.pop(incident_id), clock.now))
            elif op == "create":
                expected_busy = set(active.values()) | {
                    t for t, at in cooling if (clock.now - at).total_seconds() < cooldown
                }
                busy = await repo.busy_tokens(cooldown)
                assert busy == expected_busy
                try:
                    token = generate_token(busy, alphabet)
                except TokenExhaustedError:
                    assert expected_busy == everything  # exact: no free token existed
                    continue
                assert token not in expected_busy
                incident_id = uuid4()
                await repo.create(
                    incident_id=incident_id,
                    token=token,
                    service_name="svc",
                    error_code=f"E{n}",
                    raw_alert={},
                )
                active[incident_id] = token
        assert len(set(active.values())) == len(active)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Property 18: bounded dedup audit growth (Req 10.5)
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(duplicates=st.integers(min_value=0, max_value=700), sample=st.integers(min_value=1, max_value=40))
def test_property_18_dedup_audit_rows_are_bounded_and_the_chain_verifies(
    duplicates: int, sample: int
) -> None:
    """**Validates: Requirements 10.5**"""
    from dataclasses import replace

    from backend.app.api.routes import AlertPayload, _record_duplicate
    from backend.tests.test_expiry import add_incident, make_services

    async def scenario() -> None:
        services, _, _ = make_services()
        services = replace(services, dedup_audit_sample=sample)
        incident = await add_incident(services, "AWAITING_APPROVAL")
        payload = AlertPayload(service_name="svc", error_code="E1")
        for _ in range(duplicates):
            await _record_duplicate(services, incident.incident_id, payload)
        chain = await services.audit.records(incident.incident_id)
        dedup_rows = [r for r in chain if r.event_type.startswith("ALERT_DEDUPLICATED")]
        assert len(dedup_rows) == min(duplicates, sample) + max(0, (duplicates - sample) // 100)
        assert verify_chain(chain).valid
        row = await services.incidents.get(incident.incident_id)
        assert row is not None and row.duplicate_count == duplicates

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Property 19: page rate and coalescing (Req 10.3)
# ---------------------------------------------------------------------------

_page_ops = st.lists(
    st.one_of(
        st.tuples(st.just("req"), st.sampled_from(["auth-db", "payment-gateway", "x" * 40]), st.booleans()),
        st.tuples(st.just("wait"), st.floats(min_value=0.0, max_value=45.0), st.just(False)),
        st.tuples(st.just("flush"), st.just(""), st.just(False)),
    ),
    min_size=0,
    max_size=120,
)


@settings(max_examples=200, deadline=None)
@given(rate=st.integers(min_value=1, max_value=12), ops=_page_ops)
def test_property_19_page_rate_window_and_exactly_once_coalescing(
    rate: int, ops: list[tuple[str, Any, bool]]
) -> None:
    """**Validates: Requirements 10.3**"""
    from backend.app.services.page_rate import CoalescingPageGate, PageRateLimiter
    from backend.app.services.sms_common import validate_outbound

    now = [0.0]

    class Sms:
        def __init__(self) -> None:
            self.summaries: list[tuple[float, str]] = []

        async def send(self, text: str) -> None:
            self.summaries.append((now[0], validate_outbound(text)))  # pager invariant holds

    async def scenario() -> None:
        sms = Sms()
        gate = CoalescingPageGate(sms, PageRateLimiter(rate, lambda: now[0]), clock=lambda: now[0])
        sent_at: list[float] = []
        requests = coalesced = 0
        for kind, arg, flag in ops:
            if kind == "wait":
                now[0] += float(arg)
            elif kind == "flush":
                await gate.flush()
            else:
                requests += 1
                decision = await gate.admit(token="AB", service_name=str(arg), actionable=flag)
                assert decision in ("SEND", "COALESCED")
                if decision == "SEND":
                    sent_at.append(now[0])
                else:
                    coalesced += 1
        # Never more than ``rate`` individual pages in any 60 s window.
        for i, start in enumerate(sent_at):
            assert sum(1 for t in sent_at[i:] if t < start + 60.0) <= rate
        # Every request is decided exactly once.
        assert len(sent_at) + coalesced == requests
        # Coalesced incidents are either summarised once or still pending, never lost or doubled.
        summarised = sum(int(re.match(r"ALERTS: (\d+) more", text).group(1)) for _, text in sms.summaries)  # type: ignore[union-attr]
        assert summarised + gate.pending == coalesced
        # At most one summary per minute, each within the septet budget.
        times = [t for t, _ in sms.summaries]
        assert all(b - a >= 60.0 for a, b in zip(times, times[1:], strict=False))
        assert all(len(text) <= PAGER_MAX_CHARS for _, text in sms.summaries)

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Property 20: Pager readiness threshold (task 23). Validates: Requirements 7.5
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(failures=st.integers(0, 50), threshold=st.integers(1, 50))
def test_property_20_pager_readiness_threshold(failures: int, threshold: int) -> None:
    from backend.app.services.health_state import HealthState
    from backend.app.services.readiness import ReaperHeartbeat, run_readiness

    health = HealthState()
    for _ in range(failures):
        health.record_page_failure()
    report = asyncio.run(
        run_readiness(
            ping_postgres=None,
            ping_redis=None,
            heartbeat=ReaperHeartbeat(),
            health=health,
            page_failure_threshold=threshold,
            dry_run=False,
            timeout=0.05,
        )
    )
    assert report.checks.pager.ok is (failures < threshold)
    assert (report.status == "ok") is (failures < threshold)


# ---------------------------------------------------------------------------
# Property 21: Live configuration validation (task 24). Validates: Requirements 11.1, 11.4
# ---------------------------------------------------------------------------

from backend.app.main import ConfigError as _ConfigError  # noqa: E402
from backend.app.main import Settings as _LiveSettings  # noqa: E402

_LIVE_NAMES = (
    "ALERT_WEBHOOK_SECRET",
    "API_READ_SECRET",
    "AFRICASTALKING_USERNAME",
    "AFRICASTALKING_API_KEY",
    "AFRICASTALKING_WEBHOOK_SECRET",
    "ONCALL_PHONE_NUMBER",
)
_LIVE_VALUES = {
    "ALERT_WEBHOOK_SECRET": "zq-alert-7c1d",
    "API_READ_SECRET": "zq-read-93ab",
    "AFRICASTALKING_USERNAME": "zq-user-55ef",
    "AFRICASTALKING_API_KEY": "zq-key-08cc",
    "AFRICASTALKING_WEBHOOK_SECRET": "zq-hook-4d2a",
}


@settings(max_examples=200, deadline=None)
@given(
    present=st.fixed_dictionaries({n: st.booleans() for n in _LIVE_NAMES}),
    number=st.sampled_from(["+254711000111", "+14155550100", "0700123456", "254711000111", "+0711", "abc"]),
)
def test_property_21_live_config_validation(present: dict[str, bool], number: str) -> None:
    env = {"DRY_RUN": "false", "USE_IN_MEMORY": "true"}
    for name in _LIVE_NAMES:
        if present[name]:
            env[name] = number if name == "ONCALL_PHONE_NUMBER" else _LIVE_VALUES[name]
    cfg = _LiveSettings.from_env(env)
    number_ok = present["ONCALL_PHONE_NUMBER"] and number in ("+254711000111", "+14155550100")
    expect_ok = all(present.values()) and number_ok
    try:
        cfg.validate_for_runtime()
    except _ConfigError as exc:
        assert not expect_ok
        text = str(exc)
        assert all(v not in text for v in _LIVE_VALUES.values())
        if present["ONCALL_PHONE_NUMBER"]:
            assert number not in text
        for name in _LIVE_NAMES:
            if not present[name]:
                assert name in text
    else:
        assert expect_ok


# ---------------------------------------------------------------------------
# Property 22: sanitiser. No secret survives; only the real reply codes parse (task 25).
# Validates: Requirements 3.7, 3.8, 3.9
# ---------------------------------------------------------------------------

from backend.app.services.guardrails import format_pager_payload as _fmt22  # noqa: E402
from backend.app.services.guardrails import gsm7_septets as _septets22  # noqa: E402
from backend.app.services.guardrails import parse_sms_reply as _parse22  # noqa: E402

_SECRET_FRAGMENTS_22: tuple[tuple[str, str], ...] = (
    ("password=hunter2", "hunter2"),
    ("api_key=sk-abc123", "abc123"),
    ("AKIA" + "ABCDEFGHIJKLMNOP", "AKIA" + "ABCDEFGHIJKLMNOP"),
    ("ghp_abcdefghij1234567890", "ghp_abcdefghij1234567890"),
    ("xoxb-123-456-abcdefgh", "xoxb-123-456-abcdefgh"),
    (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
        "eyJhbGciOiJIUzI1NiJ9",
    ),
    ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "9f86d081884c7d659a2feaa0"),
)
_NOISE_22 = st.text(
    alphabet=st.sampled_from(list("abAB12 -_.:,\u2013\u2014\u2010\u00e9\u201c\u4e2d\uff0d\uff11")),
    max_size=40,
)


@st.composite
def _untrusted_22(draw: st.DrawFn) -> tuple[str, list[str]]:
    pieces: list[str] = []
    secrets: list[str] = []
    for _ in range(draw(st.integers(1, 4))):
        pieces.append(draw(_NOISE_22))
        frag, needle = draw(st.sampled_from(_SECRET_FRAGMENTS_22))
        if draw(st.booleans()):
            pieces.append(frag)
            secrets.append(needle)
    pieces.append(draw(_NOISE_22))
    return draw(st.sampled_from([" ", ""])).join(pieces), secrets


@settings(max_examples=200, deadline=None)
@given(
    token=st.from_regex(r"[A-Z0-9]{2}", fullmatch=True),
    service=_untrusted_22(),
    summary=_untrusted_22(),
    titles=st.lists(_untrusted_22(), max_size=2),
)
def test_property_22_sanitiser(
    token: str,
    service: tuple[str, list[str]],
    summary: tuple[str, list[str]],
    titles: list[tuple[str, list[str]]],
) -> None:
    """**Validates: Requirements 3.7, 3.8, 3.9**"""
    page = _fmt22(
        token, service[0], summary[0], option_titles=[t[0] for t in titles]
    ).text
    assert page.isascii()
    assert _septets22(page) <= 160
    for _, secrets in (service, summary, *titles):
        for needle in secrets:
            assert needle not in page
    real = {f"{token}-{n}" for n in range(1, len(titles) + 1)}
    # Windows that start inside the fixed ``INC-`` prefix (``NC-1`` for token ``10``) are not
    # untrusted text and cannot be removed without changing the mandated prefix.
    found = {
        page[i:j].rstrip(" .!")
        for i in range(len("INC-"), len(page))
        for j in range(i + 1, min(len(page), i + 10) + 1)
        if _parse22(page[i:j]) is not None and page[i] != " "
    }
    assert found == real
