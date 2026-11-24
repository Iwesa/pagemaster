"""Example tests for GSM-7 septet counting and UCS-2 prevention (task 7.1)."""

from __future__ import annotations

import pytest

from backend.app.services.guardrails import (
    AuditEvent,
    ClampReason,
    clamp_to_septets,
    format_pager_payload,
    gsm7_septets,
    sanitize_pager_text,
    to_gsm7_safe,
)
from backend.app.services.sms_common import PagerInvariantError, validate_outbound


def test_basic_chars_cost_one() -> None:
    assert gsm7_septets("Hello @ $_ \u00e9\u00a3") == 13
    assert gsm7_septets("") == 0


@pytest.mark.parametrize("ch", list("^{}\\[~]|\u20ac\f"))
def test_extension_chars_cost_two(ch: str) -> None:
    assert gsm7_septets(ch) == 2


def test_mixed_count() -> None:
    assert gsm7_septets("a[b]{c}") == 1 + 2 + 1 + 2 + 2 + 1 + 2


def test_unencodable_raises() -> None:
    with pytest.raises(ValueError):
        gsm7_septets("\u2019")
    with pytest.raises(ValueError):
        gsm7_septets("`")


def test_transliteration() -> None:
    assert to_gsm7_safe("`x` \u2018a\u2019 \u201cb\u201d c\u2014d\u2013e\u2026 5\u20ac") == (
        "'x' 'a' \"b\" c-d-e... 5EUR"
    )
    assert to_gsm7_safe("caf\u00e9 \u00fc \u00a3") == "cafe u ?"
    out = to_gsm7_safe("\u4e2d\u6587 `tick` \u201cq\u201d")
    assert out.isascii()
    assert gsm7_septets(out) == len(out)


def test_clamp_never_splits_extension_char() -> None:
    assert clamp_to_septets("aaa[", 4) == "aaa"
    assert clamp_to_septets("aaa[", 5) == "aaa["
    assert clamp_to_septets("\u20ac\u20ac", 3) == "\u20ac"
    assert clamp_to_septets("abc", 0) == ""


def test_clamp_never_exceeds_limit() -> None:
    text = "{a}|b~" * 60
    for limit in range(0, 200, 7):
        assert gsm7_septets(clamp_to_septets(text, limit)) <= limit
    assert gsm7_septets(clamp_to_septets(text)) <= 160


def test_payload_with_extension_chars_fits_budget() -> None:
    payload = format_pager_payload("AB", "svc", "{[|]}^~\\ " * 40)
    assert gsm7_septets(payload.text) <= 160
    assert payload.text.isascii()
    assert payload.clamped
    assert payload.audit_event is AuditEvent.GUARDRAIL_CLAMPED
    assert "AB-1" in payload.text and "AB-2" in payload.text


def test_transliteration_flags_clamped() -> None:
    payload = format_pager_payload("AB", "svc", "disk `full` \u201cnow\u201d")
    assert payload.clamped
    assert ClampReason.TRANSLITERATED in payload.reasons
    assert "`" not in payload.text and "\u201c" not in payload.text


def test_plain_payload_not_clamped() -> None:
    payload = format_pager_payload("AB", "svc", "disk full")
    assert not payload.clamped


def test_sanitize_pager_text_is_gsm7_safe() -> None:
    out = sanitize_pager_text("a`b \u2019 \u20ac")
    assert gsm7_septets(out) == len(out)


def test_validate_outbound_counts_septets() -> None:
    ok = "INC-AB " + "a" * 153
    assert validate_outbound(ok) == ok
    over = "INC-AB " + "[" * 77  # 7 + 154 septets, 84 chars
    with pytest.raises(PagerInvariantError):
        validate_outbound(over)


def test_payload_layout_with_titles() -> None:
    payload = format_pager_payload("AB", "auth-db", "pool 99%", "Reset connection pool", "Failover to replica")
    assert payload.text == "INC-AB auth-db: pool 99%. AB-1:Reset connection AB-2:Failover to"
    assert not payload.clamped


def test_missing_titles_fall_back_and_codes_survive_long_input() -> None:
    assert format_pager_payload("AB", "svc", "disk full").text.endswith("AB-1:Option A AB-2:Option B")
    text = format_pager_payload("AB", "s" * 40, "x" * 400, "{" * 50, "~" * 50).text
    assert gsm7_septets(text) <= 160 and "AB-1:" in text and "AB-2:" in text
