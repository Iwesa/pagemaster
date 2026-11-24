"""Sanitiser table tests (task 25; Req 3.7, 3.8, 3.9)."""

from __future__ import annotations

import pytest

from backend.app.services.guardrails import (
    format_pager_payload,
    gsm7_septets,
    parse_sms_reply,
    sanitize_pager_text,
    to_gsm7_safe,
)

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"

SECRETS: list[tuple[str, str]] = [
    ("password=hunter2", "hunter2"),
    ("PASSWORD: hunter2", "hunter2"),
    ("passwd=hunter2", "hunter2"),
    ("pwd=hunter2", "hunter2"),
    ("secret=s3cr3t", "s3cr3t"),
    ("token=abc123", "abc123"),
    ("api_key=zzz999", "zzz999"),
    ("apikey=zzz999", "zzz999"),
    ("api-key: zzz999", "zzz999"),
    ("authorization=xyz789", "xyz789"),
    ("auth=xyz789", "xyz789"),
    ("credentials=xyz789", "xyz789"),
    ("client_secret=xyz789", "xyz789"),
    ("access_key=xyz789", "xyz789"),
    ("private_key=xyz789", "xyz789"),
    ('password="two words"', "two words"),
    ("password='two words'", "two words"),
    ("db down sk-abc12345 now", "sk-abc12345"),
    ("db down sk_abc12345 now", "sk_abc12345"),
    ("key ghp_abcdefghij1234 end", "ghp_abcdefghij1234"),
    ("key gho_abcdefghij1234 end", "gho_abcdefghij1234"),
    ("key ghs_abcdefghij1234 end", "ghs_abcdefghij1234"),
    ("key github_pat_abcdefghij1234 end", "github_pat_abcdefghij1234"),
    ("slack xoxb-123-456-abcdef end", "xoxb-123-456-abcdef"),
    ("slack xoxp-123-456-abcdef end", "xoxp-123-456-abcdef"),
    ("aws " + "AKIA" + "ABCDEFGHIJKLMNOP" + " end", "AKIA" + "ABCDEFGHIJKLMNOP"),
    ("aws ASIAABCDEFGHIJKLMNOP end", "ASIAABCDEFGHIJKLMNOP"),
    ("gcp AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q end", "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
    (f"jwt {_JWT} end", _JWT),
    ("hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 end",
     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
    ("blob dGhpcyBpcyBhIHZlcnkgc2VjcmV0IHZhbHVlIQ== end", "dGhpcyBpcyBhIHZlcnkgc2VjcmV0IHZhbHVl"),
    ("blob dGhpcy_pcyBhIHZlcnkgc2VjcmV0IHZhbHVlIQ-x end", "dGhpcy_pcyBhIHZlcnkgc2VjcmV0IHZhbHVlIQ"),
]

SURVIVORS: list[str] = [
    "payment-gateway",
    "order-service timeout",
    "id 123e4567-e89b-12d3-a456-426614174000",
    "at 12:30:45 err",
    "mac 00:1A:2B:3C:4D:5E",
    "listening on :8080",
    "connection pool exhausted",
    "disk usage high on volume",
    "author: alice",
    "tokenizer slow",
    "task-runner stalled",
]


@pytest.mark.parametrize(("text", "secret"), SECRETS)
def test_known_secret_formats_are_redacted(text: str, secret: str) -> None:
    out = sanitize_pager_text(text)
    assert secret not in out
    assert "***" in out


@pytest.mark.parametrize("text", SURVIVORS)
def test_non_secrets_survive(text: str) -> None:
    assert sanitize_pager_text(text, neutralize_codes=False) == text


def test_redaction_runs_before_truncation() -> None:
    page = format_pager_payload("AB", "svc", "x " * 20 + "password=hunter2supersecret", "a", "b").text
    assert "hunter2" not in page


@pytest.mark.parametrize(
    "text",
    ["ab-1", "AB 2", "ab\u20102", "ab\u20132", "ab\u22121", "\uff41\uff42\uff0d1", "(ab-1)", "ab-1.", "xab-1"],
)
def test_reply_lookalikes_are_neutralised(text: str) -> None:
    out = sanitize_pager_text(text)
    for i in range(len(out)):
        for j in range(i + 1, len(out) + 1):
            assert parse_sms_reply(out[i:j]) is None, (text, out, out[i:j])


def test_page_has_only_the_real_codes() -> None:
    page = format_pager_payload("7A", "ab-1", "restart cd 2 or EF-1 now", "ab-2 fix", "gh 1 fix").text
    found = {
        page[i:j]
        for i in range(len(page))
        for j in range(i + 1, min(len(page), i + 6) + 1)
        if parse_sms_reply(page[i:j]) and page[i] != " "
    }
    assert found == {"7A-1", "7A-2"}


def test_leading_digit_service_cannot_complete_the_token() -> None:
    page = format_pager_payload("AB", "1st-service", "down", "a", "b").text
    assert parse_sms_reply("AB 1") is not None
    assert "AB 1" not in page


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("caf\u00e9 cr\u00e8me", "cafe creme"),
        ("\u201cquoted\u201d \u2018x\u2019", "\"quoted\" 'x'"),
        ("a\u2013b\u2014c", "a-b-c"),
        ("wait\u2026", "wait..."),
        ("a\u00a0b", "a b"),
        ("x \u4e2d\u6587\u5b57 y", "x ? y"),
        ("x \U0001f600\U0001f600 y", "x ? y"),
    ],
)
def test_transliteration(text: str, expected: str) -> None:
    assert to_gsm7_safe(text) == expected


def test_page_with_hostile_unicode_is_gsm7_and_short() -> None:
    page = format_pager_payload("AB", "caf\u00e9\u4e2d", "\u201cpassword=hunter2\u201d " * 30, "r\u00e9set", "\u4e2d").text
    assert page.isascii()
    assert gsm7_septets(page) <= 160
    assert "hunter2" not in page
