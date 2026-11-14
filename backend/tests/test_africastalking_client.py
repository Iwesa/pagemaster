"""Tests for the Africa's Talking SMS adapter."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from backend.app.agents.ports import SmsPort
from backend.app.services.africastalking_client import (
    PRODUCTION_URL,
    SANDBOX_URL,
    AfricasTalkingConfigError,
    AfricasTalkingSettings,
    AfricasTalkingSmsAdapter,
    PagerInvariantError,
    SmsSendError,
    canonicalize_e164,
)

MSG = "INC-AB Svc db down. Reply 1 Restart, 2 Ignore"
OK_BODY = {"SMSMessageData": {"Recipients": [{"statusCode": 101, "status": "Success"}]}}


def _settings(**kw: object) -> AfricasTalkingSettings:
    base: dict[str, object] = {
        "dry_run": False,
        "username": "pagemaster",
        "api_key": "SECRETKEY",
        "to_number": "+254700000001",
    }
    base.update(kw)
    return AfricasTalkingSettings.model_validate(base)


def _adapter(
    handler: httpx.MockTransport, **kw: object
) -> AfricasTalkingSmsAdapter:
    return AfricasTalkingSmsAdapter(_settings(**kw), transport=handler)


async def test_success_headers_form_and_url() -> None:
    seen: list[httpx.Request] = []

    def handle(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(201, json=OK_BODY)

    adapter = _adapter(httpx.MockTransport(handle), shortcode="PAGER")
    assert isinstance(adapter, SmsPort)
    await adapter.send(MSG)
    await adapter.aclose()
    req = seen[0]
    assert str(req.url) == PRODUCTION_URL
    assert req.method == "POST"
    assert req.headers["apiKey"] == "SECRETKEY"
    assert req.headers["Accept"] == "application/json"
    assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"
    form = parse_qs(req.content.decode())
    assert form == {
        "username": ["pagemaster"],
        "to": ["+254700000001"],
        "message": [MSG],
        "from": ["PAGER"],
    }


async def test_from_omitted_without_shortcode() -> None:
    seen: list[httpx.Request] = []

    def handle(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(201, json=OK_BODY)

    adapter = _adapter(httpx.MockTransport(handle))
    await adapter.send(MSG)
    await adapter.aclose()
    assert "from" not in parse_qs(seen[0].content.decode())


async def test_sandbox_url_by_username_and_flag() -> None:
    urls: list[str] = []

    def handle(req: httpx.Request) -> httpx.Response:
        urls.append(str(req.url))
        return httpx.Response(201, json=OK_BODY)

    for kw in ({"username": "sandbox", "sandbox": True}, {"sandbox": True}):
        adapter = _adapter(httpx.MockTransport(handle), **kw)
        await adapter.send(MSG)
        await adapter.aclose()
    assert urls == [SANDBOX_URL, SANDBOX_URL]


def test_from_env_sandbox_and_dry_run_defaults() -> None:
    s = AfricasTalkingSettings.from_env({"AFRICASTALKING_USERNAME": "sandbox"})
    assert s.sandbox and s.dry_run
    s = AfricasTalkingSettings.from_env({"AFRICASTALKING_USERNAME": "acme"})
    assert not s.sandbox
    s = AfricasTalkingSettings.from_env(
        {"AFRICASTALKING_USERNAME": "acme", "AFRICASTALKING_SANDBOX": "true", "DRY_RUN": "false"}
    )
    assert s.sandbox and not s.dry_run
    s = AfricasTalkingSettings.from_env(
        {
            "AFRICASTALKING_API_KEY": "key-zz9",
            "AFRICASTALKING_SHORTCODE": "123",
            "ONCALL_PHONE_NUMBER": "+2547",
            "AFRICASTALKING_WEBHOOK_SECRET": "hook-qq7",
        }
    )
    assert s.shortcode == "123" and s.to_number == "+2547"
    assert "key-zz9" not in repr(s) and "hook-qq7" not in repr(s)


async def test_http_error_raises() -> None:
    adapter = _adapter(httpx.MockTransport(lambda r: httpx.Response(401, text="no")))
    with pytest.raises(SmsSendError):
        await adapter.send(MSG)
    await adapter.aclose()


async def test_recipient_failure_raises() -> None:
    body = {"SMSMessageData": {"Recipients": [{"statusCode": 403, "status": "InvalidSenderId"}]}}
    adapter = _adapter(httpx.MockTransport(lambda r: httpx.Response(201, json=body)))
    with pytest.raises(SmsSendError, match="InvalidSenderId"):
        await adapter.send(MSG)
    await adapter.aclose()


async def test_malformed_response_and_transport_error_raise() -> None:
    adapter = _adapter(httpx.MockTransport(lambda r: httpx.Response(201, text="not json")))
    with pytest.raises(SmsSendError):
        await adapter.send(MSG)
    await adapter.aclose()

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=req)

    adapter = _adapter(httpx.MockTransport(boom))
    with pytest.raises(SmsSendError):
        await adapter.send(MSG)
    await adapter.aclose()


async def test_dry_run_makes_no_http_call() -> None:
    adapter = AfricasTalkingSmsAdapter(
        AfricasTalkingSettings(dry_run=True, to_number="+254700000001"),
        transport=httpx.MockTransport(lambda r: pytest.fail("network used")),
    )
    assert adapter.dry_run
    await adapter.send(MSG)
    assert [m.text for m in adapter.outbox] == [MSG]
    adapter.clear_outbox()
    assert adapter.outbox == ()


async def test_invalid_outbound_rejected() -> None:
    adapter = AfricasTalkingSmsAdapter(AfricasTalkingSettings(dry_run=True))
    for bad in ("no prefix", "INC-A short token", "inc-ab lowercase", ""):
        with pytest.raises(PagerInvariantError):
            await adapter.send(bad)
    assert adapter.outbox == ()


def test_live_requires_credentials() -> None:
    with pytest.raises(AfricasTalkingConfigError):
        AfricasTalkingSmsAdapter(AfricasTalkingSettings(dry_run=False))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("+254 700-000-001", "+254700000001"),
        ("00254700000001", "+254700000001"),
        ("+1 (415) 555-0100", "+14155550100"),
        ("0700000001", None),
        ("+1234567", None),
        ("+1234567890123456", None),
        ("+25470abc0001", None),
        ("", None),
    ],
)
def test_canonicalize_e164_examples(raw: str, expected: str | None) -> None:
    assert canonicalize_e164(raw) == expected


@settings(max_examples=200)
@given(
    st.one_of(
        st.text(max_size=30),
        st.from_regex(r"(\+|00)[0-9 ()\-]{6,24}", fullmatch=True),
    )
)
def test_canonicalize_e164_idempotent(raw: str) -> None:
    once = canonicalize_e164(raw)
    if once is not None:
        assert canonicalize_e164(once) == once
