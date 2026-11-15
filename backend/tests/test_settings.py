"""Settings parsing for INFLIGHT_STALE_SECONDS (Requirement 6.4)."""

from __future__ import annotations

import logging

import pytest

from backend.app.main import Settings, build_in_memory_services


def test_default_is_60() -> None:
    assert Settings.from_env({}).inflight_stale_seconds == 60
    assert Settings().inflight_stale_seconds == 60


def test_env_override() -> None:
    assert Settings.from_env({"INFLIGHT_STALE_SECONDS": "120"}).inflight_stale_seconds == 120


@pytest.mark.parametrize("raw", ["10", "9", "0", "-5"])
def test_clamped_to_minimum_10(raw: str) -> None:
    assert Settings.from_env({"INFLIGHT_STALE_SECONDS": raw}).inflight_stale_seconds == 10


@pytest.mark.parametrize("raw", ["", "abc", "1.5", "  "])
def test_invalid_falls_back_to_60_with_warning(raw: str, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="pagemaster.main"):
        settings = Settings.from_env({"INFLIGHT_STALE_SECONDS": raw})
    assert settings.inflight_stale_seconds == 60
    assert "INFLIGHT_STALE_SECONDS" in caplog.text


def test_in_memory_services_receive_value() -> None:
    settings = Settings.from_env({"INFLIGHT_STALE_SECONDS": "45", "USE_IN_MEMORY": "true"})
    assert build_in_memory_services(settings).inflight_stale_seconds == 45


# --- ALLOW_QUERY_SECRET / PUBLIC_BASE_URL (Requirement 4.2, task 14.1) ---


def test_allow_query_secret_defaults_false() -> None:
    assert Settings().allow_query_secret is False
    assert Settings.from_env({}).allow_query_secret is False


@pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "Yes", " true "])
def test_allow_query_secret_truthy(raw: str) -> None:
    assert Settings.from_env({"ALLOW_QUERY_SECRET": raw}).allow_query_secret is True


@pytest.mark.parametrize("raw", ["", "false", "0", "no", "on", "enabled", "2"])
def test_allow_query_secret_other_values_false(raw: str) -> None:
    assert Settings.from_env({"ALLOW_QUERY_SECRET": raw}).allow_query_secret is False


@pytest.mark.parametrize("flag", [True, False])
def test_allow_query_secret_reaches_in_memory_services(flag: bool) -> None:
    settings = Settings(use_in_memory=True, allow_query_secret=flag)
    assert build_in_memory_services(settings).allow_query_secret is flag


def test_app_services_default_disallows_query_secret() -> None:
    assert build_in_memory_services(Settings(use_in_memory=True)).allow_query_secret is False


def test_warning_for_public_base_url_with_query(caplog: pytest.LogCaptureFixture) -> None:
    from backend.app.main import create_app

    with caplog.at_level(logging.WARNING, logger="pagemaster.main"):
        create_app(settings=Settings(public_base_url="https://x.example/hook?secret=abc", dry_run=True))
    assert "PUBLIC_BASE_URL" in caplog.text
    assert "abc" not in caplog.text


def test_no_url_warning_for_clean_public_base_url(caplog: pytest.LogCaptureFixture) -> None:
    from backend.app.main import create_app

    with caplog.at_level(logging.WARNING, logger="pagemaster.main"):
        create_app(settings=Settings(public_base_url="https://x.example", dry_run=True))
    assert "PUBLIC_BASE_URL" not in caplog.text
    assert "ALLOW_QUERY_SECRET" not in caplog.text


def test_warning_when_allow_query_secret_enabled(caplog: pytest.LogCaptureFixture) -> None:
    from backend.app.main import create_app

    with caplog.at_level(logging.WARNING, logger="pagemaster.main"):
        create_app(settings=Settings(allow_query_secret=True, dry_run=True))
    assert "ALLOW_QUERY_SECRET" in caplog.text
