"""Retrying ``SmsPort`` decorator (Req 8.1).

Wraps another ``SmsPort``. A ``SmsSendError`` with ``retryable=True`` is retried up to
``max_attempts`` total attempts with exponential backoff (1 s, 2 s, 4 s, ...) plus jitter.
A non-retryable ``SmsSendError`` (authentication, invalid number) and any other exception
propagate immediately. The final error is re-raised so the graph can fail the page.

``sleep`` and ``rand`` are injectable so tests run without real delays.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import Final

from backend.app.agents.ports import SmsPort
from backend.app.services.africastalking_client import SmsSendError

logger = logging.getLogger(__name__)

__all__ = ["BACKOFF_BASE_SECONDS", "JITTER_FRACTION", "RetryingSmsPort", "backoff_delay"]

BACKOFF_BASE_SECONDS: Final[float] = 1.0
JITTER_FRACTION: Final[float] = 0.25


def backoff_delay(retry_index: int, rand: float) -> float:
    """Delay before retry ``retry_index`` (0-based): ``1 s * 2**i`` stretched by up to 25% jitter."""
    return BACKOFF_BASE_SECONDS * (1 << retry_index) * (1.0 + JITTER_FRACTION * rand)


class RetryingSmsPort:
    """``SmsPort`` that retries transient provider failures."""

    def __init__(
        self,
        inner: SmsPort,
        *,
        max_attempts: int = 3,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rand: Callable[[], float] = random.random,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._inner = inner
        self._max_attempts = max_attempts
        self._sleep = sleep
        self._rand = rand

    async def send(self, text: str) -> None:
        attempt = 0
        while True:
            attempt += 1
            try:
                await self._inner.send(text)
                return
            except SmsSendError as exc:
                if not exc.retryable or attempt >= self._max_attempts:
                    logger.warning(
                        "sms send failed (attempt %d/%d, retryable=%s)",
                        attempt,
                        self._max_attempts,
                        exc.retryable,
                    )
                    raise
                delay = backoff_delay(attempt - 1, self._rand())
                logger.warning("sms send failed (attempt %d/%d); retrying in %.1fs", attempt, self._max_attempts, delay)
                await self._sleep(delay)
