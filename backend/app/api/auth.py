"""Constant-time bearer-token comparison shared by the alert webhook and the read APIs."""

from __future__ import annotations

import hmac

__all__ = ["bearer_valid"]


def bearer_valid(secret: str, header: str) -> bool:
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        return False
    return hmac.compare_digest(supplied.strip().encode("utf-8"), secret.encode("utf-8"))
