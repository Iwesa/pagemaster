"""Hash-chained audit log: ``AuditLogger``, ``compute_audit_hash``, ``jsonb_text``, ``verify_chain``.

Standalone domain module (stdlib + Pydantic v2 only).

Audit hash contract (must match ``database/30_demo_seed.sql`` (seed) and ``10_schema.sql``)::

    hash = hex(sha256(utf8(
        prev_hash '|' incident_id '|' seq '|' event_type '|' payload_text)))

* ``prev_hash`` is the previous record's hash, or 64 ``'0'`` characters for the
  first record (``seq == 0``) of an incident.
* ``incident_id`` is the lowercase hyphenated UUID text (``uuid::text``).
* ``seq`` is the decimal integer; sequences start at 0 and increase by 1.
* ``payload_text`` is PostgreSQL's ``jsonb::text`` rendering: object keys sorted
  by (byte length, bytes), ``": "`` after keys, ``", "`` between items, no
  escaping of non-ASCII characters. See :func:`jsonb_text`. Floats are rendered
  as Postgres ``numeric`` text (plain decimal, no exponent); NaN/Infinity raise.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "GENESIS_HASH",
    "AuditEvent",
    "AuditLogger",
    "AuditRecord",
    "ChainVerification",
    "JsonValue",
    "compute_audit_hash",
    "jsonb_text",
    "verify_chain",
]

GENESIS_HASH: Final[str] = "0" * 64


class AuditEvent(StrEnum):
    """Well-known audit ``event_type`` values."""

    INCIDENT_CREATED = "INCIDENT_CREATED"
    GUARDRAIL_CLAMPED = "GUARDRAIL_CLAMPED"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    TRIPWIRE_PASSED = "TRIPWIRE_PASSED"
    TRIPWIRE_BLOCKED = "TRIPWIRE_BLOCKED"


type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]


def _jsonb_key_order(key: str) -> tuple[int, bytes]:
    raw = key.encode("utf-8")
    return (len(raw), raw)


def jsonb_text(value: object) -> str:
    """Render ``value`` exactly like PostgreSQL ``jsonb::text``.

    Supports ``None``, ``bool``, ``int``, ``float``, ``str``, lists and dicts
    with string keys.

    Floats: the JSON text of a Python float is ``repr(value)`` (shortest
    round-trip). Postgres parses that text as ``numeric``, which keeps the digits
    and scale as written but never prints an exponent and has no negative zero.
    So ``Decimal(repr(x))`` formatted with ``"f"`` matches: ``1.5 -> 1.5``,
    ``2.0 -> 2.0``, ``1e-07 -> 0.0000001``, ``1e16 -> 10000000000000000``,
    ``-0.0 -> 0.0``. NaN and +/-Infinity are not valid JSON and raise ``ValueError``.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity cannot be represented in jsonb")
        number = Decimal(repr(value))
        rendered = format(number, "f")
        return rendered[1:] if number.is_zero() and rendered.startswith("-") else rendered
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, Sequence):
        return "[" + ", ".join(jsonb_text(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items: list[str] = []
        for key in sorted(value, key=_jsonb_key_order):
            if not isinstance(key, str):
                raise TypeError("jsonb object keys must be strings")
            items.append(f"{json.dumps(key, ensure_ascii=False)}: {jsonb_text(value[key])}")
        return "{" + ", ".join(items) + "}"
    raise TypeError(f"unsupported payload type for audit hashing: {type(value).__name__}")


def compute_audit_hash(
    prev_hash: str,
    incident_id: UUID,
    seq: int,
    event_type: str,
    payload: Mapping[str, Any],
) -> str:
    """SHA-256 hex digest of ``prev_hash|incident_id|seq|event_type|payload::text``."""
    material = f"{prev_hash}|{incident_id}|{seq}|{event_type}|{jsonb_text(payload)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditRecord(BaseModel):
    """One row of ``audit_trail``."""

    model_config = ConfigDict(frozen=True)

    incident_id: UUID
    seq: int = Field(ge=0)
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ChainVerification(BaseModel):
    """Result of :func:`verify_chain`; ``broken_at`` is the first bad ``seq`` index."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    broken_at: int | None = None


def verify_chain(records: Sequence[AuditRecord]) -> ChainVerification:
    """Verify a single incident's chain, ordered by ``seq``.

    Checks the genesis ``prev_hash``, contiguous ``seq`` from 0, a single
    ``incident_id``, ``prev_hash`` linkage, and each record's recomputed hash.
    ``broken_at`` is the list index of the first failing record.
    """
    prev = GENESIS_HASH
    for index, rec in enumerate(records):
        expected = compute_audit_hash(prev, rec.incident_id, rec.seq, rec.event_type, rec.payload)
        if (
            rec.seq != index
            or rec.incident_id != records[0].incident_id
            or rec.prev_hash != prev
            or rec.hash != expected
        ):
            return ChainVerification(valid=False, broken_at=index)
        prev = rec.hash
    return ChainVerification(valid=True)


class AuditLogger:
    """In-memory builder for one incident's hash chain.

    Persistence is the caller's concern (an adapter inserts each returned
    :class:`AuditRecord`). Resume an existing chain by passing its records.
    """

    def __init__(self, incident_id: UUID, records: Sequence[AuditRecord] = ()) -> None:
        self._incident_id = incident_id
        self._records: list[AuditRecord] = list(records)
        if any(r.incident_id != incident_id for r in self._records):
            raise ValueError("records belong to a different incident")
        if not verify_chain(self._records).valid:
            raise ValueError("existing audit chain failed verification")

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    @property
    def head_hash(self) -> str:
        return self._records[-1].hash if self._records else GENESIS_HASH

    def append(self, event_type: str, payload: Mapping[str, Any] | None = None) -> AuditRecord:
        body: dict[str, Any] = dict(payload or {})
        seq = len(self._records)
        prev = self.head_hash
        record = AuditRecord(
            incident_id=self._incident_id,
            seq=seq,
            event_type=str(event_type),
            payload=body,
            prev_hash=prev,
            hash=compute_audit_hash(prev, self._incident_id, seq, str(event_type), body),
        )
        self._records.append(record)
        return record

    def verify(self) -> ChainVerification:
        return verify_chain(self._records)
