---
inclusion: always
---
# Pagemaster Engineering & Guardrail Standards

- **Architecture:** Strict hexagonal boundaries. Domain state machines (`backend/app/agents/`) must never import FastAPI or Twilio SDKs directly; interact via typed port interfaces.
- **Determinism & Safety:** Never allow unconstrained shell or SQL execution. All MCP database tools must enforce `SET TRANSACTION READ ONLY` and query allowlisted views only.
- **Pager Payload Invariant:** Every outbound pager message MUST be <= 160 ASCII characters, contain a valid `INC-<TOKEN>` prefix, and strip emails, IPv4/IPv6 addresses, and bearer tokens.
- **Testing Discipline:** Every correctness property in `design.md` must have a corresponding `hypothesis` property-based test in `backend/tests/test_properties.py` with `@settings(max_examples=200)`.
- **Code Hygiene:** Python 3.13+, strict type annotations (`mypy --strict` compatible), Pydantic v2 models for all state and webhook payloads, async I/O throughout.